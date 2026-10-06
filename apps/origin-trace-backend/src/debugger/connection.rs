use crate::{
    error::{Cause, Code, Error, Reason, Result},
    validation, worker,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
};

pub enum Event {
    Message(Result<Value>, Option<OwnedSemaphorePermit>),
    Barrier(oneshot::Sender<()>),
}
pub struct Connection {
    stdin: Mutex<ChildStdin>,
    child: Mutex<Child>,
    pending: StdMutex<BTreeMap<u64, oneshot::Sender<Result<Value>>>>,
    next: AtomicU64,
    closed: watch::Sender<bool>,
    events: mpsc::Sender<Event>,
}
struct Pending<'a> {
    connection: &'a Connection,
    id: u64,
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.connection.pending.lock() {
            pending.remove(&self.id);
        }
    }
}
impl Connection {
    pub async fn open(path: &Path, url: &str) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        local_websocket(url)?;
        if !worker::executable(path) {
            return Err(Error::new(
                503,
                "Native debugger transport is unavailable; run make debugger-transport",
            )
            .with_code(Code::DependencyUnavailable));
        }
        let mut child = Command::new(path)
            .args(["--url", url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                Error::conflict(format!("Native debugger transport could not start: {e}"))
                    .with_code(Code::DependencyUnavailable)
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::conflict("Debugger transport input is unavailable"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::conflict("Debugger transport output is unavailable"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::conflict("Debugger transport diagnostics are unavailable"))?;
        let ready = tokio::time::timeout(Duration::from_secs(3), frame(&mut stdout))
            .await
            .map_err(|_| Error::conflict("Native debugger transport startup timed out"))??;
        if !ready.is_empty() {
            return Err(Error::protocol(
                "Native debugger transport returned a malformed startup frame",
            ));
        }
        let (closed, mut stopped) = watch::channel(false);
        let (sender, events) = mpsc::channel(512);
        let budget = Arc::new(Semaphore::new(64 * 1024 * 1024));
        let connection = Arc::new(Self {
            stdin: Mutex::new(stdin),
            child: Mutex::new(child),
            pending: StdMutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            closed,
            events: sender.clone(),
        });
        let weak = Arc::downgrade(&connection);
        let diagnostics = Arc::new(StdMutex::new(Vec::new()));
        let retained = diagnostics.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok(size) = stderr.read(&mut buffer).await {
                if size == 0 {
                    break;
                }
                let mut kept = retained.lock().unwrap_or_else(|e| e.into_inner());
                let size = size.min(4096usize.saturating_sub(kept.len()));
                kept.extend_from_slice(&buffer[..size]);
            }
        });
        tokio::spawn(async move {
            let failure = loop {
                let message = tokio::select! {
                    biased;
                    _=stopped.changed()=>break Error::conflict("Debugger WebSocket is closed"),
                    body=frame(&mut stdout)=>match body {Ok(body)=>body,Err(error)=>break error},
                };
                let value: Value = match serde_json::from_slice(&message) {
                    Ok(value) => value,
                    Err(_) => break Error::protocol("Debugger WebSocket sent malformed JSON"),
                };
                if !value.is_object() {
                    break Error::protocol("Debugger WebSocket sent a non-object message");
                }
                let Some(connection) = weak.upgrade() else {
                    break Error::conflict("Debugger connection closed");
                };
                if let Some(id) = value["id"].as_u64() {
                    if let Some(pending) = connection
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&id)
                    {
                        let _ = pending.send(Ok(value));
                    }
                } else if value["method"].is_string() && value["params"].is_object() {
                    let permit = match budget
                        .clone()
                        .try_acquire_many_owned(message.len().min(u32::MAX as usize) as u32)
                    {
                        Ok(permit) => permit,
                        Err(_) => {
                            break Error::conflict(
                                "Debugger event byte capacity exceeded; reconnecting preserves a visible gap",
                            );
                        }
                    };
                    if sender
                        .try_send(Event::Message(Ok(value), Some(permit)))
                        .is_err()
                    {
                        break Error::conflict(
                            "Debugger event queue capacity exceeded; reconnecting preserves a visible gap",
                        );
                    }
                }
            };
            let detail =
                String::from_utf8_lossy(&diagnostics.lock().unwrap_or_else(|e| e.into_inner()))
                    .trim()
                    .to_owned();
            let failure = if detail.is_empty() {
                failure
            } else {
                Error::conflict(format!(
                    "{}: {}",
                    failure.message,
                    validation::truncate(&detail, 4096)
                ))
                .with_reason(failure.reason)
            };
            let _ = sender
                .send(Event::Message(
                    Err(Error::conflict(failure.message.clone())),
                    None,
                ))
                .await;
            fail_pending(&weak, &failure).await;
            if let Some(connection) = weak.upgrade() {
                let _ = connection.closed.send(true);
                let mut child = connection.child.lock().await;
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        });
        Ok((connection, events))
    }
    pub async fn barrier(&self) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.events
            .send(Event::Barrier(sender))
            .await
            .map_err(|_| Error::conflict("Debugger event stream closed"))?;
        tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .map_err(|_| Error::conflict("Debugger event barrier timed out"))?
            .map_err(|_| Error::conflict("Debugger event stream closed"))?;
        Ok(())
    }
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
    pub async fn command(&self, method: &str, params: Value, deadline: Duration) -> Result<Value> {
        self.command_session(method, params, deadline, None).await
    }
    pub async fn command_session(
        &self,
        method: &str,
        params: Value,
        deadline: Duration,
        session: Option<&str>,
    ) -> Result<Value> {
        if self.is_closed() {
            return Err(Error::conflict("Debugger WebSocket is closed"));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(Error::conflict("Debugger command identifier exhausted")
                .with_code(Code::ResourceLimit));
        }
        let mut message = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        let body = serde_json::to_vec(&message)?;
        if body.len() > 16 * 1024 * 1024 {
            return Err(Error::bad("Debugger command is oversized").with_code(Code::ResourceLimit));
        }
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if pending.len() >= 256 {
                return Err(
                    Error::conflict("Debugger pending command capacity exceeded")
                        .with_code(Code::ResourceLimit),
                );
            }
            pending.insert(id, sender);
        }
        let _pending = Pending {
            connection: self,
            id,
        };
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(b"REB\x01").await?;
            stdin.write_all(&(body.len() as u32).to_be_bytes()).await?;
            stdin.write_all(&body).await?;
            stdin.flush().await
        })
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            self.close().await;
            return Err(Error::conflict(
                "Native debugger transport command pipe failed or timed out",
            )
            .with_reason(Reason::uncertain(Cause::TransportFailure)));
        }
        let result = tokio::time::timeout(deadline, receiver).await;
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        let value = result
            .map_err(|_| {
                Error::conflict(format!("Debugger command {method} timed out"))
                    .with_reason(Reason::uncertain(Cause::Timeout))
            })?
            .map_err(|_| {
                Error::conflict("Debugger target disconnected")
                    .with_reason(Reason::uncertain(Cause::Disconnected))
            })??;
        if value["error"].is_object() {
            let reason = if value["error"]["code"].as_i64().is_some()
                && value["error"]["message"].is_string()
                && value.get("result").is_none()
            {
                Reason::new(Code::ApplicationFailed)
            } else {
                Reason::uncertain(Cause::InvalidReply)
            };
            return Err(Error::conflict(validation::truncate(
                value["error"]["message"]
                    .as_str()
                    .unwrap_or("Debugger command failed"),
                512,
            ))
            .with_reason(reason));
        }
        let result = value
            .get("result")
            .filter(|v| v.is_object())
            .ok_or_else(|| {
                Error::protocol(format!(
                    "Debugger command {method} returned malformed output"
                ))
                .with_reason(Reason::uncertain(Cause::InvalidReply))
            })?;
        Ok(result.clone())
    }
    pub async fn close(&self) {
        let _ = self.closed.send(true);
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}
async fn fail_pending(connection: &Weak<Connection>, failure: &Error) {
    if let Some(connection) = connection.upgrade() {
        let pending =
            std::mem::take(&mut *connection.pending.lock().unwrap_or_else(|e| e.into_inner()));
        let cause = if failure.reason.code == Code::ProtocolError {
            Cause::InvalidReply
        } else {
            Cause::Disconnected
        };
        for (_, sender) in pending {
            let _ = sender.send(Err(
                Error::conflict(&failure.message).with_reason(Reason::uncertain(cause))
            ));
        }
    }
}
async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut header = [0; 8];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| Error::conflict("Debugger WebSocket closed"))?;
    if &header[..4] != b"REB\x01" {
        return Err(Error::protocol(
            "Native debugger transport returned an invalid protocol header",
        ));
    }
    let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
    if length > 64 * 1024 * 1024 {
        return Err(Error::protocol("Debugger WebSocket message is oversized"));
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| Error::conflict("Debugger WebSocket closed"))?;
    Ok(body)
}
pub fn local_websocket(value: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .map_err(|_| Error::conflict("Debugger WebSocket URL is malformed"))?;
    if url.scheme() != "ws"
        || !["127.0.0.1", "localhost", "[::1]", "::1"].contains(&url.host_str().unwrap_or(""))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::conflict(
            "Debugger WebSocket endpoint must be local and credential-free",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // This fixture consumes one full command and records that it was received.
    // It never starts a browser or evaluates the submitted synthetic expression.
    async fn fixture(
        reply: Option<Value>,
        disconnect: bool,
    ) -> (tempfile::TempDir, Arc<Connection>) {
        fn printf(bytes: &[u8]) -> String {
            let escaped = bytes
                .iter()
                .map(|b| format!("\\{b:03o}"))
                .collect::<String>();
            format!("printf '{escaped}'\n")
        }
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("transport");
        let body = serde_json::to_vec(
            &json!({"id":1,"method":"Runtime.evaluate","params":{"expression":"synthetic_secret"}}),
        )
        .unwrap();
        let mut script = String::from("#!/bin/sh\n");
        script.push_str(&printf(b"REB\x01\0\0\0\0"));
        script.push_str(&format!(
            "dd bs=1 count={} of=/dev/null 2>/dev/null\nprintf received > '{}'/received\n",
            body.len() + 8,
            directory.path().display()
        ));
        if let Some(reply) = reply {
            let body = serde_json::to_vec(&reply).unwrap();
            let mut frame = b"REB\x01".to_vec();
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(&body);
            script.push_str(&printf(&frame));
        }
        script.push_str(if disconnect {
            "exit 0\n"
        } else {
            "exec sleep 60\n"
        });
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (connection, _events) = Connection::open(&executable, "ws://127.0.0.1:1")
            .await
            .unwrap();
        (directory, connection)
    }
    #[tokio::test]
    async fn sent_commands_with_lost_or_invalid_replies_have_unknown_outcomes() {
        for (reply, disconnect, status, cause) in [
            (None, false, 409, "timeout"),
            (None, true, 409, "disconnected"),
            (
                Some(json!({"id":1,"result":"malformed"})),
                false,
                422,
                "invalid_reply",
            ),
            (
                Some(json!({"id":1,"error":{}})),
                false,
                409,
                "invalid_reply",
            ),
            (
                Some(json!({"id":1,"error":{"message":"Synthetic application failure"}})),
                false,
                409,
                "invalid_reply",
            ),
            (
                Some(json!({"id":1,"error":{"code":-32000,"message":"failure"},"result":{}})),
                false,
                409,
                "invalid_reply",
            ),
        ] {
            let (directory, connection) = fixture(reply, disconnect).await;
            let error = connection
                .command(
                    "Runtime.evaluate",
                    json!({"expression":"synthetic_secret"}),
                    Duration::from_millis(100),
                )
                .await
                .unwrap_err();
            assert!(directory.path().join("received").exists());
            assert_eq!(error.status, status);
            assert_eq!(error.reason.code, Code::CommandOutcomeUnknown);
            let value = serde_json::to_value(error).unwrap();
            assert_eq!(
                value["details"],
                json!({"phase":"command_exchange","cause":cause})
            );
            assert!(!value["details"].to_string().contains("synthetic_secret"));
            connection.close().await;
        }
    }
    #[tokio::test]
    async fn explicit_reply_and_pre_send_capacity_remain_distinct() {
        let (_directory, connection) = fixture(
            Some(json!({"id":1,"error":{"code":-32000,"message":"Synthetic application failure"}})),
            false,
        )
        .await;
        let error = connection
            .command(
                "Runtime.evaluate",
                json!({"expression":"synthetic_secret"}),
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(error.message, "Synthetic application failure");
        assert_eq!(error.reason.code, Code::ApplicationFailed);
        connection.close().await;

        let (directory, connection) = fixture(None, false).await;
        for id in 100..356 {
            connection
                .pending
                .lock()
                .unwrap()
                .insert(id, oneshot::channel().0);
        }
        let error = connection
            .command(
                "Runtime.evaluate",
                json!({"expression":"synthetic_secret"}),
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(error.reason.code, Code::ResourceLimit);
        assert!(!directory.path().join("received").exists());
        connection.close().await;
    }
}
