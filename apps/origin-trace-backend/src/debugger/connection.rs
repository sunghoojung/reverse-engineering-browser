use crate::{
    error::{Error, Result},
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
            ));
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
            };
            let _ = sender
                .send(Event::Message(
                    Err(Error::conflict(failure.message.clone())),
                    None,
                ))
                .await;
            fail_pending(&weak, &failure.message).await;
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
            return Err(Error::conflict("Debugger command identifier exhausted"));
        }
        let mut message = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        let body = serde_json::to_vec(&message)?;
        if body.len() > 16 * 1024 * 1024 {
            return Err(Error::bad("Debugger command is oversized"));
        }
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if pending.len() >= 256 {
                return Err(Error::conflict(
                    "Debugger pending command capacity exceeded",
                ));
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
            ));
        }
        let result = tokio::time::timeout(deadline, receiver).await;
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        let value = result
            .map_err(|_| Error::conflict(format!("Debugger command {method} timed out")))?
            .map_err(|_| Error::conflict("Debugger target disconnected"))??;
        if value["error"].is_object() {
            return Err(Error::conflict(validation::truncate(
                value["error"]["message"]
                    .as_str()
                    .unwrap_or("Debugger command failed"),
                512,
            )));
        }
        let result = value
            .get("result")
            .filter(|v| v.is_object())
            .ok_or_else(|| {
                Error::protocol(format!(
                    "Debugger command {method} returned malformed output"
                ))
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
async fn fail_pending(connection: &Weak<Connection>, message: &str) {
    if let Some(connection) = connection.upgrade() {
        let pending =
            std::mem::take(&mut *connection.pending.lock().unwrap_or_else(|e| e.into_inner()));
        for (_, sender) in pending {
            let _ = sender.send(Err(Error::conflict(message)));
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
