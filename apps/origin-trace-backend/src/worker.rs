use crate::error::{Code, Error, Phase, Reason, Result};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{mpsc, watch},
};

// Workers own a process group. Cancellation and dropped futures must also stop
// descendants that inherited stdout, not leave the pipe reader alive forever.
pub(crate) struct ProcessGroup(pub(crate) u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.0 <= i32::MAX as u32 {
            unsafe {
                libc::kill(-(self.0 as i32), libc::SIGKILL);
            }
        }
    }
}
pub struct Output {
    pub bytes: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_us: u64,
}
/// Reads a worker stream to its end. An analysis worker's output grows with
/// its input, so `maximum` is `None` there; it bounds only the streams of a
/// worker whose output has a fixed shape, such as diagnostics.
async fn bounded_read(reader: impl AsyncRead + Unpin, maximum: Option<usize>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let Some(maximum) = maximum else {
        let mut reader = reader;
        reader.read_to_end(&mut bytes).await?;
        return Ok(bytes);
    };
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > maximum {
        return Err(
            Error::protocol("Worker output exceeded its byte limit").with_code(Code::ResourceLimit)
        );
    }
    Ok(bytes)
}
/// Runs one worker to completion. Analysis of captured input passes `None`
/// for both bounds: it runs as long as its input needs and is stopped only by
/// cancellation, which here is the caller dropping this future (the request
/// it serves went away), killing the worker's whole process group.
pub async fn run(
    command: &mut Command,
    input: &[u8],
    output_limit: Option<usize>,
    deadline: Option<Duration>,
) -> Result<Output> {
    run_cancel(
        command,
        vec![Input::Borrowed(input)],
        output_limit,
        deadline,
        None,
    )
    .await
}
/// One part of a worker's stdin. Parts are written in order, so a large part
/// reaches the worker without first being copied after the others.
pub enum Input<'a> {
    Borrowed(&'a [u8]),
    /// Freed once written, so it is not held while the worker runs.
    Owned(Vec<u8>),
    /// Encoded by a [`ChunkWriter`] while the worker reads it, so the encoded
    /// input is never held whole.
    Chunks(mpsc::Receiver<Vec<u8>>),
}
const CHUNK_BYTES: usize = 1 << 20;
/// A blocking writer whose bytes reach a worker as an [`Input::Chunks`]
/// part. Each chunk waits for the worker to take the one before it, so at
/// most a few chunks are held. Writes fail once the worker is gone.
pub struct ChunkWriter {
    sender: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
}
impl ChunkWriter {
    pub fn new() -> (Self, Input<'static>) {
        let (sender, chunks) = mpsc::channel(4);
        (
            Self {
                sender,
                buffer: Vec::with_capacity(CHUNK_BYTES),
            },
            Input::Chunks(chunks),
        )
    }
}
impl std::io::Write for ChunkWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() >= CHUNK_BYTES {
            self.flush()?;
        }
        Ok(bytes.len())
    }
    /// Sends what is buffered; the part ends when the writer drops.
    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(CHUNK_BYTES));
        self.sender
            .blocking_send(chunk)
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }
}
/// [`run`] with its input written as consecutive parts, and with `cancel`
/// stopping the worker and its descendants.
pub async fn run_cancel(
    command: &mut Command,
    input: Vec<Input<'_>>,
    output_limit: Option<usize>,
    deadline: Option<Duration>,
    mut cancel: Option<&mut watch::Receiver<bool>>,
) -> Result<Output> {
    let started = Instant::now();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().map_err(|e| {
        Error::new(503, format!("Worker could not start: {e}"))
            .with_code(Code::DependencyUnavailable)
    })?;
    let _group = ProcessGroup(
        child
            .id()
            .ok_or_else(|| Error::new(503, "Worker process is unavailable"))?,
    );
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::new(503, "Worker input is unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(503, "Worker output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::new(503, "Worker diagnostics are unavailable"))?;
    let result = tokio::select! {
        biased;
        _=async {if let Some(receiver)=cancel.as_mut() {if !*receiver.borrow() {let _=receiver.changed().await;}} else {std::future::pending::<()>().await}}=> {let _=child.kill().await;let _=child.wait().await;return Err(Error::new(499,"Worker cancelled").with_reason(Reason::at(Code::Cancelled, Phase::Worker)));},
        result=async {
            let work = async {
                tokio::try_join!(async {
                    for part in input {
                        match part {
                            Input::Borrowed(bytes) => stdin.write_all(bytes).await?,
                            Input::Owned(bytes) => stdin.write_all(&bytes).await?,
                            Input::Chunks(mut chunks) => {
                                while let Some(chunk) = chunks.recv().await {
                                    stdin.write_all(&chunk).await?;
                                }
                            }
                        }
                    }
                    drop(stdin);
                    Ok::<_, Error>(())
                }, bounded_read(stdout,output_limit),bounded_read(stderr,Some(64*1024)),async { child.wait().await.map_err(Error::from) })
            };
            match deadline {
                Some(deadline) => tokio::time::timeout(deadline, work).await,
                None => Ok(work.await),
            }
        }=>result,
    };
    match result {
        Ok(Ok(((), bytes, stderr, status))) => Ok(Output {
            bytes,
            stderr,
            success: status.success(),
            exit_code: status.code(),
            duration_us: started
                .elapsed()
                .as_micros()
                .max(1)
                .min(u128::from(u64::MAX)) as u64,
        }),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(Error::new(408, "Worker execution deadline exceeded")
                .with_reason(Reason::at(Code::Timeout, Phase::Worker)))
        }
    }
}
pub fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancellation_stops_worker_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("descendant.pid");
        let (sender, mut receiver) = watch::channel(false);
        let child_path = path.clone();
        let task = tokio::spawn(async move {
            let mut command = Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "sleep 60 & printf '%s' \"$!\" > \"$1\"; wait",
                    "origin-trace-worker-test",
                ])
                .arg(child_path);
            run_cancel(
                &mut command,
                Vec::new(),
                Some(1024),
                Some(Duration::from_secs(5)),
                Some(&mut receiver),
            )
            .await
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(pid) = text.parse::<i32>()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "Worker descendant never started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        sender.send(true).unwrap();
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.status, 499);
        assert_eq!(error.reason.code, Code::Cancelled);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Worker descendant survived cancellation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    /// An unbounded analysis has no deadline; the request that dropped its
    /// future is its cancellation, and that must stop the whole group.
    #[tokio::test]
    async fn dropping_an_unbounded_run_stops_worker_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("descendant.pid");
        let child_path = path.clone();
        let task = tokio::spawn(async move {
            let mut command = Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "sleep 60 & printf '%s' \"$!\" > \"$1\"; wait",
                    "origin-trace-worker-test",
                ])
                .arg(child_path);
            run(&mut command, b"", None, None).await
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(pid) = text.parse::<i32>()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "Worker descendant never started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        task.abort();
        assert!(task.await.is_err_and(|error| error.is_cancelled()));
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "Worker descendant survived a dropped run"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn timeout_and_output_limits_terminate_workers() {
        let mut slow = Command::new("/bin/sh");
        slow.args(["-c", "sleep 60"]);
        let error = run(&mut slow, b"", Some(1024), Some(Duration::from_millis(100)))
            .await
            .err()
            .unwrap();
        assert_eq!(error.status, 408);
        assert_eq!(error.reason.code, Code::Timeout);
        let mut noisy = Command::new("/bin/sh");
        noisy.args(["-c", "while true; do printf 0123456789; done"]);
        let error = run(&mut noisy, b"", Some(16), Some(Duration::from_secs(2)))
            .await
            .err()
            .unwrap();
        assert_eq!(error.status, 422);
        assert_eq!(error.reason.code, Code::ResourceLimit);
    }
}
