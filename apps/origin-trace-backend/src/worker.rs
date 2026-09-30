use crate::error::{Error, Result};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::watch,
};

// Workers own a process group. Cancellation and dropped futures must also stop
// descendants that inherited stdout, not leave the pipe reader alive forever.
struct ProcessGroup(u32);
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
async fn bounded_read(reader: impl AsyncRead + Unpin, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > maximum {
        return Err(Error::protocol("Worker output exceeded its byte limit"));
    }
    Ok(bytes)
}
pub async fn run(
    command: &mut Command,
    input: &[u8],
    output_limit: usize,
    deadline: Duration,
) -> Result<Output> {
    run_cancel(command, input, output_limit, deadline, None).await
}
pub async fn run_cancel(
    command: &mut Command,
    input: &[u8],
    output_limit: usize,
    deadline: Duration,
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
    let mut child = command
        .spawn()
        .map_err(|e| Error::new(503, format!("Worker could not start: {e}")))?;
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
        _=async {if let Some(receiver)=cancel.as_mut() {if !*receiver.borrow() {let _=receiver.changed().await;}} else {std::future::pending::<()>().await}}=> {let _=child.kill().await;let _=child.wait().await;return Err(Error::new(499,"Worker cancelled"));},
        result=tokio::time::timeout(deadline, async {
        tokio::try_join!(async { stdin.write_all(input).await?; drop(stdin); Ok::<_,Error>(()) }, bounded_read(stdout,output_limit),bounded_read(stderr,64*1024),async { child.wait().await.map_err(Error::from) })
    })=>result,
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
            Err(Error::new(408, "Worker execution deadline exceeded"))
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
                b"",
                1024,
                Duration::from_secs(5),
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
        assert_eq!(task.await.unwrap().err().unwrap().status, 499);
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
    #[tokio::test]
    async fn timeout_and_output_limits_terminate_workers() {
        let mut slow = Command::new("/bin/sh");
        slow.args(["-c", "sleep 60"]);
        assert_eq!(
            run(&mut slow, b"", 1024, Duration::from_millis(100))
                .await
                .err()
                .unwrap()
                .status,
            408
        );
        let mut noisy = Command::new("/bin/sh");
        noisy.args(["-c", "while true; do printf 0123456789; done"]);
        assert_eq!(
            run(&mut noisy, b"", 16, Duration::from_secs(2))
                .await
                .err()
                .unwrap()
                .status,
            422
        );
    }
}
