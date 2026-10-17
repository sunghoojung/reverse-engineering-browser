//! The only authority for startup holds is a process/profile created here.
//! A user-supplied DevTools endpoint never grants this capability.
use crate::config::Options;
use std::{io, process::Stdio, time::Duration};
use tempfile::TempDir;
use tokio::process::{Child, Command};

pub struct CaptureFirstBrowser {
    child: Child,
    group: i32,
    // Drop only after the process group is stopped, including failed startup.
    profile: Option<TempDir>,
}
impl CaptureFirstBrowser {
    pub async fn launch(
        options: &mut Options,
        cancelled: &mut tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<Option<Self>> {
        let Some(executable) = options.capture_first_browser.as_ref() else {
            return Ok(None);
        };
        if options.devtools_active_port.is_some() || !options.capture_network_content {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Capture-first requires content capture and cannot use an existing browser endpoint",
            ));
        }
        let profile = tempfile::Builder::new()
            .prefix("reb-capture-first-")
            .tempdir()?;
        let mut command = Command::new(executable);
        command
            .args([
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
            ])
            .arg(format!("--user-data-dir={}", profile.path().display()));
        if options.capture_first_headless {
            command.arg("--headless=new");
        }
        // No URL or arbitrary flags are accepted: capture arms on about:blank
        // before the researcher deliberately navigates the disposable browser.
        let child = command
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0)
            .spawn()?;
        let group = i32::try_from(
            child
                .id()
                .ok_or_else(|| io::Error::other("Browser PID unavailable"))?,
        )
        .map_err(|_| io::Error::other("Browser PID out of range"))?;
        let mut browser = Self {
            child,
            group,
            profile: Some(profile),
        };
        let active = browser
            .profile
            .as_ref()
            .unwrap()
            .path()
            .join("DevToolsActivePort");
        let ready = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if *cancelled.borrow() { return Err(io::Error::new(io::ErrorKind::Interrupted, "Capture-first browser launch cancelled")); }
                if let Some(status) = browser.child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "Disposable capture-first browser exited: {status}"
                    )));
                }
                if let Ok(body) = tokio::fs::read_to_string(&active).await {
                    let mut lines = body.lines();
                    if lines
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .is_some_and(|p| p > 0)
                        && lines
                            .next()
                            .is_some_and(|p| p.starts_with("/devtools/browser/") && p.len() <= 4096)
                    {
                        return Ok(());
                    }
                }
                tokio::select! {
                    _=tokio::time::sleep(Duration::from_millis(25))=>(),
                    _=cancelled.changed()=>return Err(io::Error::new(io::ErrorKind::Interrupted, "Capture-first browser launch cancelled")),
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Disposable capture-first browser startup timed out",
            ))
        });
        if let Err(error) = ready {
            browser.stop().await;
            return Err(error);
        }
        options.devtools_active_port = Some(active);
        options.capture_first_owned = true;
        println!(
            "CAPTURE-FIRST EXPERIMENT: fresh disposable browser; startup is briefly paused for capture setup. Wait for Traffic capture readiness before navigation. Initial OOPIF requests and bounded content can still be missing."
        );
        Ok(Some(browser))
    }
    pub fn exited(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(None))
    }
    pub async fn stop(&mut self) {
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGTERM);
            }
            if tokio::time::timeout(Duration::from_secs(2), self.child.wait())
                .await
                .is_err()
            {
                unsafe {
                    libc::kill(-self.group, libc::SIGKILL);
                }
                let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
            }
            // Descendants can survive an already exited browser leader.
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
            // A leader wait is not proof that every descendant has exited.
            // Bound verification; preserve the private profile if cleanup is uncertain.
            for _ in 0..40 {
                if unsafe { libc::kill(-self.group, 0) } != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if unsafe { libc::kill(-self.group, 0) } == 0 {
                if let Some(profile) = self.profile.take() {
                    let _ = profile.keep();
                }
                eprintln!(
                    "Capture-first browser group exit could not be confirmed; its private temporary profile was preserved."
                );
            }
            self.group = 0;
        }
    }
}
impl Drop for CaptureFirstBrowser {
    fn drop(&mut self) {
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
            // Drop cannot await group termination. Never delete a possibly live profile.
            if let Some(profile) = self.profile.take() {
                let _ = profile.keep();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn endpoint_or_cli_cannot_grant_owned_capture() {
        let ordinary =
            Options::try_parse_from(["test", "--devtools-active-port", "/tmp/port"]).unwrap();
        assert!(!ordinary.capture_first_owned);
        assert!(Options::try_parse_from(["test", "--capture-first-owned"]).is_err());
        assert!(Options::try_parse_from(["test", "--capture-first-browser", "/browser"]).is_err());
        assert!(Options::try_parse_from(["test", "--capture-first-headless"]).is_err());
        assert!(
            Options::try_parse_from([
                "test",
                "--capture-network-content",
                "--capture-first-browser",
                "/browser",
                "--devtools-active-port",
                "/tmp/port"
            ])
            .is_err()
        );
        let requested = Options::try_parse_from([
            "test",
            "--capture-network-content",
            "--capture-first-browser",
            "/browser",
        ])
        .unwrap();
        assert!(
            !requested.capture_first_owned,
            "launch success, not a claim flag, grants ownership"
        );
    }
}
