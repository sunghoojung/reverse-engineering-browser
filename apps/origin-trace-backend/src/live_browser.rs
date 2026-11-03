//! Control of this backend's own live capture session for agents: open a URL
//! in the capture browser, or end the session. Both act only on the browser
//! profile and launcher this backend was started with. Neither touches another
//! browser, and neither runs page JavaScript.
use crate::{
    config::Options,
    error::{Code, Error, Result},
    event_query, native_input, validation,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

/// Chromium hands a second launch with the same profile to the running browser
/// and exits. A process that is still running after this long started a new
/// browser instead, which would not be captured.
const RELAY_DEADLINE: Duration = Duration::from_secs(10);
/// Time for the end response to reach the caller before the launcher stops
/// this backend with the rest of the session.
const END_GRACE: Duration = Duration::from_millis(300);
/// How long an opened page has to produce its first stored record. Any new
/// record shows the browser is a connected capture browser; none does not.
const OBSERVE_DEADLINE: Duration = Duration::from_secs(10);
/// Switches for the relay process. The running browser ignores them, since a
/// relayed command line only names what to open. If the relay ever starts a
/// browser of its own, they leave it with no network to reach.
const RELAY_ISOLATION: [&str; 8] = [
    "--no-first-run",
    "--no-default-browser-check",
    "--use-mock-keychain",
    "--disable-background-networking",
    "--disable-sync",
    "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=<-loopback>",
    "--host-resolver-rules=MAP * ~NOTFOUND",
];

pub struct LiveBrowser {
    binary: Option<PathBuf>,
    profile: Option<PathBuf>,
    launcher_pid: Option<i32>,
    store: PathBuf,
}

impl LiveBrowser {
    pub fn new(options: &Options) -> Self {
        Self {
            binary: options.brave_binary.clone(),
            profile: options.brave_profile.clone(),
            launcher_pid: options.launcher_pid,
            store: options.store.clone(),
        }
    }

    /// The process that holds the profile's singleton lock, when it is alive.
    /// Chromium's lock is a symlink whose target is `<host>-<pid>`.
    fn holder(profile: &Path) -> Option<i32> {
        let target = std::fs::read_link(profile.join("SingletonLock")).ok()?;
        let pid = target
            .to_str()?
            .rsplit_once('-')?
            .1
            .parse::<i32>()
            .ok()
            .filter(|pid| *pid > 0)?;
        alive(pid).then_some(pid)
    }

    /// `recording` is true while native capture is live and not stopped.
    pub async fn action(&self, request: &Value, recording: bool) -> Result<Value> {
        match request["action"].as_str() {
            Some("open_url") => {
                // Driving the browser while nothing records it would produce
                // activity with no evidence, so a page opens only under capture.
                if !recording {
                    return Err(Error::conflict(
                        "Native capture is not running, so the page would not be captured. No URL was opened.",
                    )
                    .with_code(Code::NativeCaptureUnavailable));
                }
                self.open_url(request).await
            }
            Some("end") => self.end(request),
            Some("list_inputs") => self.input(request, recording).await,
            Some("click") => self.input(request, recording).await,
            Some("type") => self.input(request, recording).await,
            Some("press") => self.input(request, recording).await,
            Some("scroll") => self.input(request, recording).await,
            _ => Err(Error::bad("Session action is invalid")),
        }
    }

    async fn open_url(&self, request: &Value) -> Result<Value> {
        validation::fields(request, &["action", "url"], "Open URL")?;
        let text = validation::text(&request["url"], "URL", 4096, false, false)?;
        let url = url::Url::parse(text)
            .ok()
            .filter(|url| {
                ["http", "https"].contains(&url.scheme())
                    && url.username().is_empty()
                    && url.password().is_none()
            })
            .ok_or_else(|| Error::bad("URL must be HTTP or HTTPS without embedded credentials"))?;
        let (Some(binary), Some(profile)) = (&self.binary, &self.profile) else {
            return Err(Error::conflict(
                "This backend was not started with its capture browser and profile. Restart the session with a current launcher.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        let Some(holder) = Self::holder(profile) else {
            return Err(Error::conflict(
                "The capture browser is not running, so no URL was opened. Start a new live session.",
            )
            .with_code(Code::TargetUnavailable));
        };
        let before = event_query::current_boundary(&self.store).unwrap_or(0);
        let mut relay = tokio::process::Command::new(binary)
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(RELAY_ISOLATION)
            .arg(url.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        match tokio::time::timeout(RELAY_DEADLINE, relay.wait()).await {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(_)) | Ok(Err(_)) => {
                return Err(Error::new(
                    502,
                    "The capture browser did not accept the URL. Nothing else was started.",
                )
                .with_code(Code::DependencyUnavailable));
            }
            Err(_) => {
                let _ = relay.kill().await;
                return Err(Error::conflict(
                    "A browser launch did not hand the URL to the capture browser and was stopped. Start a new live session.",
                )
                .with_code(Code::TargetUnavailable));
            }
        }
        if Self::holder(profile) != Some(holder) {
            return Err(Error::conflict(
                "The capture browser changed while the URL was opening. Start a new live session.",
            )
            .with_code(Code::StateConflict));
        }
        // The broker socket proves only that the broker is listening. A new
        // stored record proves the browser is a connected capture browser.
        let deadline = tokio::time::Instant::now() + OBSERVE_DEADLINE;
        let observed = loop {
            if event_query::current_boundary(&self.store).is_ok_and(|end| end > before) {
                break true;
            }
            if tokio::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        Ok(
            json!({"ok": true, "action": "open_url", "opened": "new_tab",
            "capture_observed": observed}),
        )
    }

    /// Trusted input to this session's own capture browser, found by the
    /// process that holds its profile. See `native_input`.
    async fn input(&self, request: &Value, recording: bool) -> Result<Value> {
        native_input::parse(request)?;
        if !recording {
            return Err(Error::conflict(
                "Native capture is not running, so input would not be captured. No input was sent.",
            )
            .with_code(Code::NativeCaptureUnavailable));
        }
        let Some(profile) = &self.profile else {
            return Err(Error::conflict(
                "This backend was not started with its capture browser profile. No input was sent.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        let Some(pid) = Self::holder(profile) else {
            return Err(
                Error::conflict("The capture browser is not running. No input was sent.")
                    .with_code(Code::TargetUnavailable),
            );
        };
        let request = request.clone();
        tokio::task::spawn_blocking(move || native_input::act(pid, &request))
            .await
            .map_err(|_| Error::new(500, "Input task failed"))?
    }

    /// Asks the launcher that started this backend to stop the session. The
    /// launcher closes the capture browser and every helper, including this
    /// process. Stored evidence stays on disk.
    fn end(&self, request: &Value) -> Result<Value> {
        validation::fields(request, &["action", "confirm"], "End session")?;
        if request["confirm"] != true {
            return Err(Error::bad(
                "Confirm that ending the session closes the capture browser",
            ));
        }
        let Some(launcher) = self.launcher_pid else {
            return Err(Error::conflict(
                "This backend was not started by a live-session launcher, so it cannot end the session.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        // The launcher is this process's parent. A different parent means the
        // launcher is gone and the PID may now name an unrelated process.
        #[cfg(unix)]
        if unsafe { libc::getppid() } != launcher {
            return Err(Error::conflict(
                "The live-session launcher is no longer running; nothing was stopped.",
            )
            .with_code(Code::TargetUnavailable));
        }
        tokio::spawn(async move {
            tokio::time::sleep(END_GRACE).await;
            #[cfg(unix)]
            unsafe {
                libc::kill(launcher, libc::SIGTERM);
            }
        });
        Ok(json!({"ok": true, "action": "end", "ending": true}))
    }
}

fn alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_singleton_holder_is_the_live_pid_in_the_lock() {
        let profile = tempfile::tempdir().unwrap();
        assert_eq!(LiveBrowser::holder(profile.path()), None);
        let me = std::process::id() as i32;
        std::os::unix::fs::symlink(
            format!("host.local-{me}"),
            profile.path().join("SingletonLock"),
        )
        .unwrap();
        assert_eq!(LiveBrowser::holder(profile.path()), Some(me));
        std::fs::remove_file(profile.path().join("SingletonLock")).unwrap();
        std::os::unix::fs::symlink("host-2147483646", profile.path().join("SingletonLock"))
            .unwrap();
        assert_eq!(LiveBrowser::holder(profile.path()), None);
    }
}
