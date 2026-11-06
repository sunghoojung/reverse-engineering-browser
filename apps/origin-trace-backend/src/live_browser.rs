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
    wasm_budget_reset_file: Option<PathBuf>,
}

impl LiveBrowser {
    pub fn new(options: &Options) -> Self {
        Self {
            binary: options.brave_binary.clone(),
            profile: options.brave_profile.clone(),
            launcher_pid: options.launcher_pid,
            store: options.store.clone(),
            wasm_budget_reset_file: options.wasm_budget_reset_file.clone(),
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
            Some("reset_wasm_sample_budgets") => self.reset_wasm_sample_budgets(request, recording),
            Some("list_inputs") => self.input(request, recording).await,
            Some("click") => self.input(request, recording).await,
            Some("type") => self.input(request, recording).await,
            Some("press") => self.input(request, recording).await,
            Some("scroll") => self.input(request, recording).await,
            _ => Err(Error::bad("Session action is invalid")),
        }
    }

    fn reset_wasm_sample_budgets(&self, request: &Value, recording: bool) -> Result<Value> {
        validation::fields(request, &["action"], "Reset Wasm sample budgets")?;
        if !recording {
            return Err(Error::conflict(
                "Native capture is not running, so the Wasm sample budgets were not reset.",
            )
            .with_code(Code::NativeCaptureUnavailable));
        }
        let Some(path) = &self.wasm_budget_reset_file else {
            return Err(Error::conflict(
                "This backend was not started with a Wasm sample-budget reset file.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        let Some(profile) = &self.profile else {
            return Err(Error::conflict(
                "This backend was not started with its capture browser and profile.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        if Self::holder(profile).is_none() {
            return Err(Error::conflict(
                "The capture browser is not running, so the Wasm sample budgets were not reset.",
            )
            .with_code(Code::TargetUnavailable));
        }
        let generation = bump_wasm_budget_reset(path)?;
        Ok(json!({
            "ok": true,
            "action": "reset_wasm_sample_budgets",
            "generation": generation,
        }))
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

/// Writes the next generation beside the file and renames it into place. The
/// browser applies a generation only when it is greater than the last one it
/// saw, on its writer wake of about 250ms. An exclusive lock covers the
/// read-modify-rename so two resets cannot publish the same generation or
/// overwrite a newer one. The rename itself is what the browser reads, so it
/// never observes a torn decimal.
pub fn bump_wasm_budget_reset(path: &Path) -> Result<u64> {
    let lock_path = path.with_extension("lock");
    let lock = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| {
                Error::conflict("The Wasm sample-budget reset file could not be updated.")
                    .with_code(Code::DependencyUnavailable)
            })?
    };
    lock_wasm_budget_reset(&lock)?;
    let result = bump_wasm_budget_reset_locked(path);
    unlock_wasm_budget_reset(&lock);
    result
}

fn bump_wasm_budget_reset_locked(path: &Path) -> Result<u64> {
    let text = std::fs::read_to_string(path).map_err(|_| {
        Error::conflict("The Wasm sample-budget reset file could not be read.")
            .with_code(Code::DependencyUnavailable)
    })?;
    let current = parse_wasm_budget_generation(&text).ok_or_else(|| {
        Error::conflict("The Wasm sample-budget reset file is not a generation.")
            .with_code(Code::DependencyUnavailable)
    })?;
    let next = current.checked_add(1).ok_or_else(|| {
        Error::conflict("The Wasm sample-budget reset generation cannot increase.")
            .with_code(Code::DependencyUnavailable)
    })?;
    let temporary = path.with_extension("tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| {
                Error::conflict("The Wasm sample-budget reset file could not be updated.")
                    .with_code(Code::DependencyUnavailable)
            })?;
        writeln!(file, "{next}").map_err(|_| {
            Error::conflict("The Wasm sample-budget reset file could not be updated.")
                .with_code(Code::DependencyUnavailable)
        })?;
        file.sync_all().map_err(|_| {
            Error::conflict("The Wasm sample-budget reset file could not be updated.")
                .with_code(Code::DependencyUnavailable)
        })?;
    }
    std::fs::rename(&temporary, path).map_err(|_| {
        Error::conflict("The Wasm sample-budget reset file could not be updated.")
            .with_code(Code::DependencyUnavailable)
    })?;
    Ok(next)
}

fn lock_wasm_budget_reset(file: &std::fs::File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Blocking is safe: each critical section is one small read and rename.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if status == 0 {
        Ok(())
    } else {
        Err(
            Error::conflict("The Wasm sample-budget reset file could not be updated.")
                .with_code(Code::DependencyUnavailable),
        )
    }
}

fn unlock_wasm_budget_reset(file: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

fn parse_wasm_budget_generation(text: &str) -> Option<u64> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
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

    #[test]
    fn bump_wasm_budget_reset_increases_the_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wasm-sample-budget-reset");
        std::fs::write(&path, "0\n").unwrap();
        assert_eq!(bump_wasm_budget_reset(&path).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1\n");
        assert_eq!(bump_wasm_budget_reset(&path).unwrap(), 2);
        assert!(bump_wasm_budget_reset(&directory.path().join("missing")).is_err());
        std::fs::write(&path, "x\n").unwrap();
        assert!(bump_wasm_budget_reset(&path).is_err());
    }

    #[test]
    fn bump_wasm_budget_reset_serializes_concurrent_increments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wasm-sample-budget-reset");
        std::fs::write(&path, "0\n").unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..25 {
                        bump_wasm_budget_reset(&path).unwrap();
                    }
                });
            }
        });
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "100");
    }
}
