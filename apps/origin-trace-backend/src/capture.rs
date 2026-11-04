//! The live capture lifecycle of one backend. The launcher starts the native
//! event broker, waits for its socket, then starts this backend; a backend
//! never gets a second broker.
//!
//! Liveness comes from the kernel, not from a path. The broker holds an
//! exclusive lock on its event store guard from startup until it exits, and
//! the kernel releases that lock even when the broker is killed. The socket
//! file only tells how it exited: the broker unlinks it on its own shutdown
//! path, so a socket left behind means it was killed or crashed.
use crate::config::{CaptureMode, Options};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// An idle or demo backend: no broker belongs to it.
    NotLive,
    Running,
    /// Stop was delivered to the broker, which has not exited yet.
    StopRequested,
    /// The broker exited after this backend asked it to stop.
    Stopped,
    /// The broker exited through its own shutdown path without a stop
    /// request: the session expired, the browser disconnected, or the broker
    /// failed and said why in its log.
    Ended,
    /// The broker is gone and left its socket behind: it was killed or crashed.
    Lost,
}
impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotLive => "not_live",
            Self::Running => "running",
            Self::StopRequested => "stop_requested",
            Self::Stopped => "stopped",
            Self::Ended => "ended",
            Self::Lost => "lost",
        }
    }
    /// The broker process is running and holds its event store.
    pub fn broker_running(self) -> bool {
        matches!(self, Self::Running | Self::StopRequested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    /// The broker holds its event store guard.
    Alive,
    /// No process holds the guard; `socket_left` says the socket remains.
    Exited {
        socket_left: bool,
    },
    StopDelivered,
}

/// The only transition table. Exits are terminal: a broker never restarts
/// under the same backend, so a later lock holder is not this session's.
fn next(state: State, event: Event) -> State {
    use State::*;
    match (state, event) {
        (NotLive | Stopped | Ended | Lost, _) => state,
        (Running | StopRequested, Event::StopDelivered) => StopRequested,
        (Running | StopRequested, Event::Alive) => state,
        (Running | StopRequested, Event::Exited { socket_left: true }) => Lost,
        (Running, Event::Exited { socket_left: false }) => Ended,
        (StopRequested, Event::Exited { socket_left: false }) => Stopped,
    }
}

/// Why a stop was not dispatched.
pub enum StopRefusal {
    NotRunning(State),
    /// The configured PID is gone or is no longer the process the launcher
    /// named at startup. Signaling it could stop an unrelated process.
    UnconfirmedBroker,
    Signal(std::io::Error),
}

pub struct Capture {
    socket: Option<PathBuf>,
    /// The broker's lifetime lock beside the event store.
    guard: PathBuf,
    broker: Option<Broker>,
    state: Mutex<State>,
}
impl Capture {
    pub fn new(options: &Options) -> Self {
        let mut guard = options.store.clone().into_os_string();
        guard.push(".reb-lock-v1");
        Self {
            socket: options.socket.clone(),
            guard: guard.into(),
            broker: options.broker_pid.filter(|pid| *pid > 0).map(Broker::new),
            state: Mutex::new(if options.capture_mode() == CaptureMode::Live {
                State::Running
            } else {
                State::NotLive
            }),
        }
    }
    /// Stop and clear need a broker PID to signal.
    pub fn controls_available(&self) -> bool {
        self.broker.is_some() && self.socket.is_some()
    }
    /// Observes the broker and returns the current state.
    pub fn state(&self) -> State {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.observe(&mut state)
    }
    /// Signals the broker to stop when it is running and the PID is still the
    /// process the launcher named. A repeat after a timed-out stop signals
    /// again. Observation and signal hold one lock, so an exit cannot be
    /// recorded as ended between them.
    pub fn request_stop(&self) -> Result<State, StopRefusal> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.observe(&mut state);
        if !current.broker_running() {
            return Err(StopRefusal::NotRunning(current));
        }
        let broker = self
            .broker
            .as_ref()
            .filter(|broker| broker.confirmed())
            .ok_or(StopRefusal::UnconfirmedBroker)?;
        #[cfg(unix)]
        if unsafe { libc::kill(broker.pid, libc::SIGUSR1) } != 0 {
            return Err(StopRefusal::Signal(std::io::Error::last_os_error()));
        }
        #[cfg(not(unix))]
        {
            let _ = broker;
            return Err(StopRefusal::UnconfirmedBroker);
        }
        *state = next(*state, Event::StopDelivered);
        Ok(*state)
    }
    fn observe(&self, state: &mut State) -> State {
        // Terminal and non-live states never probe, so a clear never races
        // this backend's own momentary shared lock on the guard.
        if state.broker_running() {
            let event = if writer_holds(&self.guard) {
                Event::Alive
            } else {
                Event::Exited {
                    socket_left: self.socket.as_deref().is_some_and(is_socket),
                }
            };
            *state = next(*state, event);
        }
        *state
    }
}

/// True while another process holds the guard exclusively. The probe never
/// creates the guard, and a shared lock it obtains is released on return.
fn writer_holds(guard: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(guard)
        else {
            return false;
        };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            return false;
        }
        std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
    }
    #[cfg(not(unix))]
    {
        let _ = guard;
        false
    }
}

fn is_socket(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// The broker PID and its process start time, read when this backend starts.
/// The launcher starts the broker first, so a later start time at the same
/// PID is a different process.
struct Broker {
    pid: i32,
    started: Option<(u64, u64)>,
}
impl Broker {
    fn new(pid: i32) -> Self {
        Self {
            pid,
            started: start_time(pid),
        }
    }
    fn confirmed(&self) -> bool {
        self.started.is_some() && start_time(self.pid) == self.started
    }
}

#[cfg(target_vendor = "apple")]
fn start_time(pid: i32) -> Option<(u64, u64)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    (info.pbi_pid == pid as u32).then_some((info.pbi_start_tvsec, info.pbi_start_tvusec))
}

#[cfg(target_os = "linux")]
fn start_time(pid: i32) -> Option<(u64, u64)> {
    // Field 22 of /proc/PID/stat, counted after the parenthesized command,
    // which may itself contain spaces and parentheses.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = &stat[stat.rfind(')')? + 1..];
    let ticks = fields.split_whitespace().nth(19)?.parse().ok()?;
    Some((ticks, 0))
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn start_time(_: i32) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::{Event, State, next};

    #[test]
    fn exits_are_terminal_and_say_who_ended_the_capture() {
        use State::*;
        let clean = Event::Exited { socket_left: false };
        let crashed = Event::Exited { socket_left: true };
        assert_eq!(next(Running, Event::Alive), Running);
        assert_eq!(next(Running, clean), Ended);
        assert_eq!(next(Running, crashed), Lost);
        assert_eq!(next(Running, Event::StopDelivered), StopRequested);
        assert_eq!(next(StopRequested, Event::Alive), StopRequested);
        assert_eq!(next(StopRequested, Event::StopDelivered), StopRequested);
        assert_eq!(next(StopRequested, clean), Stopped);
        assert_eq!(next(StopRequested, crashed), Lost);
        for terminal in [NotLive, Stopped, Ended, Lost] {
            for event in [Event::Alive, clean, crashed, Event::StopDelivered] {
                assert_eq!(next(terminal, event), terminal);
            }
        }
    }

    #[test]
    fn a_running_process_keeps_its_start_time() {
        let own = std::process::id() as i32;
        assert!(super::start_time(own).is_some());
        assert_eq!(super::start_time(own), super::start_time(own));
        assert!(super::start_time(i32::MAX).is_none());
    }
}
