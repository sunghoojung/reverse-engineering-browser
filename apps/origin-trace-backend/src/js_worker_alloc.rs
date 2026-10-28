//! Allocation ceiling for the isolated JavaScript worker, never the service.
//! GlobalAlloc cannot unwind. Refusal writes fixed telemetry without allocating
//! and exits only the disposable worker; the caller emits a counted omission.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

pub struct JavaScriptWorkerAllocator;
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static LIMIT: AtomicU64 = AtomicU64::new(u64::MAX);
static WORK: AtomicU64 = AtomicU64::new(0);
pub(crate) const REFUSED: &[u8; 8] = b"REBJSOOM";

/// Drop inherited capabilities before reading any artifact. The worker needs
/// only its three anonymous pipes, memory, and the already loaded executable.
pub(crate) fn contain() -> std::io::Result<()> {
    let descriptors = std::fs::read_dir("/dev/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .collect::<Vec<_>>();
    for fd in descriptors {
        // SAFETY: close owns no Rust object here. The directory iterator has
        // already closed its descriptor; closing that stale number is harmless.
        unsafe { libc::close(fd) };
    }
    contain_network()
}

#[cfg(target_os = "macos")]
fn contain_network() -> std::io::Result<()> {
    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            error: *mut *mut libc::c_char,
        ) -> i32;
        fn sandbox_free_error(error: *mut libc::c_char);
    }
    let mut error = std::ptr::null_mut();
    // SAFETY: literal is NUL terminated and error is a writable out pointer.
    let status = unsafe {
        sandbox_init(
            c"(version 1)(allow default)(deny network*)(deny file-read*)(deny file-write*)"
                .as_ptr(),
            0,
            &mut error,
        )
    };
    if !error.is_null() {
        // SAFETY: the sandbox library owns this error allocation.
        unsafe { sandbox_free_error(error) };
    }
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other("Worker sandbox unavailable"))
    }
}

#[cfg(target_os = "linux")]
fn contain_network() -> std::io::Result<()> {
    // No inherited sockets survive. Deny creation of sockets as well as connect
    // (including socketpair) without allowing a second syscall architecture.
    let mut filter = Vec::new();
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let architecture = 0; // Fail closed on an unsupported syscall ABI.
    filter.push(statement(0x20, 4)); // seccomp_data.arch
    filter.push(libc::sock_filter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: architecture,
    });
    filter.push(statement(0x06, 0x8000_0000)); // SECCOMP_RET_KILL_PROCESS
    filter.push(statement(0x20, 0)); // BPF_LD | BPF_W | BPF_ABS: syscall number
    // x32 uses the x86_64 audit architecture with a different syscall-number
    // bit. Never let that alternate ABI bypass the native syscall filter.
    filter.push(libc::sock_filter {
        code: 0x35,
        jt: 0,
        jf: 1,
        k: 0x4000_0000,
    });
    filter.push(statement(0x06, 0x8000_0000));
    for number in [libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect] {
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: number as u32,
        });
        filter.push(statement(0x06, 0x0005_0000 | libc::EPERM as u32));
    }
    filter.push(statement(0x06, 0x7fff_0000)); // SECCOMP_RET_ALLOW
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: the kernel copies this initialized program synchronously.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn contain_network() -> std::io::Result<()> {
    Err(std::io::Error::other(
        "Worker sandbox unavailable on this platform",
    ))
}

pub(crate) fn start(limit: u64) {
    PEAK.store(LIVE.load(Relaxed), Relaxed);
    LIMIT.store(limit, Relaxed);
}
pub(crate) fn peak() -> u64 {
    PEAK.load(Relaxed)
}
pub(crate) fn record_work(work: u64) {
    WORK.store(work, Relaxed);
}

fn refuse() -> ! {
    let mut report = [0u8; 24];
    report[..8].copy_from_slice(REFUSED);
    report[8..16].copy_from_slice(&peak().to_le_bytes());
    report[16..24].copy_from_slice(&WORK.load(Relaxed).to_le_bytes());
    // SAFETY: the fixed buffer is live for the synchronous write. No allocator,
    // locks, formatting, panic hook or destructor runs on this failure path.
    unsafe {
        libc::write(libc::STDOUT_FILENO, report.as_ptr().cast(), report.len());
        libc::_exit(75);
    }
}
fn reserve(bytes: usize) {
    // Include per-allocation metadata/alignment slack. realloc's old and new
    // blocks coexist in the accounting until the system call completes.
    let bytes = bytes as u64 + 32;
    let live = LIVE.fetch_add(bytes, Relaxed).saturating_add(bytes);
    if live > LIMIT.load(Relaxed) {
        LIVE.fetch_sub(bytes, Relaxed);
        refuse();
    }
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: all allocations and deallocations delegate to System with their
// original layout. The counters own no memory and never recurse or unwind.
unsafe impl GlobalAlloc for JavaScriptWorkerAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        reserve(layout.size());
        // SAFETY: GlobalAlloc's caller supplies a valid nonzero layout.
        let ptr = unsafe { System.alloc(layout) };
        if ptr.is_null() {
            refuse();
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        reserve(layout.size());
        // SAFETY: same System allocation contract as alloc.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if ptr.is_null() {
            refuse();
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr was allocated by this System-backed allocator.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size() as u64 + 32, Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        reserve(size);
        // SAFETY: caller guarantees ptr/layout match and size is valid.
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if ptr.is_null() {
            refuse();
        }
        LIVE.fetch_sub(layout.size() as u64 + 32, Relaxed);
        ptr
    }
}
