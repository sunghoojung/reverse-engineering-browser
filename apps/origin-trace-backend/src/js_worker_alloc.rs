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
