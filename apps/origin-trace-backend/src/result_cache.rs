//! A few recently built analysis results, kept by key so a later page of the
//! same request reuses the expensive part. Entries are whole results: a build
//! that fails or is cancelled keeps nothing.
use crate::error::Result;
use std::sync::{Arc, Mutex};

/// A few recently built values, most recent last.
pub(crate) type Cache<K, V> = Mutex<Vec<(K, Arc<V>)>>;

/// Returns the entry for `key`, building and keeping it when absent, and
/// drops the oldest entries past `capacity`.
pub(crate) fn kept<K: PartialEq, V>(
    cache: &Cache<K, V>,
    key: K,
    capacity: usize,
    build: impl FnOnce() -> Result<V>,
) -> Result<Arc<V>> {
    if let Some(found) = find(cache, &key) {
        return Ok(found);
    }
    let value = Arc::new(build()?);
    if let Ok(mut entries) = cache.lock() {
        entries.retain(|(k, _)| *k != key);
        entries.push((key, value.clone()));
        while entries.len() > capacity {
            entries.remove(0);
        }
    }
    Ok(value)
}

/// [`kept`] bounded by what the entries hold rather than by their count, for
/// results whose size spans orders of magnitude (one function's simulation is
/// kilobytes or hundreds of megabytes). The oldest entries go first once the
/// kept total passes `budget`; the newest entry is always kept, so a result
/// larger than the budget is still reused by the next request for it.
pub(crate) fn kept_within<K: PartialEq, V>(
    cache: &Cache<K, V>,
    key: K,
    budget: u64,
    size: impl Fn(&V) -> u64,
    build: impl FnOnce() -> Result<V>,
) -> Result<Arc<V>> {
    if let Some(found) = find(cache, &key) {
        return Ok(found);
    }
    let value = Arc::new(build()?);
    if let Ok(mut entries) = cache.lock() {
        entries.retain(|(k, _)| *k != key);
        entries.push((key, value.clone()));
        let mut total: u64 = entries.iter().map(|(_, value)| size(value)).sum();
        while entries.len() > 1 && total > budget {
            let (_, oldest) = entries.remove(0);
            total = total.saturating_sub(size(&oldest));
        }
    }
    Ok(value)
}

/// The kept entry for `key`, moved to the newest place.
pub(crate) fn find<K: PartialEq, V>(cache: &Cache<K, V>, key: &K) -> Option<Arc<V>> {
    let mut entries = cache.lock().ok()?;
    let position = entries.iter().position(|(k, _)| k == key)?;
    let entry = entries.remove(position);
    let value = entry.1.clone();
    entries.push(entry);
    Some(value)
}
