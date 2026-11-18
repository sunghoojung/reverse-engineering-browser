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
    let found = cache.lock().ok().and_then(|entries| {
        entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, value)| value.clone())
    });
    if let Some(found) = found {
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
