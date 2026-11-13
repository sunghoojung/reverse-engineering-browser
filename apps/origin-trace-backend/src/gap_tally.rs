//! The store's drop gaps, kept per store so a Headers, Cookies or provenance
//! read does not rescan the newest 64 MiB for them on every call ("Missing
//! final blocks" and `read_coverage` in protocol/native-network-v3.md). The
//! first call reads the newest 64 MiB; later calls read only the bytes
//! appended since, and none while the store's length is unchanged. A store
//! that shrank, was replaced (another file) or was cleared and written again
//! (the bytes before the last boundary changed) is read again, as the request
//! index checks it.
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use crate::app::Query;
use crate::error::Result;
use crate::event_query::{self, RecordRange};
use crate::event_window;
use crate::request_headers::Drops;

/// Drops kept across sessions, newest last; older ones are forgotten first.
const DROPS: usize = 65_536;
/// Bytes before the last boundary that must be unchanged for it to stand.
const ANCHOR: u64 = 64;

/// What the last scan saw of the store.
struct Seen {
    length: u64,
    /// The record boundary it read to, where the next scan resumes.
    boundary: u64,
    identity: String,
    anchor: Vec<u8>,
}

#[derive(Default)]
struct State {
    seen: Option<Seen>,
    /// (session, gap time, records dropped), in store order.
    drops: VecDeque<(String, u64, u64)>,
    scans: u64,
}

#[derive(Default)]
pub struct GapTally(Mutex<State>);

impl GapTally {
    /// The drops of `session` in `store` as of now.
    pub fn drops(&self, store: &Path, session: &str) -> Result<Drops> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut file = match std::fs::File::open(store) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let (length, identity) = match &file {
            Some(file) => {
                let metadata = file.metadata()?;
                (metadata.len(), crate::request_index::identity_of(&metadata))
            }
            None => (0, String::new()),
        };
        let still = match (&state.seen, file.as_mut()) {
            (Some(seen), Some(file)) => {
                seen.identity == identity
                    && length >= seen.length
                    && anchor(file, seen.boundary)? == seen.anchor
            }
            (Some(seen), None) => seen.length == 0,
            (None, _) => false,
        };
        let filter = event_query::event_filter(&Query::new("type=gap"))?;
        let boundary = match (&state.seen, still) {
            (Some(seen), true) if seen.length == length => seen.boundary,
            // Appended bytes only, from the boundary the last scan stopped at.
            (Some(seen), true) => {
                let mut from = seen.boundary;
                while from < length {
                    let range = RecordRange {
                        first: from,
                        end: length,
                        indexed: false,
                    };
                    let detail =
                        event_query::read_request_records(store, Some(range), DROPS, &filter)?;
                    state.scans += 1;
                    state.keep(&detail.records);
                    let end = detail.coverage.scan_end();
                    if end <= from {
                        break;
                    }
                    from = end;
                }
                from
            }
            // First use, or a store that is no longer the one read: the newest 64 MiB.
            _ => {
                let detail = event_query::read_request_records(store, None, DROPS, &filter)?;
                state.drops.clear();
                state.scans += 1;
                state.keep(&detail.records);
                detail.coverage.scan_end()
            }
        };
        let anchor = match file.as_mut() {
            Some(file) => anchor(file, boundary)?,
            None => Vec::new(),
        };
        state.seen = Some(Seen {
            length,
            boundary,
            identity,
            anchor,
        });
        Ok(Drops::new(
            state
                .drops
                .iter()
                .filter(|(owner, _, _)| owner == session)
                .map(|(_, time, count)| (*time, *count))
                .collect(),
        ))
    }

    /// Forgets the store before a capture clear empties it.
    pub fn reset(&self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.seen = None;
        state.drops.clear();
    }

    #[cfg(test)]
    fn scans(&self) -> u64 {
        self.0.lock().unwrap().scans
    }
}

/// The bytes just before `boundary`, which change when the store is cleared
/// and written again past it.
fn anchor(file: &mut std::fs::File, boundary: u64) -> Result<Vec<u8>> {
    let start = boundary.saturating_sub(ANCHOR);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(boundary - start).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl State {
    fn keep(&mut self, gaps: &[serde_json::Value]) {
        for gap in gaps {
            let count = event_window::dropped_records(gap);
            let (Some(session), Some(time)) = (
                gap["session_id"].as_str(),
                event_window::unsigned(&gap["monotonic_time_ns"]),
            ) else {
                continue;
            };
            if count == 0 {
                continue;
            }
            if self.drops.len() == DROPS {
                self.drops.pop_front();
            }
            self.drops.push_back((session.to_owned(), time, count));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn gap(sequence: u64, session: &str, payload: &str) -> String {
        json!({"protocol_version":3,"session_id":session,"sequence_number":sequence.to_string(),
            "monotonic_time_ns":(sequence * 10).to_string(),"process_id":9,"thread_id":1,"tab_id":0,
            "navigation_id":"0","frame_id":"0","artifact_id":"0","parent_event_id":"0","request_id":"0",
            "category":"canvas","type":"gap","payload_truncated":false,"payload_size":payload.len(),
            "payload_encoding":"hex","payload":hex::encode(payload)})
        .to_string()
            + "\n"
    }

    #[test]
    fn an_unchanged_store_is_not_scanned_again_and_a_grown_one_is_seen() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        std::fs::write(&store, gap(1, "7", "2") + &gap(2, "8", "5")).unwrap();
        let tally = GapTally::default();
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 2);
        assert_eq!(tally.scans(), 1);
        // Unchanged: answered without reading the store.
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 2);
        assert_eq!(tally.drops(&store, "8").unwrap().between(0, None), 5);
        assert_eq!(tally.scans(), 1);
        // Grown, by a drop and a named reason: only the new bytes are read.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&store)
            .unwrap();
        file.write_all((gap(3, "7", "4") + &gap(4, "7", "service_worker_end_lost")).as_bytes())
            .unwrap();
        drop(file);
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 6);
        assert_eq!(tally.scans(), 2);
        assert_eq!(tally.drops(&store, "7").unwrap().between(25, None), 4);
        // A record still being written is read once it is whole.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&store)
            .unwrap();
        let next = gap(5, "7", "1");
        file.write_all(&next.as_bytes()[..next.len() - 10]).unwrap();
        drop(file);
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 6);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&store)
            .unwrap();
        file.write_all(&next.as_bytes()[next.len() - 10..]).unwrap();
        drop(file);
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 7);
        // A store that shrank was replaced and is read again whole.
        std::fs::write(&store, gap(1, "7", "3")).unwrap();
        let scans = tally.scans();
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 3);
        assert_eq!(tally.scans(), scans + 1);
        // Cleared in place and written again past the old length: the bytes
        // before the old boundary changed, so it is read again, not resumed.
        let cleared = gap(1, "8", "9") + &gap(2, "8", "9") + &gap(3, "7", "1");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&store)
            .unwrap();
        file.set_len(0).unwrap();
        drop(file);
        std::fs::write(&store, &cleared).unwrap();
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 1);
        assert_eq!(tally.drops(&store, "8").unwrap().between(0, None), 18);
        // The capture clear forgets it too.
        tally.reset();
        let scans = tally.scans();
        assert_eq!(tally.drops(&store, "7").unwrap().between(0, None), 1);
        assert_eq!(tally.scans(), scans + 1);
        // No store yet: no drops, and no error.
        let missing = GapTally::default();
        assert_eq!(
            missing
                .drops(&root.path().join("none.jsonl"), "7")
                .unwrap()
                .between(0, None),
            0
        );
    }
}
