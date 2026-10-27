//! Bounded, byte-verified polling of the append-only evidence store.
//!
//! The cache is an optimization, never an authority: every poll reads at most
//! 64 MiB plus the predecessor byte and checks the exact overlap before reuse.
//! Small per-record summaries are reused on a sliding tail; JSON trees are kept
//! only for the two independent newest-event windows.
use crate::{
    error::{Error, Result},
    evidence,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    fs::Metadata,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 4096;
const MAX_EVENTS: usize = 5000;

#[derive(Debug, PartialEq)]
pub struct EventWindow {
    pub events: Vec<Value>,
    pub network_events: Vec<Value>,
    pub sequence_gaps: u64,
    pub sequence_gaps_saturated: bool,
    pub queue_drops: u64,
    pub queue_drops_saturated: bool,
    pub coverage: Value,
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}
impl Identity {
    fn of(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                created: metadata.created().ok(),
            }
        }
    }
}

// Identity and change time are not enough. A same-size rewrite can restore
// mtime without advancing ctime, and that must not produce a false 304.
pub fn etag(path: &Path, signature: &str) -> String {
    let identity = evidence::observed_identity(path, true);
    evidence::resource_etag(path, &format!("{signature}:event-window-v4:{identity}"))
}

struct Record {
    start: u64,
    end: u64,
    terminated: bool,
    stream: (u64, u64),
    sequence: u64,
    drops: u64,
    network: bool,
    event: Option<Value>,
}
struct Snapshot {
    identity: Identity,
    start: u64,
    end: u64,
    predecessor: Option<u8>,
    bytes: Vec<u8>,
    records: Vec<Record>,
}
impl Snapshot {
    fn overlaps(&self, newer: &Self) -> bool {
        if self.identity != newer.identity
            || newer.start < self.start
            || newer.end < self.end
            || newer.start > self.end
        {
            return false;
        }
        let offset = (newer.start - self.start) as usize;
        let predecessor = if offset == 0 {
            self.predecessor
        } else {
            self.bytes.get(offset - 1).copied()
        };
        predecessor == newer.predecessor
            && self.bytes[offset..] == newer.bytes[..(self.end - newer.start) as usize]
    }
}

pub struct EventWindowCache {
    snapshot: Option<Snapshot>,
    maximum_bytes: usize,
    #[cfg(test)]
    parsed_records: usize,
}
impl Default for EventWindowCache {
    fn default() -> Self {
        Self {
            snapshot: None,
            maximum_bytes: SCAN_BYTES,
            #[cfg(test)]
            parsed_records: 0,
        }
    }
}
impl EventWindowCache {
    pub fn read(
        &mut self,
        path: &Path,
        limit: usize,
        validate: fn(&Value) -> Result<()>,
    ) -> Result<EventWindow> {
        // Any failure invalidates the previous snapshot, including partial tails.
        let previous = self.snapshot.take();
        #[cfg(test)]
        {
            self.parsed_records = 0;
        }
        let mut snapshot = match read_tail(path, self.maximum_bytes)? {
            Some(snapshot) => snapshot,
            None => return Ok(summarize(&mut [], 0, 0, self.maximum_bytes, limit, &[])?.0),
        };
        let skip = if snapshot.start == 0 || snapshot.predecessor == Some(b'\n') {
            0
        } else {
            // Never discard a whole valid boundary record or parse a truncated
            // prefix as a record, even if its suffix happens to be valid JSON.
            snapshot
                .bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(snapshot.bytes.len(), |n| n + 1)
        };
        if skip > MAX_RECORD_BYTES + 1 {
            return Err(Error::new(
                500,
                "The evidence store contains an oversized event",
            ));
        }
        let first = snapshot.start + skip as u64;
        let mut parse_from = first;
        if let Some(mut old) = previous.filter(|old| old.overlaps(&snapshot)) {
            old.records
                .retain(|record| record.start >= first && record.terminated);
            if let Some(last) = old.records.last() {
                parse_from = last.end;
            }
            snapshot.records = old.records;
        }
        let mut position = (parse_from - snapshot.start) as usize;
        while position < snapshot.bytes.len() {
            let rest = &snapshot.bytes[position..];
            let newline = rest.iter().position(|byte| *byte == b'\n');
            let length = newline.unwrap_or(rest.len());
            let end = position + length + usize::from(newline.is_some());
            let line = &rest[..length];
            if !line.iter().all(u8::is_ascii_whitespace) {
                if length > MAX_RECORD_BYTES {
                    return Err(Error::new(
                        500,
                        "The evidence store contains an oversized event",
                    ));
                }
                let event: Value = serde_json::from_slice(line).map_err(|_| malformed())?;
                validate(&event)?;
                let session = unsigned(&event["session_id"]).ok_or_else(malformed)?;
                let process = unsigned(&event["process_id"]).ok_or_else(malformed)?;
                let sequence = unsigned(&event["sequence_number"]).ok_or_else(malformed)?;
                let drops = if event["type"] == "gap" {
                    drop_weight(&event)
                } else {
                    0
                };
                snapshot.records.push(Record {
                    start: snapshot.start + position as u64,
                    end: snapshot.start + end as u64,
                    terminated: newline.is_some(),
                    stream: (session, process),
                    sequence,
                    drops,
                    network: is_network(&event),
                    event: None,
                });
                #[cfg(test)]
                {
                    self.parsed_records += 1;
                }
            }
            position = end;
        }
        let (window, retained) = summarize(
            &mut snapshot.records,
            first,
            snapshot.end,
            self.maximum_bytes,
            limit,
            &snapshot.bytes[skip..],
        )?;
        for (index, record) in snapshot.records.iter_mut().enumerate() {
            if !retained[index] {
                record.event = None;
            }
        }
        self.snapshot = Some(snapshot);
        Ok(window)
    }
}

fn malformed() -> Error {
    Error::new(500, "The evidence store contains a malformed event")
}
fn unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text)
            if !text.is_empty()
                && text.len() <= 20
                && (text.len() == 1 || !text.starts_with('0'))
                && text.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            text.parse().ok()
        }
        _ => None,
    }
}
fn drop_weight(event: &Value) -> u64 {
    event["payload"]
        .as_str()
        .and_then(|text| hex::decode(text).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| unsigned(&Value::String(text)))
        .filter(|count| *count > 0)
        .unwrap_or(1)
}
fn is_network(event: &Value) -> bool {
    event["category"] == "network"
        && matches!(
            event["type"].as_str(),
            Some(
                "request_initiated"
                    | "request_started"
                    | "request_redirected"
                    | "response_started"
                    | "response_completed"
                    | "request_completed"
                    | "request_failed"
            )
        )
}
fn add(total: &mut u64, saturated: &mut bool, count: u64) {
    match total.checked_add(count) {
        Some(sum) => *total = sum,
        None => {
            *total = u64::MAX;
            *saturated = true;
        }
    }
}

fn read_tail(path: &Path, maximum: usize) -> Result<Option<Snapshot>> {
    let mut file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(500, "Evidence store must be a regular file"));
    }
    let end = metadata.len();
    let start = end.saturating_sub(maximum as u64);
    let predecessor = if start == 0 {
        None
    } else {
        file.seek(SeekFrom::Start(start - 1))?;
        let mut byte = [0];
        file.read_exact(&mut byte)?;
        Some(byte[0])
    };
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (end - start) as usize];
    // A fixed endpoint bounds work even while a producer continues appending.
    file.read_exact(&mut bytes)?;
    Ok(Some(Snapshot {
        identity: Identity::of(&metadata),
        start,
        end,
        predecessor,
        bytes,
        records: Vec::new(),
    }))
}

fn summarize(
    records: &mut [Record],
    start: u64,
    end: u64,
    maximum: usize,
    limit: usize,
    bytes: &[u8],
) -> Result<(EventWindow, Vec<bool>)> {
    let limit = limit.min(MAX_EVENTS);
    let mut window = EventWindow {
        events: Vec::new(),
        network_events: Vec::new(),
        sequence_gaps: 0,
        sequence_gaps_saturated: false,
        queue_drops: 0,
        queue_drops_saturated: false,
        coverage: Value::Null,
    };
    let mut marks: HashMap<(u64, u64), (u64, u64, HashSet<u64>)> = HashMap::new();
    let mut retained = vec![false; records.len()];
    let general_start = records.len().saturating_sub(limit);
    let network_count = records.iter().filter(|record| record.network).count();
    let mut network_skip = network_count.saturating_sub(limit);
    for (index, record) in records.iter_mut().enumerate() {
        let stream = marks
            .entry(record.stream)
            .or_insert_with(|| (record.sequence, record.sequence, HashSet::new()));
        stream.0 = stream.0.min(record.sequence);
        stream.1 = stream.1.max(record.sequence);
        stream.2.insert(record.sequence);
        add(
            &mut window.queue_drops,
            &mut window.queue_drops_saturated,
            record.drops,
        );
        let keep_general = index >= general_start;
        let keep_network = record.network
            && if network_skip > 0 {
                network_skip -= 1;
                false
            } else {
                true
            };
        if keep_general || keep_network {
            if record.event.is_none() {
                let from = (record.start - start) as usize;
                let to = (record.end - start) as usize - usize::from(record.terminated);
                record.event =
                    Some(serde_json::from_slice(&bytes[from..to]).map_err(|_| malformed())?);
            }
            let event = record.event.as_ref().unwrap();
            if keep_general {
                window.events.push(event.clone());
            }
            if keep_network {
                window.network_events.push(event.clone());
            }
            retained[index] = true;
        }
    }
    // Count absent IDs inside observed bounds, independent of arrival order.
    for (low, high, seen) in marks.values() {
        add(
            &mut window.sequence_gaps,
            &mut window.sequence_gaps_saturated,
            high - low - (seen.len() as u64 - 1),
        );
    }
    window.coverage = json!({
        "scope": if start == 0 { "store" } else { "bounded_tail" },
        "scan_start": start.to_string(), "scan_end": end.to_string(), "scan_limit": maximum,
        "events_limited": records.len() > limit, "network_events_limited": network_count > limit
    });
    Ok((window, retained))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::validate_event;
    use std::{fs, io::Write, time::Instant};

    fn event(sequence: u64, category: &str, kind: &str, payload: &str) -> Value {
        json!({"protocol_version":3,"session_id":"1","sequence_number":sequence.to_string(),
            "monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"0",
            "request_id":"1","process_id":7,"category":category,"type":kind,
            "payload_encoding":"hex","payload":hex::encode(payload),"payload_size":payload.len()})
    }
    fn line(event: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(event).unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn write(path: &Path, events: &[Value]) -> Vec<u8> {
        let bytes: Vec<u8> = events.iter().flat_map(line).collect();
        fs::write(path, &bytes).unwrap();
        bytes
    }
    fn poll(cache: &mut EventWindowCache, path: &Path, limit: usize) -> EventWindow {
        cache.read(path, limit, validate_event).unwrap()
    }
    fn ids(events: &[Value]) -> Vec<u64> {
        events
            .iter()
            .map(|event| unsigned(&event["sequence_number"]).unwrap())
            .collect()
    }
    fn cache_with_budget(maximum_bytes: usize) -> EventWindowCache {
        EventWindowCache {
            maximum_bytes,
            ..Default::default()
        }
    }

    #[test]
    fn newest_independent_network_retention_and_gap_scope() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let mut events = vec![
            event(1, "network", "request_started", ""),
            event(2, "network", "request_failed", ""),
        ];
        events.extend((3..=6).map(|n| event(n, "webgl", "api_call", "")));
        events.push(event(7, "canvas", "api_call", ""));
        write(&path, &events);
        let mut cache = EventWindowCache::default();
        let window = poll(&mut cache, &path, 1);
        assert_eq!(ids(&window.events), vec![7]);
        assert_eq!(ids(&window.network_events), vec![2]);
        assert_eq!(window.coverage["network_events_limited"], true);
        // Gap rows cannot consume network capacity, even after a full general-window slide.
        events.extend((8..=30).map(|n| event(n, "canvas", "gap", "4")));
        write(&path, &events);
        let window = poll(&mut cache, &path, 2);
        assert_eq!(ids(&window.network_events), vec![1, 2]);
        assert_eq!(window.queue_drops, 23 * 4);
        assert_eq!(window.coverage["scope"], "store");
    }

    #[test]
    fn exact_record_boundaries_and_sliding_overlap_reuse() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let events: Vec<_> = (10..=19)
            .map(|n| event(n, "canvas", "api_call", ""))
            .collect();
        let bytes = write(&path, &events);
        let size = line(&events[0]).len();
        let mut cache = cache_with_budget(5 * size);
        let window = poll(&mut cache, &path, 10);
        assert_eq!(ids(&window.events), vec![15, 16, 17, 18, 19]);
        assert_eq!(cache.parsed_records, 5);
        assert_eq!(window.coverage["scan_start"], (5 * size).to_string());
        assert_eq!(window.coverage["scope"], "bounded_tail");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&line(&event(20, "canvas", "api_call", "")))
            .unwrap();
        let window = poll(&mut cache, &path, 10);
        assert_eq!(ids(&window.events), vec![16, 17, 18, 19, 20]);
        assert_eq!(
            cache.parsed_records, 1,
            "a full tail slide reuses overlap summaries, not JSON parsing"
        );
        // Move the cut one byte inside a record; only that partial record is omitted.
        let mut partial = super::EventWindowCache {
            maximum_bytes: 5 * size - 1,
            ..Default::default()
        };
        let window = poll(&mut partial, &path, 10);
        assert_eq!(ids(&window.events), vec![17, 18, 19, 20]);
        assert_eq!(window.coverage["scan_start"], (7 * size).to_string());
        assert_eq!(
            window.coverage["scan_end"],
            (bytes.len() + size).to_string()
        );
    }

    #[test]
    fn cache_invalidates_predecessor_rewrite_rotation_truncation_and_bad_tail() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let events: Vec<_> = (10..=19)
            .map(|n| event(n, "canvas", "api_call", ""))
            .collect();
        let mut bytes = write(&path, &events);
        let size = line(&events[0]).len();
        let mut cache = cache_with_budget(5 * size);
        assert_eq!(poll(&mut cache, &path, 10).events.len(), 5);
        // Change only the byte preceding an otherwise identical cached suffix.
        bytes[5 * size - 1] = b' ';
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            ids(&poll(&mut cache, &path, 10).events),
            vec![16, 17, 18, 19]
        );
        assert_eq!(cache.parsed_records, 4);
        write(&path, &events);
        let _ = poll(&mut cache, &path, 10);
        let previous_etag = etag(&path, "test");
        let old_time = fs::metadata(&path).unwrap().modified().unwrap();
        let mut rewritten = events.clone();
        rewritten[6]["sequence_number"] = json!("99");
        write(&path, &rewritten);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        assert_ne!(etag(&path, "test"), previous_etag);
        assert_eq!(
            ids(&poll(&mut cache, &path, 10).events),
            vec![15, 99, 17, 18, 19]
        );
        assert_eq!(cache.parsed_records, 5);
        let replacement = root.path().join("rotated");
        write(&replacement, &events);
        fs::rename(replacement, &path).unwrap();
        let _ = poll(&mut cache, &path, 10);
        assert_eq!(cache.parsed_records, 5);
        write(&path, &events[..1]);
        assert_eq!(ids(&poll(&mut cache, &path, 10).events), vec![10]);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"protocol_version\":")
            .unwrap();
        assert!(cache.read(&path, 10, validate_event).is_err());
        assert!(cache.snapshot.is_none());
        write(&path, &events[..2]);
        assert_eq!(poll(&mut cache, &path, 10).events.len(), 2);
        assert_eq!(cache.parsed_records, 2);
        fs::write(&path, b"[]\n").unwrap();
        assert!(cache.read(&path, 10, validate_event).is_err());
        cache.maximum_bytes = SCAN_BYTES;
        fs::write(&path, vec![b'x'; 4097]).unwrap();
        assert!(cache.read(&path, 10, validate_event).is_err());
    }

    #[test]
    fn complete_unterminated_record_is_reparsed_on_append_and_limits_are_honest() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let first = event(1, "webgl", "gap", "280");
        let second = event(2, "network", "request_failed", "");
        fs::write(&path, serde_json::to_vec(&first).unwrap()).unwrap();
        let mut cache = EventWindowCache::default();
        assert_eq!(poll(&mut cache, &path, 2).queue_drops, 280);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"\n").unwrap();
        file.write_all(&line(&second)).unwrap();
        let window = poll(&mut cache, &path, 1);
        assert_eq!(window.queue_drops, 280);
        assert_eq!(cache.parsed_records, 2);
        assert_eq!(ids(&window.network_events), vec![2]);
        assert_eq!(window.coverage["scope"], "store");
        cache.maximum_bytes = line(&second).len();
        let window = poll(&mut cache, &path, 1);
        assert_eq!(window.queue_drops, 0);
        assert_eq!(window.coverage["scope"], "bounded_tail");
        assert_eq!(window.coverage["events_limited"], false);
    }

    #[test]
    fn delayed_ack_ids_close_holes_without_resequencing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        for sequences in [vec![3, 1, 2], vec![1, 4, 2, 3], vec![3, 1, 2, 2]] {
            let events: Vec<_> = sequences
                .iter()
                .map(|&n| event(n, "canvas", "api_call", ""))
                .collect();
            write(&path, &events);
            let mut cache = EventWindowCache::default();
            let window = poll(&mut cache, &path, 10);
            assert_eq!(window.sequence_gaps, 0);
            assert_eq!(ids(&window.events), sequences);
        }
    }

    #[test]
    fn summary_stream_order_drop_parsing_and_saturation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let mut events: Vec<_> = [1, 3, 2, 5]
            .into_iter()
            .map(|n| event(n, "canvas", "api_call", ""))
            .collect();
        let mut other = event(900, "canvas", "api_call", "");
        other["process_id"] = json!(8);
        events.insert(2, other);
        events.push(event(6, "webgl", "gap", "18446744073709551615"));
        events.push(event(7, "webgl", "gap", "1"));
        write(&path, &events);
        let mut cache = EventWindowCache::default();
        let window = poll(&mut cache, &path, 1);
        assert_eq!(window.sequence_gaps, 1);
        assert_eq!(window.queue_drops, u64::MAX);
        assert!(window.queue_drops_saturated);
        for payload in [
            "",
            "0",
            "01",
            "-1",
            "+1",
            " 2",
            "2 ",
            "18446744073709551616",
        ] {
            write(&path, &[event(1, "webgl", "gap", payload)]);
            assert_eq!(poll(&mut cache, &path, 1).queue_drops, 1);
        }
        // A malformed old record cannot silently influence a trusted summary.
        events[0]["payload"] = json!("not-hex");
        write(&path, &events);
        assert!(cache.read(&path, 1, validate_event).is_err());
    }

    #[test]
    fn cached_and_fresh_windows_match_through_file_lifecycle_and_limit_changes() {
        fn compare(cache: &mut EventWindowCache, path: &Path, limit: usize) {
            let mut fresh = cache_with_budget(cache.maximum_bytes);
            assert_eq!(poll(cache, path, limit), poll(&mut fresh, path, limit));
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let events: Vec<_> = (10_000..15_205)
            .map(|n| {
                if n % 10 == 0 {
                    event(n, "network", "request_failed", "fixture.local")
                } else {
                    event(n, "canvas", "api_call", "draw")
                }
            })
            .collect();
        let mut bytes = write(&path, &events);
        let mut cache = cache_with_budget(bytes.len());
        for limit in [1, 5000, 7, 5000] {
            compare(&mut cache, &path, limit);
        }
        bytes.extend(
            serde_json::to_vec(&event(15_205, "network", "response_completed", "")).unwrap(),
        );
        fs::write(&path, &bytes).unwrap(); // Complete, unterminated tail and sliding start.
        compare(&mut cache, &path, 5000);
        bytes.push(b'\n');
        bytes.extend(line(&event(15_206, "network", "request_redirected", "")));
        fs::write(&path, &bytes).unwrap();
        for limit in [2, 5000, 100] {
            compare(&mut cache, &path, limit);
        }
        let saved = bytes.clone();
        bytes.extend_from_slice(b"{\"protocol_version\":");
        fs::write(&path, &bytes).unwrap();
        let mut fresh = cache_with_budget(cache.maximum_bytes);
        assert!(cache.read(&path, 5000, validate_event).is_err());
        assert!(fresh.read(&path, 5000, validate_event).is_err());
        fs::write(&path, &saved).unwrap();
        compare(&mut cache, &path, 5000);
        // Same-size valid rewrite, atomic replacement, truncation, disappearance,
        // and recreation must all match a reader with no prior cache authority.
        let mut rewritten = events.clone();
        rewritten[150]["sequence_number"] = json!("99999");
        write(&path, &rewritten);
        compare(&mut cache, &path, 5000);
        let replacement = root.path().join("replacement");
        write(&replacement, &events);
        fs::rename(replacement, &path).unwrap();
        compare(&mut cache, &path, 5000);
        write(&path, &events[..3]);
        compare(&mut cache, &path, 2);
        fs::remove_file(&path).unwrap();
        compare(&mut cache, &path, 5000);
        write(&path, &events);
        compare(&mut cache, &path, 5000);
    }

    #[test]
    #[ignore = "representative release-mode timing, run explicitly"]
    fn benchmark_cold_warm_append_and_full_slide() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        let record = line(&event(100_000, "canvas", "api_call", &"x".repeat(128)));
        let count = SCAN_BYTES / record.len() + 2;
        let mut bytes = Vec::with_capacity(count * record.len());
        for _ in 0..count {
            bytes.extend_from_slice(&record);
        }
        fs::write(
            &path,
            &bytes[..bytes.len() / 2 / record.len() * record.len()],
        )
        .unwrap();
        let mut cache = EventWindowCache::default();
        let _ = poll(&mut cache, &path, 5000);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record)
            .unwrap();
        let begin = Instant::now();
        let _ = poll(&mut cache, &path, 5000);
        let append_time = begin.elapsed();
        assert_eq!(cache.parsed_records, 1);
        fs::write(&path, &bytes).unwrap();
        let mut cache = EventWindowCache::default();
        let begin = Instant::now();
        let cold = poll(&mut cache, &path, 5000);
        let cold_time = begin.elapsed();
        assert_eq!(cold.coverage["scope"], "bounded_tail");
        let begin = Instant::now();
        let warm = poll(&mut cache, &path, 5000);
        let warm_time = begin.elapsed();
        assert_eq!(cache.parsed_records, 0);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record)
            .unwrap();
        let begin = Instant::now();
        let slide = poll(&mut cache, &path, 5000);
        let slide_time = begin.elapsed();
        assert_eq!(cache.parsed_records, 1);
        assert_eq!(cold.events, warm.events);
        assert_eq!(warm.events, slide.events);
        eprintln!(
            "64 MiB bounded event scan: cold={cold_time:?}, unchanged={warm_time:?}, 32 MiB warm append={append_time:?}, one-record full slide={slide_time:?}; records={count}"
        );
    }
}
