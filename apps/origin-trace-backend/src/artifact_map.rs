//! Whole-artifact map: one fixed-size entropy and kind summary per artifact.
//!
//! Memory is independent of artifact size. The file is read in 64 KiB chunks
//! and reduced to at most 128 by 128 cells of one byte each, so a 1 GiB module
//! costs the same as a 1 MiB one and no byte is left out to save memory. The
//! kind pass reuses facts the store already has: Wasm section framing and the
//! Inspect data rows, the existing JavaScript lexer, and the published VM byte
//! attributions. Nothing here executes the artifact or adds a format parser.
use crate::{
    error::{Code, Error, Result},
    evidence, validation,
    vm::js_lexer::{Kind as TokenKind, Lexer},
    wasm,
};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const VERSION: u32 = 1;
const MAX_SIDE: u64 = 128;
/// A window shorter than the 256 possible byte values cannot reach 8 bits per
/// byte: Shannon entropy over W bytes is at most log2(W), so a 4-byte window
/// tops out at 2 bits and a color scale reading 0 to 8 would mean nothing. A
/// short artifact gets a smaller grid rather than smaller windows.
pub const MIN_WINDOW_BYTES: u64 = 256;
/// Entropy cells are stored as whole 1/30ths of a bit, so 7.0 is an exact
/// level and the threshold test below matches what the legend states.
const UNITS_PER_BIT: f64 = 30.0;
const HIGH_ENTROPY_BITS: u8 = 7;
const HIGH_UNITS: u8 = HIGH_ENTROPY_BITS * 30;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const MAX_HIGHEST_RANGES: usize = 8;
const MAX_WASM_FRAMES: usize = 4096;
const WASM_HEADER_BYTES: u64 = 8;
/// Set on a kind cell when the window holds more than one kind.
const MIXED_FLAG: u8 = 0x80;
const DEADLINE: Duration = Duration::from_secs(60);
/// The VM opcode workspace the analyzer publishes into the artifact store.
const VM_WORKSPACE_DOCUMENT: &str = "analysis/vm-opcode-workspace-v2.json";
/// The analyzer attributes VM bytes only inside this retained preview.
const VM_ANALYZED_BYTES: u64 = 4096;

fn check(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(
            Error::new(499, "Artifact map request was cancelled").with_code(Code::Cancelled)
        );
    }
    if Instant::now() >= deadline {
        return Err(Error::new(408, "Artifact map exceeded its deadline").with_code(Code::Timeout));
    }
    Ok(())
}

/// Largest power-of-two side whose windows stay at or above the minimum, so
/// the grid always fills and never shows unexplained empty cells.
fn grid(byte_length: u64) -> (u64, u64) {
    if byte_length == 0 {
        return (0, 0);
    }
    let mut side = MAX_SIDE;
    while side > 1 && byte_length / (side * side) < MIN_WINDOW_BYTES {
        side /= 2;
    }
    (side, side * side)
}

/// The first byte of cell `index`. Cells differ in size by at most one byte.
fn boundary(index: u64, cells: u64, byte_length: u64) -> u64 {
    ((u128::from(index) * u128::from(byte_length)) / u128::from(cells)) as u64
}

fn open_blob(root: &Path, artifact: &Value) -> Result<(File, u64)> {
    let root = root.canonicalize()?;
    let path = root
        .join(
            artifact["content_path"]
                .as_str()
                .ok_or_else(|| Error::new(500, "Malformed artifact content path"))?,
        )
        .canonicalize()?;
    if !path.starts_with(&root) {
        return Err(Error::new(
            500,
            "Artifact content path escapes the artifact store",
        ));
    }
    let file = evidence::regular_file(&path)?;
    let expected = artifact["byte_size"]
        .as_u64()
        .ok_or_else(|| Error::new(500, "Artifact content byte size is invalid"))?;
    if file.metadata()?.len() != expected {
        return Err(Error::new(500, "Artifact content byte size is invalid"));
    }
    Ok((file, expected))
}

/// Shannon entropy of a histogram, in bits per byte.
fn shannon(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let length = total as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

struct Entropy {
    cells: Vec<u8>,
    mean_bits: f64,
    max_bits: f64,
}

/// Streams the whole blob once, hashing as it goes, so integrity is proven by
/// the same read that produced the map.
fn entropy_pass(
    file: &mut File,
    artifact: &Value,
    byte_length: u64,
    cell_count: u64,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Entropy> {
    let mut cells = vec![0u8; cell_count as usize];
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    let mut hash = Sha256::new();
    let mut counts = [0u64; 256];
    let mut position = 0u64;
    let mut cell = 0u64;
    let mut cell_end = if cell_count == 0 {
        0
    } else {
        boundary(1, cell_count, byte_length)
    };
    let mut sum_bits = 0.0f64;
    let mut max_bits = 0.0f64;
    loop {
        check(deadline, cancelled)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        let mut chunk = &buffer[..read];
        while !chunk.is_empty() {
            if position + chunk.len() as u64 > byte_length {
                return Err(Error::new(500, "Artifact changed while it was being read"));
            }
            let take = chunk.len().min((cell_end - position) as usize);
            for byte in &chunk[..take] {
                counts[*byte as usize] += 1;
            }
            position += take as u64;
            chunk = &chunk[take..];
            if position == cell_end && cell < cell_count {
                let start = boundary(cell, cell_count, byte_length);
                let window = cell_end - start;
                let bits = shannon(&counts, window);
                sum_bits += bits * window as f64;
                max_bits = max_bits.max(bits);
                cells[cell as usize] = (bits * UNITS_PER_BIT).floor().min(240.0) as u8;
                counts = [0; 256];
                cell += 1;
                if cell < cell_count {
                    cell_end = boundary(cell + 1, cell_count, byte_length);
                }
            }
        }
    }
    if position != byte_length
        || file.metadata()?.len() != byte_length
        || hex::encode(hash.finalize()) != artifact["sha256"].as_str().unwrap_or("")
    {
        return Err(Error::new(500, "Artifact content integrity is invalid"));
    }
    let mean_bits = if byte_length == 0 {
        0.0
    } else {
        sum_bits / byte_length as f64
    };
    Ok(Entropy {
        cells,
        mean_bits,
        max_bits,
    })
}

struct KindRow {
    id: String,
    label: String,
    group: &'static str,
}

/// Per-cell byte counts for each kind, fixed at `cells * kinds` integers.
struct KindCounts {
    counts: Vec<u32>,
    kinds: usize,
    cells: u64,
    byte_length: u64,
    default: u8,
}

impl KindCounts {
    fn new(kinds: usize, cells: u64, byte_length: u64, default: u8) -> Self {
        Self {
            counts: vec![0; kinds * cells as usize],
            kinds,
            cells,
            byte_length,
            default,
        }
    }

    fn add(&mut self, start: u64, end: u64, kind: u8) {
        let end = end.min(self.byte_length);
        if start >= end || self.cells == 0 {
            return;
        }
        let estimate = u128::from(start) * u128::from(self.cells) / u128::from(self.byte_length);
        let mut cell = (estimate as u64).min(self.cells - 1);
        while cell > 0 && boundary(cell, self.cells, self.byte_length) > start {
            cell -= 1;
        }
        while cell < self.cells {
            let cell_start = boundary(cell, self.cells, self.byte_length);
            if cell_start >= end {
                break;
            }
            let cell_end = boundary(cell + 1, self.cells, self.byte_length);
            let overlap = cell_end.min(end).saturating_sub(cell_start.max(start));
            if overlap > 0 {
                self.counts[cell as usize * self.kinds + kind as usize] += overlap as u32;
            }
            cell += 1;
        }
    }

    fn finish(self, kinds: Vec<KindRow>) -> (Vec<u8>, Vec<Value>) {
        let mut cells = vec![0u8; self.cells as usize];
        let mut bytes = vec![0u64; kinds.len()];
        let mut windows = vec![0u64; kinds.len()];
        for cell in 0..self.cells {
            let window = (boundary(cell + 1, self.cells, self.byte_length)
                - boundary(cell, self.cells, self.byte_length)) as u32;
            let row = &self.counts[cell as usize * self.kinds..(cell as usize + 1) * self.kinds];
            let known = row.iter().sum::<u32>();
            // Bytes no fact named belong to the default kind.
            let remainder = window.saturating_sub(known);
            let mut dominant = self.default;
            let mut most = 0;
            let mut distinct = 0;
            for (index, count) in row.iter().enumerate() {
                let effective = *count
                    + if index == self.default as usize {
                        remainder
                    } else {
                        0
                    };
                if effective > 0 {
                    distinct += 1;
                }
                if effective > most {
                    most = effective;
                    dominant = index as u8;
                }
            }
            cells[cell as usize] = dominant | if distinct > 1 { MIXED_FLAG } else { 0 };
            windows[dominant as usize] += 1;
            for (index, count) in row.iter().enumerate() {
                bytes[index] += u64::from(*count);
            }
            bytes[self.default as usize] += u64::from(window - known);
        }
        let table = kinds
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                json!({"id":row.id,"label":row.label,"group":row.group,
                "bytes":bytes[index],"windows":windows[index]})
            })
            .collect();
        (cells, table)
    }
}

struct Kinds {
    cells: Vec<u8>,
    table: Vec<Value>,
    facts: Value,
}

fn unclassified(byte_length: u64, cell_count: u64, reason: &str) -> Kinds {
    let table = vec![KindRow {
        id: "unclassified".into(),
        label: "no recorded fact".into(),
        group: "unknown",
    }];
    let (cells, table) = KindCounts::new(1, cell_count, byte_length, 0).finish(table);
    Kinds {
        cells,
        table,
        facts: json!({"source":"none","complete":false,"notes":[reason]}),
    }
}

const WASM_DATA_KIND: u8 = 15;
const WASM_TAIL_KIND: u8 = 16;

fn wasm_kind_table() -> Vec<KindRow> {
    let mut rows = vec![KindRow {
        id: "wasm_header".into(),
        label: "module header".into(),
        group: "structure",
    }];
    for id in 0..14u8 {
        let name = wasm::section_name(id);
        rows.push(KindRow {
            id: format!("section_{name}"),
            label: format!("{name} section"),
            group: match name {
                "code" => "code",
                "data" => "data",
                "custom" => "custom",
                _ => "structure",
            },
        });
    }
    rows.push(KindRow {
        id: "data_segment".into(),
        label: "data segment".into(),
        group: "data",
    });
    rows.push(KindRow {
        id: "undecoded_tail".into(),
        label: "undecoded tail".into(),
        group: "undecoded",
    });
    rows
}

struct Frame {
    start: u64,
    end: u64,
    id: u8,
}

/// Reads only each section's id and size, then seeks over its payload, so the
/// walk costs one small header per section however large the module is.
fn wasm_frames(
    file: &mut File,
    byte_length: u64,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(Vec<Frame>, u64, Option<String>)> {
    let mut header = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    if byte_length < WASM_HEADER_BYTES || file.read_exact(&mut header).is_err() {
        return Ok((Vec::new(), 0, Some("Module header is incomplete.".into())));
    }
    if &header[..4] != b"\0asm" {
        return Ok((Vec::new(), 0, Some("Module header is not \\0asm.".into())));
    }
    let mut frames = Vec::new();
    let mut position = WASM_HEADER_BYTES;
    while position < byte_length {
        check(deadline, cancelled)?;
        if frames.len() >= MAX_WASM_FRAMES {
            return Ok((
                frames,
                position,
                Some(format!(
                    "Stopped after {MAX_WASM_FRAMES} sections; the rest is the undecoded tail."
                )),
            ));
        }
        let mut raw = [0u8; 6];
        file.seek(SeekFrom::Start(position))?;
        let available = (byte_length - position).min(raw.len() as u64) as usize;
        file.read_exact(&mut raw[..available])?;
        // The pinned wasmparser reader decodes the framing integers.
        let mut reader = wasmparser::BinaryReader::new(&raw[..available], 0);
        let frame = reader.read_u8().and_then(|id| {
            let size = reader.read_var_u32()?;
            Ok((id, u64::from(size), reader.original_position() as u64))
        });
        let (id, size, header_bytes) = match frame {
            Ok(frame) => frame,
            Err(_) => {
                return Ok((
                    frames,
                    position,
                    Some(format!("Section framing stopped at byte {position}.")),
                ));
            }
        };
        let end = position + header_bytes + size;
        if id > 13 || end > byte_length {
            return Ok((
                frames,
                position,
                Some(format!("Section framing stopped at byte {position}.")),
            ));
        }
        frames.push(Frame {
            start: position,
            end,
            id,
        });
        position = end;
    }
    Ok((frames, position, None))
}

fn wasm_kinds(
    root: &Path,
    artifact: &Value,
    file: &mut File,
    byte_length: u64,
    cell_count: u64,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Kinds> {
    let table = wasm_kind_table();
    let mut counts = KindCounts::new(table.len(), cell_count, byte_length, WASM_TAIL_KIND);
    let (frames, decoded_end, stopped) = wasm_frames(file, byte_length, deadline, cancelled)?;
    let mut notes = Vec::new();
    if decoded_end > 0 {
        counts.add(0, WASM_HEADER_BYTES, 0);
    }
    let mut segments = Vec::<(u64, u64)>::new();
    let has_data = frames.iter().any(|frame| frame.id == 11);
    if has_data && byte_length <= wasm::MAX_BYTES as u64 {
        // Inspect is the existing decoder for segment boundaries; its 2 MiB
        // input bound is why larger modules keep the data section as one kind.
        let bytes = evidence::content(root, artifact, wasm::MAX_BYTES)?;
        let inspected = wasm::inspect(&bytes, Some(&BTreeSet::from([11u8])));
        match inspected {
            Ok(report) => {
                segments = report["rows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|row| row["kind"] == "data")
                    .filter_map(|row| row["byte_offset"].as_u64().zip(row["byte_end"].as_u64()))
                    .collect();
                // A filtered document is always partial, so read the data section's
                // own coverage instead of the overall status.
                let analyzed = report["coverage"]["analyzed_sections"].as_array();
                if !analyzed.is_some_and(|names| names.iter().any(|name| name == "data")) {
                    notes.push(
                        "Inspect stopped before every data segment was listed; the remaining bytes keep the data section kind.".to_owned(),
                    );
                }
            }
            Err(_) => {
                notes.push("Inspect could not list data segments for this module.".to_owned());
            }
        }
    } else if has_data {
        notes.push(format!(
            "Data segments are listed for modules of at most {} MiB, the Inspect input bound; the data section is shown as one kind.",
            wasm::MAX_BYTES / (1024 * 1024)
        ));
    }
    let mut segment_rows = 0;
    for frame in &frames {
        let kind = 1 + frame.id;
        if u32::from(frame.id) == 11 {
            let mut cursor = frame.start;
            for &(start, end) in &segments {
                if start < cursor || end > frame.end || start >= end {
                    continue;
                }
                counts.add(cursor, start, kind);
                counts.add(start, end, WASM_DATA_KIND);
                cursor = end;
                segment_rows += 1;
            }
            counts.add(cursor, frame.end, kind);
        } else {
            counts.add(frame.start, frame.end, kind);
        }
    }
    if decoded_end < byte_length {
        notes.push(stopped.unwrap_or_else(|| "Bytes after the last section are undecoded.".into()));
    } else if let Some(stopped) = stopped {
        notes.push(stopped);
    }
    let (cells, kinds) = counts.finish(table);
    Ok(Kinds {
        cells,
        table: kinds,
        facts: json!({"source":"wasm_section_frames",
            "complete":decoded_end >= byte_length,"sections":frames.len(),
            "data_segments":segment_rows,"notes":notes}),
    })
}

fn script_kinds(
    root: &Path,
    artifact: &Value,
    byte_length: u64,
    cell_count: u64,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Kinds> {
    let table = vec![
        KindRow {
            id: "script_text".into(),
            label: "script text".into(),
            group: "code",
        },
        KindRow {
            id: "string".into(),
            label: "string".into(),
            group: "string",
        },
    ];
    let limit = crate::source_facts::MAX_SOURCE_BYTES as u64;
    if byte_length > limit {
        return Ok(unclassified(
            byte_length,
            cell_count,
            &format!(
                "String literals are identified in scripts of at most {} MiB, the JavaScript facts bound.",
                limit / (1024 * 1024)
            ),
        ));
    }
    let bytes = evidence::content(root, artifact, limit as usize)?;
    let Ok(source) = String::from_utf8(bytes) else {
        return Ok(unclassified(
            byte_length,
            cell_count,
            "This artifact is not valid UTF-8 JavaScript.",
        ));
    };
    let mut counts = KindCounts::new(table.len(), cell_count, byte_length, 0);
    let mut literals = 0u64;
    let mut string_bytes = 0u64;
    for (index, token) in Lexer::new(&source).enumerate() {
        if matches!(token.kind, TokenKind::String | TokenKind::TemplateText) {
            counts.add(token.start as u64, token.end as u64, 1);
            literals += 1;
            string_bytes += (token.end - token.start) as u64;
        }
        if index.is_multiple_of(65536) {
            check(deadline, cancelled)?;
        }
    }
    let (cells, kinds) = counts.finish(table);
    Ok(Kinds {
        cells,
        table: kinds,
        facts: json!({"source":"javascript_lexer","complete":true,
            "string_literals":literals,"string_bytes":string_bytes,"notes":[]}),
    })
}

#[derive(Deserialize)]
struct VmDocument {
    workspaces: Vec<VmWorkspace>,
}
#[derive(Deserialize)]
struct VmWorkspace {
    #[serde(default)]
    snapshots: Vec<VmSnapshot>,
    #[serde(default)]
    coverage: VmCoverage,
}
#[derive(Deserialize)]
struct VmSnapshot {
    artifact_id: String,
    byte_count: u64,
}
#[derive(Deserialize, Default)]
struct VmCoverage {
    #[serde(default)]
    attributions: Vec<VmAttribution>,
}
#[derive(Deserialize)]
struct VmAttribution {
    artifact_id: String,
    byte_offset: u64,
    byte_size: u64,
}

fn vm_kinds(root: &Path, artifact: &Value, byte_length: u64, cell_count: u64) -> Kinds {
    let unavailable = |reason: &str| unclassified(byte_length, cell_count, reason);
    let path = root.join(VM_WORKSPACE_DOCUMENT);
    let Ok(file) = evidence::regular_file(&path) else {
        return unavailable("VM analysis has not been published for this store.");
    };
    // Typed fields keep only the attribution rows; other workspace fields are
    // skipped by the reader instead of being materialized.
    let Ok(document) = serde_json::from_reader::<_, VmDocument>(BufReader::new(file)) else {
        return unavailable("The published VM analysis could not be read.");
    };
    let id = artifact["artifact_id"].as_str().unwrap_or("");
    let analyzed = document
        .workspaces
        .iter()
        .flat_map(|workspace| &workspace.snapshots)
        .filter(|snapshot| snapshot.artifact_id == id)
        .map(|snapshot| snapshot.byte_count)
        .max()
        .map(|bytes| bytes.min(VM_ANALYZED_BYTES).min(byte_length));
    let Some(analyzed) = analyzed else {
        return unavailable("No VM analysis names this bytecode image.");
    };
    let table = vec![
        KindRow {
            id: "vm_instruction".into(),
            label: "VM instruction coverage".into(),
            group: "code",
        },
        KindRow {
            id: "vm_uncharacterized".into(),
            label: "uncharacterized bytecode".into(),
            group: "undecoded",
        },
        KindRow {
            id: "undecoded_tail".into(),
            label: "undecoded tail".into(),
            group: "undecoded",
        },
    ];
    let mut covered = vec![false; analyzed as usize];
    for attribution in document
        .workspaces
        .iter()
        .flat_map(|workspace| &workspace.coverage.attributions)
        .filter(|row| row.artifact_id == id)
    {
        let end = attribution
            .byte_offset
            .saturating_add(attribution.byte_size)
            .min(analyzed) as usize;
        if let Some(cells) = covered.get_mut((attribution.byte_offset.min(analyzed)) as usize..end)
        {
            cells.fill(true);
        }
    }
    let mut counts = KindCounts::new(table.len(), cell_count, byte_length, 2);
    let mut start = 0usize;
    let mut characterized = 0u64;
    while start < covered.len() {
        let value = covered[start];
        let end = covered[start..]
            .iter()
            .position(|flag| *flag != value)
            .map_or(covered.len(), |run| start + run);
        counts.add(start as u64, end as u64, if value { 0 } else { 1 });
        if value {
            characterized += (end - start) as u64;
        }
        start = end;
    }
    let mut notes = Vec::new();
    if analyzed < byte_length {
        notes.push(format!(
            "VM analysis attributes bytes only in the first {analyzed} bytes it retains; the rest is the undecoded tail."
        ));
    }
    let (cells, kinds) = counts.finish(table);
    Kinds {
        cells,
        table: kinds,
        facts: json!({"source":"vm_byte_coverage","complete":analyzed >= byte_length && characterized >= analyzed,
            "analyzed_bytes":analyzed,"characterized_bytes":characterized,"notes":notes}),
    }
}

struct Range {
    start_cell: u64,
    end_cell: u64,
    peak: u8,
    high: bool,
}

/// Highest-entropy ranges: adjacent high windows merged. An artifact with none
/// lists its highest single windows instead.
fn highest_ranges(cells: &[u8]) -> Vec<Range> {
    let mut ranges: Vec<Range> = Vec::new();
    let mut index = 0usize;
    while index < cells.len() {
        if cells[index] < HIGH_UNITS {
            index += 1;
            continue;
        }
        let start = index;
        let mut peak = 0;
        while index < cells.len() && cells[index] >= HIGH_UNITS {
            peak = peak.max(cells[index]);
            index += 1;
        }
        insert_ranked(
            &mut ranges,
            Range {
                start_cell: start as u64,
                end_cell: index as u64,
                peak,
                high: true,
            },
        );
    }
    if ranges.is_empty() {
        // Nothing crossed the threshold; list the highest windows instead so
        // the summary still points somewhere. Filling alongside high ranges
        // would only add low-entropy noise.
        let mut order: Vec<usize> = (0..cells.len()).collect();
        order.sort_unstable_by_key(|index| std::cmp::Reverse(cells[*index]));
        for index in order.into_iter().take(MAX_HIGHEST_RANGES) {
            ranges.push(Range {
                start_cell: index as u64,
                end_cell: index as u64 + 1,
                peak: cells[index],
                high: false,
            });
        }
    }
    ranges
}

fn insert_ranked(ranges: &mut Vec<Range>, range: Range) {
    let span = |value: &Range| value.end_cell - value.start_cell;
    let position = ranges
        .iter()
        .position(|other| (range.peak, span(&range)) > (other.peak, span(other)))
        .unwrap_or(ranges.len());
    if position < MAX_HIGHEST_RANGES {
        ranges.insert(position, range);
        ranges.truncate(MAX_HIGHEST_RANGES);
    }
}

fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Builds the versioned map document for one validated artifact record.
///
/// Refuses the kinds Sources refuses, so a request body or Canvas image keeps
/// its existing boundary even for an entropy-only summary.
pub fn build(root: &Path, artifact: &Value, cancelled: &AtomicBool) -> Result<Value> {
    let kind = artifact["kind"].as_str().unwrap_or("");
    if matches!(kind, "request_body" | "canvas_data_url") {
        return Err(Error::bad(
            "Request bodies and Canvas images are not mapped in Sources",
        ));
    }
    let deadline = Instant::now() + DEADLINE;
    let (mut file, byte_length) = open_blob(root, artifact)?;
    let (side, cell_count) = grid(byte_length);
    let entropy = entropy_pass(
        &mut file,
        artifact,
        byte_length,
        cell_count,
        deadline,
        cancelled,
    )?;
    let kinds = match kind {
        _ if cell_count == 0 => unclassified(0, 0, "This artifact has no bytes."),
        "wasm" => wasm_kinds(
            root,
            artifact,
            &mut file,
            byte_length,
            cell_count,
            deadline,
            cancelled,
        )?,
        "javascript" => script_kinds(root, artifact, byte_length, cell_count, deadline, cancelled)?,
        "bytecode_buffer" => vm_kinds(root, artifact, byte_length, cell_count),
        _ => unclassified(
            byte_length,
            cell_count,
            "The store records no byte-level facts for this artifact kind.",
        ),
    };
    let high_windows = entropy
        .cells
        .iter()
        .filter(|cell| **cell >= HIGH_UNITS)
        .count();
    let high_bytes = entropy
        .cells
        .iter()
        .enumerate()
        .filter(|(_, cell)| **cell >= HIGH_UNITS)
        .map(|(index, _)| {
            boundary(index as u64 + 1, cell_count, byte_length)
                - boundary(index as u64, cell_count, byte_length)
        })
        .sum::<u64>();
    let ranges = highest_ranges(&entropy.cells)
        .iter()
        .map(|range| {
            json!({
                "start": boundary(range.start_cell, cell_count, byte_length),
                "end": boundary(range.end_cell, cell_count, byte_length),
                "peak_bits": round(f64::from(range.peak) / UNITS_PER_BIT),
                "high": range.high,
            })
        })
        .collect::<Vec<_>>();
    let encoded = base64::engine::general_purpose::STANDARD;
    Ok(json!({
        "version": VERSION,
        "schema": "artifact-map-v1",
        "artifact_id": artifact["artifact_id"],
        "session_id": artifact["session_id"],
        "sha256": artifact["sha256"],
        "artifact_kind": kind,
        "byte_length": byte_length,
        "integrity": "verified",
        "grid": {
            "order": "hilbert",
            "side": side,
            "cell_count": cell_count,
            "window_bytes": byte_length.checked_div(cell_count).unwrap_or(0),
            "min_window_bytes": MIN_WINDOW_BYTES,
            "below_min_window": byte_length > 0 && byte_length < MIN_WINDOW_BYTES,
        },
        "entropy": {
            "encoding": "base64",
            "units_per_bit": UNITS_PER_BIT as u64,
            "cells": encoded.encode(&entropy.cells),
            "mean_bits": round(entropy.mean_bits),
            "max_bits": round(entropy.max_bits),
        },
        "high_entropy": {
            "threshold_bits": f64::from(HIGH_ENTROPY_BITS),
            "threshold_units": HIGH_UNITS,
            "windows": high_windows,
            "bytes": high_bytes,
        },
        "kind_map": {
            "encoding": "base64",
            "mixed_flag": MIXED_FLAG,
            "cells": encoded.encode(&kinds.cells),
            "kinds": kinds.table,
        },
        "facts": kinds.facts,
        "highest_ranges": ranges,
    }))
}

/// Native helper entry point: resolves the artifact record, then builds.
pub fn load(root: &Path, id: &str) -> Result<Value> {
    validation::canonical(&json!(id), 64, true, "Artifact ID")?;
    let artifact = evidence::find_artifact(root, id)?;
    build(root, &artifact, &AtomicBool::new(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn artifact(root: &Path, id: &str, kind: &str, bytes: &[u8]) -> Value {
        let hash = hex::encode(Sha256::digest(bytes));
        let path = root.join("blobs").join(format!("{hash}.bin"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        json!({"artifact_id":id,"session_id":"1","kind":kind,"sha256":hash,"byte_size":bytes.len(),
            "content_path":format!("blobs/{hash}.bin")})
    }

    fn run(root: &Path, artifact: &Value) -> Result<Value> {
        build(root, artifact, &AtomicBool::new(false))
    }

    fn decode(value: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.as_str().unwrap())
            .unwrap()
    }

    /// A deterministic noise source; Rust's std has no seeded generator.
    fn noise(length: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn grid_prefers_a_full_grid_and_never_shrinks_windows_below_the_minimum() {
        assert_eq!(grid(0), (0, 0));
        assert_eq!(grid(1), (1, 1));
        assert_eq!(grid(255), (1, 1));
        assert_eq!(grid(256), (1, 1));
        assert_eq!(grid(1023), (1, 1));
        assert_eq!(grid(1024), (2, 4));
        assert_eq!(grid(1 << 20), (64, 4096));
        assert_eq!(grid((1 << 20) + 1), (64, 4096));
        assert_eq!(grid(4 << 20), (128, 16384));
        for length in [256u64, 4096, 65536, 123_456, 1 << 20, 1 << 30] {
            let (side, cells) = grid(length);
            assert_eq!(cells, side * side);
            assert!(length / cells >= MIN_WINDOW_BYTES, "{length}");
            assert_eq!(boundary(0, cells, length), 0);
            assert_eq!(boundary(cells, cells, length), length);
        }
    }

    #[test]
    fn four_byte_windows_cannot_exceed_two_bits_so_the_scale_requires_the_minimum() {
        let mut counts = [0u64; 256];
        for byte in 0..4u8 {
            counts[byte as usize] += 1;
        }
        assert_eq!(shannon(&counts, 4), 2.0);
        let mut uniform = [0u64; 256];
        uniform.fill(1);
        assert_eq!(shannon(&uniform, 256), 8.0);
        assert_eq!(shannon(&[0; 256], 0), 0.0);
    }

    #[test]
    fn the_whole_artifact_is_covered_and_noise_is_marked_against_the_stated_threshold() {
        let root = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8; 8192];
        bytes.extend(noise(8192));
        let record = artifact(root.path(), "1", "other", &bytes);
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["version"], 1);
        assert_eq!(report["byte_length"], 16384);
        assert_eq!(report["grid"]["side"], 8);
        assert_eq!(report["grid"]["cell_count"], 64);
        assert_eq!(report["grid"]["window_bytes"], 256);
        let cells = decode(&report["entropy"]["cells"]);
        assert_eq!(cells.len(), 64);
        assert!(cells[..32].iter().all(|cell| *cell == 0));
        assert!(cells[32..].iter().all(|cell| *cell >= HIGH_UNITS));
        assert_eq!(report["high_entropy"]["threshold_bits"], 7.0);
        assert_eq!(report["high_entropy"]["windows"], 32);
        assert_eq!(report["high_entropy"]["bytes"], 8192);
        // Exact mean over the whole artifact is the bytes-weighted average.
        let mean = report["entropy"]["mean_bits"].as_f64().unwrap();
        assert!((3.5..4.0).contains(&mean), "{mean}");
        let ranges = report["highest_ranges"].as_array().unwrap();
        assert_eq!(ranges[0]["start"], 8192);
        assert_eq!(ranges[0]["end"], 16384);
        assert_eq!(ranges[0]["high"], true);
        assert_eq!(ranges.len(), 1, "no low-entropy filler beside a high range");
        assert_eq!(report["facts"]["source"], "none");
    }

    #[test]
    fn an_artifact_with_nothing_high_still_lists_its_highest_windows() {
        let root = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0..8192usize).map(|index| (index % 16) as u8).collect();
        let record = artifact(root.path(), "1", "other", &bytes);
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["high_entropy"]["windows"], 0);
        let ranges = report["highest_ranges"].as_array().unwrap();
        assert_eq!(ranges.len(), MAX_HIGHEST_RANGES);
        assert!(ranges.iter().all(|range| range["high"] == false));
    }

    #[test]
    fn short_artifact_is_one_cell_never_marked_and_says_it_is_below_the_minimum() {
        let root = tempfile::tempdir().unwrap();
        let record = artifact(root.path(), "1", "other", &noise(64));
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["grid"]["side"], 1);
        assert_eq!(report["grid"]["below_min_window"], true);
        assert_eq!(report["high_entropy"]["windows"], 0);
    }

    #[test]
    fn empty_artifact_has_no_cells_and_refused_kinds_stay_refused() {
        let root = tempfile::tempdir().unwrap();
        let record = artifact(root.path(), "1", "other", b"");
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["grid"]["cell_count"], 0);
        assert_eq!(report["entropy"]["cells"], "");
        let body = artifact(root.path(), "2", "request_body", b"secret");
        assert_eq!(run(root.path(), &body).unwrap_err().status, 400);
    }

    #[test]
    fn hash_mismatch_and_size_mismatch_are_errors_not_partial_maps() {
        let root = tempfile::tempdir().unwrap();
        let mut record = artifact(root.path(), "1", "other", b"contents");
        record["sha256"] = json!("0".repeat(64));
        assert_eq!(run(root.path(), &record).unwrap_err().status, 500);
        let mut record = artifact(root.path(), "2", "other", b"contents");
        record["byte_size"] = json!(9);
        assert_eq!(run(root.path(), &record).unwrap_err().status, 500);
    }

    #[test]
    fn cancelled_read_stops_without_a_document() {
        let root = tempfile::tempdir().unwrap();
        let record = artifact(root.path(), "1", "other", &noise(4096));
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            build(root.path(), &record, &cancelled).unwrap_err().status,
            499
        );
    }

    fn wasm_module(data_payload: usize) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        // type section with one nullary function type.
        bytes.extend([1, 4, 1, 0x60, 0, 0]);
        // custom section named x.
        bytes.extend([0, 2, 1, b'x']);
        let mut segment = vec![0, 0x41, 0, 0x0b];
        let mut size = data_payload;
        loop {
            let byte = (size & 0x7f) as u8;
            size >>= 7;
            segment.push(if size > 0 { byte | 0x80 } else { byte });
            if size == 0 {
                break;
            }
        }
        segment.extend(vec![0x41; data_payload]);
        // data section holding that one active segment.
        let mut body = vec![1];
        body.extend(segment);
        let mut length = Vec::new();
        let mut value = body.len();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            length.push(if value > 0 { byte | 0x80 } else { byte });
            if value == 0 {
                break;
            }
        }
        bytes.push(11);
        bytes.extend(length);
        bytes.extend(body);
        bytes
    }

    #[test]
    fn wasm_kinds_report_sections_segments_and_an_undecoded_tail() {
        let root = tempfile::tempdir().unwrap();
        let mut bytes = wasm_module(8000);
        let record = artifact(root.path(), "1", "wasm", &bytes);
        let report = run(root.path(), &record).unwrap();
        let cells = decode(&report["kind_map"]["cells"]);
        let kinds = report["kind_map"]["kinds"].as_array().unwrap();
        assert_eq!(report["facts"]["sections"], 3);
        assert_eq!(report["facts"]["data_segments"], 1);
        assert_eq!(report["facts"]["complete"], true);
        let table_row = |id: &str| kinds.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(table_row("wasm_header")["bytes"], WASM_HEADER_BYTES);
        assert_eq!(table_row("section_type")["bytes"], 6);
        assert_eq!(table_row("section_custom")["bytes"], 4);
        // The first window mixes the header, small sections and the segment.
        assert_eq!(
            kinds[(cells[0] & !MIXED_FLAG) as usize]["id"],
            "data_segment"
        );
        assert_eq!(cells[0] & MIXED_FLAG, MIXED_FLAG);
        assert_eq!(
            kinds[(*cells.last().unwrap() & !MIXED_FLAG) as usize]["id"],
            "data_segment"
        );
        assert_eq!(*cells.last().unwrap() & MIXED_FLAG, 0);

        bytes.extend([0xff; 1024]);
        let record = artifact(root.path(), "2", "wasm", &bytes);
        let report = run(root.path(), &record).unwrap();
        let cells = decode(&report["kind_map"]["cells"]);
        let kinds = report["kind_map"]["kinds"].as_array().unwrap();
        assert_eq!(report["facts"]["complete"], false);
        assert_eq!(
            kinds[(*cells.last().unwrap() & !MIXED_FLAG) as usize]["id"],
            "undecoded_tail"
        );
        let notes = report["facts"]["notes"].as_array().unwrap();
        assert!(
            notes
                .iter()
                .any(|note| note.as_str().unwrap().contains("framing stopped"))
        );

        let record = artifact(root.path(), "3", "wasm", &[0x7f; 4096]);
        let report = run(root.path(), &record).unwrap();
        let cells = decode(&report["kind_map"]["cells"]);
        let kinds = report["kind_map"]["kinds"].as_array().unwrap();
        assert_eq!(report["facts"]["sections"], 0);
        assert_eq!(
            kinds[(cells[0] & !MIXED_FLAG) as usize]["id"],
            "undecoded_tail"
        );
    }

    #[test]
    fn large_module_keeps_framing_and_says_data_segments_are_not_split() {
        let root = tempfile::tempdir().unwrap();
        let bytes = wasm_module(wasm::MAX_BYTES + 1024);
        let record = artifact(root.path(), "1", "wasm", &bytes);
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["facts"]["complete"], true);
        assert_eq!(report["facts"]["data_segments"], 0);
        assert!(
            report["facts"]["notes"][0]
                .as_str()
                .unwrap()
                .contains("Data segments are listed for modules")
        );
    }

    #[test]
    fn javascript_strings_are_counted_and_oversized_scripts_say_why_they_are_unclassified() {
        let root = tempfile::tempdir().unwrap();
        let source = format!("var a = \"{}\";\nvar b = 1;\n", "x".repeat(4096));
        let record = artifact(root.path(), "1", "javascript", source.as_bytes());
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["facts"]["string_literals"], 1);
        let cells = decode(&report["kind_map"]["cells"]);
        let kinds = report["kind_map"]["kinds"].as_array().unwrap();
        assert!(
            cells
                .iter()
                .any(|cell| kinds[(cell & !MIXED_FLAG) as usize]["id"] == "string")
        );
        let large = vec![b'x'; crate::source_facts::MAX_SOURCE_BYTES + 1];
        let record = artifact(root.path(), "2", "javascript", &large);
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["facts"]["source"], "none");
        assert!(
            report["facts"]["notes"][0]
                .as_str()
                .unwrap()
                .contains("at most 4 MiB")
        );
    }

    #[test]
    fn vm_coverage_uses_published_attributions_and_names_the_tail() {
        let root = tempfile::tempdir().unwrap();
        let bytes = noise(8192);
        let record = artifact(root.path(), "9", "bytecode_buffer", &bytes);
        let missing = run(root.path(), &record).unwrap();
        assert_eq!(missing["facts"]["source"], "none");
        std::fs::create_dir_all(root.path().join("analysis")).unwrap();
        let mut document = std::fs::File::create(root.path().join(VM_WORKSPACE_DOCUMENT)).unwrap();
        write!(
            document,
            "{}",
            json!({"workspaces":[{"snapshots":[{"artifact_id":"9","byte_count":4096}],
                "coverage":{"attributions":[{"artifact_id":"9","byte_offset":0,"byte_size":2048,"opcode":1,"kind":"opcode","evidence_class":"observed"},
                    {"artifact_id":"8","byte_offset":0,"byte_size":512,"opcode":1,"kind":"opcode","evidence_class":"observed"}]}}]})
        )
        .unwrap();
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["facts"]["source"], "vm_byte_coverage");
        assert_eq!(report["facts"]["analyzed_bytes"], 4096);
        assert_eq!(report["facts"]["characterized_bytes"], 2048);
        let cells = decode(&report["kind_map"]["cells"]);
        let kinds = report["kind_map"]["kinds"].as_array().unwrap();
        assert_eq!(
            kinds[(cells[0] & !MIXED_FLAG) as usize]["id"],
            "vm_instruction"
        );
        // 8192 bytes make 16 windows of 512 bytes: 2048 characterized, 2048
        // analyzed but uncharacterized, and the rest past the retained preview.
        assert_eq!(
            kinds[(cells[4] & !MIXED_FLAG) as usize]["id"],
            "vm_uncharacterized"
        );
        assert_eq!(
            kinds[(cells[8] & !MIXED_FLAG) as usize]["id"],
            "undecoded_tail"
        );
    }

    /// Generates a 128 MiB module at test time, proving a fixed-size summary
    /// and bounded response. Ignored by default because a debug build is slow;
    /// run with `--ignored` or measure the release helper.
    #[test]
    #[ignore = "slow in a debug build; run with --ignored"]
    fn synthetic_hundred_megabyte_artifact_stays_fixed_size() {
        let root = tempfile::tempdir().unwrap();
        let length = 128 * 1024 * 1024usize;
        let hash = {
            let mut hasher = Sha256::new();
            let path = root.path().join("blob");
            let mut file = std::io::BufWriter::new(File::create(&path).unwrap());
            let block = noise(64 * 1024);
            for chunk in 0..length / block.len() {
                let mut piece = block.clone();
                piece[0] = chunk as u8;
                hasher.update(&piece);
                file.write_all(&piece).unwrap();
            }
            hex::encode(hasher.finalize())
        };
        let blobs = root.path().join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::rename(root.path().join("blob"), blobs.join(format!("{hash}.bin"))).unwrap();
        let record = json!({"artifact_id":"1","session_id":"1","kind":"bytecode_buffer","sha256":hash,
            "byte_size":length,"content_path":format!("blobs/{hash}.bin")});
        let report = run(root.path(), &record).unwrap();
        assert_eq!(report["grid"]["cell_count"], 16384);
        assert_eq!(decode(&report["entropy"]["cells"]).len(), 16384);
        assert_eq!(decode(&report["kind_map"]["cells"]).len(), 16384);
        assert!(serde_json::to_vec(&report).unwrap().len() < 64 * 1024);
    }
}
