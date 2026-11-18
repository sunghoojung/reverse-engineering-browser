//! Verified immutable-source adapter. Worker-local IDs never identify another artifact.
//!
//! A whole bundle yields about a hundred thousand facts per megabyte, so a
//! report is admitted one row at a time, kept as the worker's own JSON text and
//! served in pages. Reports are cached by source SHA-256 and requested region:
//! the same bytes always produce the same IDs, so an evicted report is rebuilt
//! with identical rows.
use crate::{
    app::CancelOnDrop,
    deobfuscation::Deobfuscator,
    error::{Code, Error, Result},
    evidence, validation,
};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::{HashSet, VecDeque},
    ops::Range,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub const SCHEMA: &str = "reb-javascript-source-facts-v2";
pub const ROWS_SCHEMA: &str = "reb-javascript-source-fact-rows-v2";
/// Row tables in response order, with the contract that admits each row.
pub const TABLES: [(&str, &str); 6] = [
    ("scopes", "JavaScriptSourceScope"),
    ("bindings", "JavaScriptSourceBinding"),
    ("callables", "JavaScriptSourceCallable"),
    ("regions", "JavaScriptSourceRegion"),
    ("operations", "JavaScriptSourceOperation"),
    ("frontiers", "JavaScriptSourceFrontier"),
];
const SCOPES: usize = 0;
const BINDINGS: usize = 1;
const CALLABLES: usize = 2;
const REGIONS: usize = 3;
const OPERATIONS: usize = 4;
/// Operation kinds whose admitted target can name declarations.
const REFERENCES: [&str; 5] = ["reference", "read", "write", "call", "construct"];
pub const PAGE_ROWS: usize = 1000;
const CACHE_ENTRIES: usize = 4;

pub fn load(root: &Path, session: &str, id: &str) -> Result<(String, Value)> {
    let artifact = evidence::find_artifact(root, id)?;
    if artifact["session_id"] != session {
        return Err(Error::new(
            404,
            "Artifact not found in the requested session",
        ));
    }
    if artifact["kind"] != "javascript" {
        return Err(Error::bad("Artifact is not JavaScript"));
    }
    // Read and hash the entire immutable blob before interpreting even one byte.
    let bytes = evidence::read(root, &artifact)?;
    let source = String::from_utf8(bytes)
        .map_err(|_| Error::bad("Artifact is not valid UTF-8 JavaScript"))?;
    Ok((source, evidence::public_artifact(&artifact)))
}

fn invalid() -> Error {
    // Do not forward worker diagnostics or schema errors containing source values.
    Error::new(
        502,
        "JavaScript source facts worker returned an invalid response",
    )
}

fn valid_range(source: &str, value: &Value) -> bool {
    let start = value["start"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());
    let end = value["end"].as_u64().and_then(|n| usize::try_from(n).ok());
    matches!((start, end), (Some(start), Some(end)) if start <= end
        && end <= source.len() && source.is_char_boundary(start)
        && source.is_char_boundary(end))
}

fn valid_ranges(source: &str, value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "range" || key.ends_with("_range") {
                // Optional expression ranges (for example `return;`) are null.
                // Required top-level ranges are already checked by the schema.
                value.is_null() || valid_range(source, value)
            } else if key.ends_with("_ranges") {
                value
                    .as_array()
                    .is_some_and(|items| items.iter().all(|v| valid_range(source, v)))
            } else {
                valid_ranges(source, value)
            }
        }),
        Value::Array(items) => items.iter().all(|value| valid_ranges(source, value)),
        _ => true,
    }
}

fn valid_targets(value: &Value, bindings: usize, callables: usize) -> bool {
    let id = |value: &Value, count: usize| value.as_u64().is_some_and(|id| id < count as u64);
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "binding_ids" {
                value
                    .as_array()
                    .is_some_and(|ids| ids.iter().all(|value| id(value, bindings)))
            } else if key == "callable_id" {
                id(value, callables)
            } else {
                valid_targets(value, bindings, callables)
            }
        }),
        Value::Array(items) => items
            .iter()
            .all(|value| valid_targets(value, bindings, callables)),
        _ => true,
    }
}

/// The declarations an operation names: one exact lexical binding, or a set of
/// duplicate declarations of one name. Anything else names no declaration.
fn admitted_target(operation: &Value) -> Option<&Vec<Value>> {
    if !REFERENCES.contains(&operation["kind"].as_str()?) {
        return None;
    }
    let target = &operation["detail"]["target"];
    let ids = target["binding_ids"].as_array()?;
    let exact = target["kind"] == "binding"
        && ids.len() == 1
        && matches!(
            target["resolution"].as_str(),
            Some("lexical-only" | "declaration")
        );
    let candidates = target["kind"] == "ambiguous"
        && ids.len() >= 2
        && target["resolution"] == "duplicate-declarations";
    (exact || candidates).then_some(ids)
}

fn span(range: &Value) -> (u64, u64) {
    (
        range["start"].as_u64().unwrap_or(0),
        range["end"].as_u64().unwrap_or(0),
    )
}
fn encloses(outer: (u64, u64), inner: (u64, u64)) -> bool {
    outer.0 <= inner.0 && outer.1 >= inner.1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<'a> {
    schema: String,
    profile: String,
    offset_unit: String,
    source_bytes: u64,
    ok: bool,
    #[serde(borrow)]
    coverage: CoverageReply<'a>,
    #[serde(borrow)]
    scopes: Vec<&'a RawValue>,
    #[serde(borrow)]
    bindings: Vec<&'a RawValue>,
    #[serde(borrow)]
    callables: Vec<&'a RawValue>,
    #[serde(borrow)]
    regions: Vec<&'a RawValue>,
    #[serde(borrow)]
    operations: Vec<&'a RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageReply<'a> {
    status: String,
    diagnostics: Vec<String>,
    analyzed_range: Value,
    #[serde(borrow)]
    frontiers: Vec<&'a RawValue>,
}

/// One admitted worker report: the worker's own JSON text, the byte span of
/// every row in it, and the indexes that row pages filter by.
pub struct Report {
    text: Vec<u8>,
    coverage: Value,
    ok: bool,
    rows: [Vec<Range<usize>>; 6],
    /// Binding names, for the declaration search.
    names: Vec<Box<str>>,
    /// Index of each operation's kind in `kinds`.
    kinds: Vec<u8>,
    kind_names: Vec<String>,
    /// Operations whose admitted target names each binding, in report order.
    references: Vec<Vec<u32>>,
}

/// `region` is the half-open original byte range the caller asked for, if any.
/// It is passed in rather than recovered from the response so the declared
/// coverage can be checked against the request instead of trusted.
pub fn admit(
    source: &str,
    region: Option<(usize, usize)>,
    mut text: Vec<u8>,
    cancelled: &AtomicBool,
) -> Result<Report> {
    if text.last() == Some(&b'\n') {
        text.pop();
    }
    let reply: Reply = serde_json::from_slice(&text).map_err(|_| invalid())?;
    let coverage = &reply.coverage;
    let unavailable = coverage.status == "unavailable";
    if reply.schema != SCHEMA
        || reply.profile != "lexical-effects-v1"
        || reply.offset_unit != "utf-8-byte"
        || reply.source_bytes != source.len() as u64
        || !["complete", "partial", "unavailable"].contains(&coverage.status.as_str())
        || reply.ok == unavailable
        || !valid_range(source, &coverage.analyzed_range)
    {
        return Err(invalid());
    }
    // An unscoped request must analyze the whole verified source, a scoped one
    // must analyze a range that contains what was asked, and facts covering
    // less than the whole source can never be reported as complete coverage.
    let (start, end) = span(&coverage.analyzed_range);
    let whole = start == 0 && end == source.len() as u64;
    match region {
        None if !whole => return Err(invalid()),
        Some((first, last)) if start > first as u64 || end < last as u64 => {
            return Err(invalid());
        }
        _ => {}
    }
    if coverage.status == "complete"
        && (!whole || !coverage.frontiers.is_empty() || !coverage.diagnostics.is_empty())
    {
        return Err(invalid());
    }
    let tables = [
        &reply.scopes,
        &reply.bindings,
        &reply.callables,
        &reply.regions,
        &reply.operations,
        &coverage.frontiers,
    ];
    if unavailable && tables[..5].iter().any(|rows| !rows.is_empty()) {
        return Err(invalid());
    }
    let counts = tables.map(Vec::len);
    let base = text.as_ptr() as usize;
    let mut rows: [Vec<Range<usize>>; 6] = Default::default();
    let mut ranges: [Vec<(u64, u64)>; 4] = Default::default();
    let mut names = Vec::with_capacity(counts[BINDINGS]);
    let mut kinds = Vec::with_capacity(counts[OPERATIONS]);
    let mut kind_names = Vec::<String>::new();
    let mut references = vec![Vec::new(); counts[BINDINGS]];
    // A parent consumes one unique local slot per child region or operation.
    let mut slots = HashSet::new();
    for (table, raws) in tables.iter().enumerate() {
        let contract = TABLES[table].1;
        rows[table].reserve_exact(raws.len());
        for (index, raw) in raws.iter().enumerate() {
            if index % 4096 == 0 && cancelled.load(Ordering::Relaxed) {
                return Err(Error::new(499, "Source facts request was cancelled")
                    .with_code(Code::Cancelled));
            }
            let at = raw.get().as_ptr() as usize - base;
            rows[table].push(at..at + raw.get().len());
            let row: Value = serde_json::from_str(raw.get()).map_err(|_| invalid())?;
            validation::schema(contract, &row, 502).map_err(|_| invalid())?;
            if !valid_ranges(source, &row) {
                return Err(invalid());
            }
            let range = span(&row["range"]);
            // Every row but a frontier is named by its position.
            if table < 5 && row["id"].as_u64() != Some(index as u64) {
                return Err(invalid());
            }
            // A valid ID alone does not make a valid ownership graph. Parents
            // precede children and enclose their byte ranges.
            let owner = |table: usize, field: &str| -> Result<Option<(u64, u64)>> {
                match row[field].as_u64() {
                    None if row[field].is_null() => Ok(None),
                    Some(id) if (id as usize) < ranges[table].len() => {
                        Ok(Some(ranges[table][id as usize]))
                    }
                    _ => Err(invalid()),
                }
            };
            let root =
                |kind: &str| row["kind"] == kind && range == (0, source.len() as u64) && index == 0;
            match table {
                SCOPES | REGIONS => {
                    match owner(table, "parent_id")? {
                        Some(parent) if encloses(parent, range) => {}
                        None if root("program") => {}
                        _ => return Err(invalid()),
                    }
                    if table == REGIONS {
                        if row["callable_id"]
                            .as_u64()
                            .is_some_and(|id| id as usize >= counts[CALLABLES])
                        {
                            return Err(invalid());
                        }
                        match row["parent_id"].as_u64() {
                            Some(parent) => {
                                if !slots.insert((parent, row["entry_order"].as_u64().unwrap())) {
                                    return Err(invalid());
                                }
                            }
                            None if row["entry_order"] == 0 && row["callable_id"].is_null() => {}
                            None => return Err(invalid()),
                        }
                    }
                    ranges[table].push(range);
                }
                BINDINGS | CALLABLES => {
                    let Some(scope) = owner(SCOPES, "scope_id")? else {
                        return Err(invalid());
                    };
                    if !encloses(scope, range)
                        || (table == CALLABLES && !encloses(range, span(&row["body_range"])))
                    {
                        return Err(invalid());
                    }
                    if table == BINDINGS {
                        names.push(row["name"].as_str().unwrap_or_default().into());
                    } else {
                        ranges[CALLABLES].push(range);
                    }
                }
                OPERATIONS => {
                    let Some(region) = owner(REGIONS, "region_id")? else {
                        return Err(invalid());
                    };
                    let order = row["order"].as_u64().unwrap();
                    if !encloses(region, range)
                        || !slots.insert((row["region_id"].as_u64().unwrap(), order))
                        || !valid_targets(&row, counts[BINDINGS], counts[CALLABLES])
                    {
                        return Err(invalid());
                    }
                    let kind = row["kind"].as_str().unwrap();
                    let code = match kind_names.iter().position(|name| name == kind) {
                        Some(code) => code,
                        None => {
                            kind_names.push(kind.to_owned());
                            kind_names.len() - 1
                        }
                    };
                    kinds.push(code as u8);
                    for id in admitted_target(&row).into_iter().flatten() {
                        references[id.as_u64().unwrap() as usize].push(index as u32);
                    }
                }
                _ => {}
            }
        }
        // A non-empty report has exactly one program scope and region, first.
        if (table == SCOPES || table == REGIONS)
            && !unavailable
            && rows[table].is_empty()
            && counts.iter().take(5).any(|&count| count != 0)
        {
            return Err(invalid());
        }
    }
    let coverage = json!({
        "status": coverage.status,
        "diagnostics": coverage.diagnostics,
        "analyzed_range": coverage.analyzed_range,
    });
    let ok = reply.ok;
    drop(reply);
    Ok(Report {
        text,
        coverage,
        ok,
        rows,
        names,
        kinds,
        kind_names,
        references,
    })
}

/// What one page of rows selects.
pub struct Page {
    pub table: usize,
    pub offset: usize,
    pub limit: usize,
    /// Operations whose admitted target names this binding.
    pub binding: Option<usize>,
    /// Operations of one kind.
    pub kind: Option<String>,
    /// Bindings whose name contains this text, ignoring case.
    pub name: Option<String>,
    /// Bindings an ambiguous operation names as candidates.
    pub candidates_of: Option<usize>,
}

impl Report {
    fn bytes(&self) -> usize {
        self.text.len()
            + self.rows.iter().map(|rows| rows.len() * 16).sum::<usize>()
            + self
                .references
                .iter()
                .map(|ids| ids.len() * 4 + 24)
                .sum::<usize>()
            + self.names.iter().map(|name| name.len() + 16).sum::<usize>()
    }

    fn raw(&self, table: usize, index: usize) -> &str {
        // Spans were cut from this text at admission on token boundaries.
        std::str::from_utf8(&self.text[self.rows[table][index].clone()]).unwrap_or("null")
    }

    fn row(&self, table: usize, index: usize) -> Value {
        serde_json::from_str(self.raw(table, index)).unwrap_or(Value::Null)
    }

    /// The report without its rows: coverage and how many rows each table has.
    pub fn summary(&self, source: Value, cached: bool) -> Value {
        let counts: serde_json::Map<String, Value> = TABLES
            .iter()
            .zip(&self.rows)
            .map(|((name, _), rows)| ((*name).to_owned(), json!(rows.len())))
            .collect();
        json!({
            "schema": SCHEMA,
            "profile": "lexical-effects-v1",
            "offset_unit": "utf-8-byte",
            "source_bytes": source["byte_size"],
            "ok": self.ok,
            "coverage": self.coverage,
            "counts": counts,
            "cached": cached,
            "source": source,
        })
    }

    /// One page of rows. Operation pages carry the bindings their exact
    /// targets name, so a page is readable without the whole binding table.
    pub fn page(&self, source: Value, page: &Page) -> Result<Value> {
        let table = page.table;
        let needle = page.name.as_deref().map(str::to_lowercase);
        let name_matches = |binding: usize| {
            needle.as_deref().is_none_or(|needle| {
                self.names
                    .get(binding)
                    .is_some_and(|name| name.to_lowercase().contains(needle))
            })
        };
        let indices: Vec<usize> = match (table, page.binding, page.candidates_of) {
            (OPERATIONS, Some(binding), _) => {
                let ids = self
                    .references
                    .get(binding)
                    .ok_or_else(|| Error::bad("binding_id is not a binding in this report"))?;
                ids.iter()
                    .map(|&id| id as usize)
                    .filter(|&id| self.kind_matches(id, page))
                    .collect()
            }
            (OPERATIONS, None, _) if page.kind.is_some() => (0..self.rows[OPERATIONS].len())
                .filter(|&id| self.kind_matches(id, page))
                .collect(),
            (BINDINGS, _, Some(operation)) => {
                if operation >= self.rows[OPERATIONS].len() {
                    return Err(Error::bad(
                        "candidates_of is not an operation in this report",
                    ));
                }
                let row = self.row(OPERATIONS, operation);
                let ids = admitted_target(&row)
                    .filter(|_| row["detail"]["target"]["kind"] == "ambiguous")
                    .ok_or_else(|| {
                        Error::bad("candidates_of does not name ambiguous declarations")
                    })?;
                ids.iter()
                    .filter_map(Value::as_u64)
                    .map(|id| id as usize)
                    .filter(|&id| name_matches(id))
                    .collect()
            }
            (BINDINGS, _, None) if page.name.is_some() => (0..self.names.len())
                .filter(|&id| name_matches(id))
                .collect(),
            _ => (0..self.rows[table].len()).collect(),
        };
        let total = indices.len();
        let selected = indices.iter().skip(page.offset).take(page.limit);
        let rows: Vec<Value> = selected
            .clone()
            .map(|&index| self.row(table, index))
            .collect();
        let mut named = Vec::<u64>::new();
        if table == OPERATIONS {
            named.extend(page.binding.map(|id| id as u64));
            for row in &rows {
                if let Some(ids) = admitted_target(row)
                    && ids.len() == 1
                    && let Some(id) = ids[0].as_u64()
                    && !named.contains(&id)
                {
                    named.push(id);
                }
            }
        }
        let bindings: Vec<Value> = named
            .into_iter()
            .map(|id| self.row(BINDINGS, id as usize))
            .collect();
        Ok(json!({
            "schema": ROWS_SCHEMA,
            "source": source,
            "analyzed_range": self.coverage["analyzed_range"],
            "table": TABLES[table].0,
            "filter": {
                "binding_id": page.binding,
                "kind": page.kind,
                "name": page.name,
                "candidates_of": page.candidates_of,
            },
            "offset": page.offset,
            "total": total,
            "rows": rows,
            "bindings": bindings,
        }))
    }

    fn kind_matches(&self, operation: usize, page: &Page) -> bool {
        page.kind.as_deref().is_none_or(|kind| {
            self.kind_names
                .get(self.kinds[operation] as usize)
                .is_some_and(|name| name == kind)
        })
    }
}

type Key = (String, Option<(usize, usize)>);

/// Admitted reports by source SHA-256 and requested region. One analysis runs
/// at a time, so two requests for the same bytes share one worker run.
#[derive(Default)]
pub struct SourceFacts {
    cache: Mutex<VecDeque<(Key, Arc<Report>)>>,
    run: tokio::sync::Mutex<()>,
}

impl SourceFacts {
    /// The cached report for these verified bytes and region, or a fresh one
    /// from the worker.
    pub async fn report(
        &self,
        deobfuscator: &Deobfuscator,
        source: String,
        sha256: &str,
        region: Option<(usize, usize)>,
    ) -> Result<(Arc<Report>, bool)> {
        if let Some((start, end)) = region
            && (start > end
                || end > source.len()
                || !source.is_char_boundary(start)
                || !source.is_char_boundary(end))
        {
            return Err(Error::bad(
                "A source facts region must be an original byte range in this artifact",
            ));
        }
        let key = (sha256.to_owned(), region);
        if let Some(report) = self.cached(&key) {
            return Ok((report, true));
        }
        let _run = self.run.lock().await;
        if let Some(report) = self.cached(&key) {
            return Ok((report, true));
        }
        let text = deobfuscator.source_facts(&source, region).await?;
        // Admission parses every row, so it runs off the async workers. A
        // request that goes away stops it at the next batch of rows.
        let cancelled = Arc::new(AtomicBool::new(false));
        let _stop = CancelOnDrop(cancelled.clone());
        let report = tokio::task::spawn_blocking(move || admit(&source, region, text, &cancelled))
            .await
            .map_err(|_| Error::new(500, "Source facts admission stopped unexpectedly"))??;
        let report = Arc::new(report);
        self.store(key, report.clone());
        Ok((report, false))
    }

    fn cached(&self, key: &Key) -> Option<Arc<Report>> {
        let mut cache = self.cache.lock().unwrap();
        let at = cache.iter().position(|(entry, _)| entry == key)?;
        let entry = cache.remove(at)?;
        let report = entry.1.clone();
        cache.push_front(entry);
        Some(report)
    }

    fn store(&self, key: Key, report: Arc<Report>) {
        // Eviction only costs a rebuild, never a row: keep the newest report
        // whatever its size, and older ones while they fit beside it.
        let budget = (crate::js_worker_alloc::machine_ceiling() / 16) as usize;
        let mut cache = self.cache.lock().unwrap();
        cache.push_front((key, report));
        while cache.len() > CACHE_ENTRIES
            || (cache.len() > 1
                && cache
                    .iter()
                    .map(|(_, report)| report.bytes())
                    .sum::<usize>()
                    > budget)
        {
            cache.pop_back();
        }
    }
}
