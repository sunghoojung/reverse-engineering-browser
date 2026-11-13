//! Researcher names for Wasm functions, joined into the agent-facing Wasm reads.
//!
//! A name is interpretation, never evidence. It lives in the one evidence-names
//! scratchpad of the Local Analyst library (`docs/product/evidence-names-v1.md`)
//! and is keyed by the module's SHA-256 and the function index in the full
//! index space, imports included, so it follows identical module bytes across
//! sessions. Reads add it beside the captured identity as `analyst_name`; no
//! captured field is replaced. The document is validated exactly as the UI
//! validates it (`apps/research-ui/evidence_names.js`): a document the UI would
//! refuse joins no name here either.
//!
//! The library file is at most 1 MiB and the names document at most 32 KiB, so
//! a parse is bounded. A stat-keyed cache keeps the common path to one
//! `stat` per read, and a library without Wasm names leaves every document
//! untouched apart from its small `analyst_names` status member.
use crate::{
    error::{Code, Error, Result},
    evidence_package,
    workspace::Store,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};
use unicode_casefold::UnicodeCaseFold;

pub const KIND: &str = "reb-evidence-names";
pub const SUFFIX: &str = ".reb-names.json";
pub const FILE_NAME: &str = "Evidence names.reb-names.json";
pub const MAX_NAMES: usize = 500;
pub const MAX_CHARACTERS: usize = 80;
pub const MAX_DOCUMENT_BYTES: usize = 32_768;
/// VM program groups and Wasm module groups are bounded separately.
pub const MAX_GROUPS: usize = 64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const NOTICE: &str = "Researcher names from the local Analyst library, keyed by module SHA-256 and function index. A name is interpretation, not evidence; captured names stay in their own fields.";

/// The canonical key lanes share: `wasm-function:<sha256>:<index>`.
pub fn key(sha256: &str, function: u32) -> String {
    format!("wasm-function:{sha256}:{function}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// No names document exists yet.
    None,
    Ready,
    Malformed,
    Ambiguous,
    /// The library itself could not be read.
    Unavailable,
}
impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Ready => "ready",
            Self::Malformed => "malformed",
            Self::Ambiguous => "ambiguous",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The Wasm names one library generation holds.
#[derive(Debug)]
pub struct Names {
    pub status: Status,
    pub generation: Option<u64>,
    pub file: Option<String>,
    modules: Modules,
}
impl Names {
    fn unavailable() -> Self {
        Self {
            status: Status::Unavailable,
            generation: None,
            file: None,
            modules: HashMap::new(),
        }
    }
    /// The researcher name of one function, if the document is usable.
    pub fn function(&self, sha256: &str, function: u32) -> Option<&str> {
        self.modules
            .get(sha256)
            .and_then(|module| module.get(&function))
            .map(String::as_str)
    }
    pub fn module(&self, sha256: &str) -> Option<&BTreeMap<u32, String>> {
        self.modules.get(sha256)
    }
    /// Whether any read would change: the unnamed path skips every join.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
    fn status_member(&self) -> Map<String, Value> {
        let mut member = Map::new();
        member.insert("status".into(), json!(self.status.as_str()));
        member.insert("file".into(), json!(self.file));
        member.insert("library_generation".into(), json!(self.generation));
        member.insert("notice".into(), json!(NOTICE));
        member
    }
    /// The `analyst_names` member of a document that spans several modules.
    pub fn summary(&self, joined: usize) -> Value {
        let mut member = self.status_member();
        member.insert("joined".into(), json!(joined));
        Value::Object(member)
    }
    /// The `analyst_names` member of a one-module document: every name of the
    /// module whose index lies inside its `functions` index space, as
    /// `[index, name]` pairs in index order.
    pub fn module_member(&self, sha256: &str, functions: u64) -> Value {
        let mut member = self.status_member();
        member.insert("module_sha256".into(), json!(sha256));
        let pairs: Vec<Value> = self
            .module(sha256)
            .into_iter()
            .flatten()
            .filter(|(index, _)| u64::from(**index) < functions)
            .map(|(index, name)| json!([index, name]))
            .collect();
        member.insert("functions".into(), Value::Array(pairs));
        Value::Object(member)
    }
}

// ---------------------------------------------------------------------------
// The closed document, as evidence_names.js validates it.

/// Names by module SHA-256, then function index.
type Modules = HashMap<String, BTreeMap<u32, String>>;

fn exact<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)))
        .then_some(object)
}
fn decimal(value: &Value, max: u64) -> bool {
    value.as_str().is_some_and(|text| {
        !text.is_empty()
            && text.len() <= 20
            && text.bytes().all(|b| b.is_ascii_digit())
            && !text.starts_with('0')
            && text.parse::<u64>().is_ok_and(|n| n <= max)
    })
}
fn hash(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn offset(value: &Value) -> Option<u64> {
    value.as_u64().filter(|n| *n <= MAX_SAFE_INTEGER)
}
fn forbidden(c: char) -> bool {
    matches!(c as u32,
        0x0000..=0x001f | 0x007f..=0x009f | 0x061c | 0x200b..=0x200f | 0x2028..=0x202e
        | 0x2060..=0x2069 | 0xfeff)
}
/// Plain single-line text of 1 to 80 code points without surrounding
/// whitespace, control, invisible or direction-override characters.
pub fn valid_name(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        !text.is_empty()
            && text.trim() == text
            && text.chars().count() <= MAX_CHARACTERS
            && !text.chars().any(forbidden)
    })
}
/// Trims, and refuses what `valid_name` refuses. An empty result clears.
pub fn normalize_name(input: &str) -> Result<String> {
    let text = input.trim();
    if text.chars().count() > MAX_CHARACTERS {
        return Err(Error::bad(format!(
            "Names allow at most {MAX_CHARACTERS} characters"
        )));
    }
    if text.chars().any(forbidden) {
        return Err(Error::bad(
            "Names are plain single-line text without control, invisible or direction-override characters",
        ));
    }
    Ok(text.to_owned())
}

const REQUEST: [&str; 5] = ["origin", "session", "process", "sequence", "request"];
const ARTIFACT: [&str; 4] = ["session", "artifact", "sha256", "bytes"];
const PROGRAM: [&str; 5] = ["finding", "session", "artifact", "sha256", "bytes"];
const HANDLER: [&str; 3] = ["handler", "start", "end"];
const FIELDS_V1: [&str; 6] = [
    "document_kind",
    "contract_version",
    "scope",
    "requests",
    "artifacts",
    "vm_programs",
];
const FIELDS_V2: [&str; 7] = [
    "document_kind",
    "contract_version",
    "scope",
    "requests",
    "artifacts",
    "vm_programs",
    "wasm_modules",
];

const REQUEST_ENTRY: [&str; 6] = [
    "origin", "session", "process", "sequence", "request", "name",
];
const ARTIFACT_ENTRY: [&str; 5] = ["session", "artifact", "sha256", "bytes", "name"];
const PROGRAM_ENTRY: [&str; 6] = [
    "finding", "session", "artifact", "sha256", "bytes", "handlers",
];
const HANDLER_ENTRY: [&str; 4] = ["handler", "start", "end", "name"];
const FUNCTION_ENTRY: [&str; 2] = ["function", "name"];

/// The Wasm names of a valid document, or None when the document is refused.
fn validate(doc: &Value) -> Option<Modules> {
    let version = doc.get("contract_version").and_then(Value::as_u64)?;
    let fields: &[&str] = match version {
        1 => &FIELDS_V1,
        2 => &FIELDS_V2,
        _ => return None,
    };
    let object = exact(doc, fields)?;
    if object["document_kind"] != KIND || object["scope"] != "local-analyst-library" {
        return None;
    }
    let requests = object["requests"].as_array()?;
    let artifacts = object["artifacts"].as_array()?;
    let programs = object["vm_programs"].as_array()?;
    let empty = Vec::new();
    let modules = match object.get("wasm_modules") {
        Some(value) => value.as_array()?,
        None => &empty,
    };
    if programs.len() > MAX_GROUPS || modules.len() > MAX_GROUPS {
        return None;
    }
    let mut keys: HashSet<String> = HashSet::new();
    let mut admit = |key: String, name: &Value| -> bool {
        valid_name(name) && keys.insert(key) && keys.len() <= MAX_NAMES
    };
    for entry in requests {
        let entry = exact(entry, &REQUEST_ENTRY)?;
        let valid = (entry["origin"] == "live" || entry["origin"] == "demo")
            && decimal(&entry["session"], u64::MAX)
            && decimal(&entry["process"], u64::from(u32::MAX))
            && decimal(&entry["sequence"], u64::MAX)
            && decimal(&entry["request"], u64::MAX);
        let key = format!(
            "request:{}",
            serde_json::to_string(&REQUEST.map(|f| &entry[f])).ok()?
        );
        if !valid || !admit(key, &entry["name"]) {
            return None;
        }
    }
    let artifact_valid = |entry: &Map<String, Value>| {
        decimal(&entry["session"], u64::MAX)
            && decimal(&entry["artifact"], u64::MAX)
            && hash(&entry["sha256"])
            && offset(&entry["bytes"]).is_some()
    };
    for entry in artifacts {
        let entry = exact(entry, &ARTIFACT_ENTRY)?;
        let key = format!(
            "artifact:{}",
            serde_json::to_string(&ARTIFACT.map(|f| &entry[f])).ok()?
        );
        if !artifact_valid(entry) || !admit(key, &entry["name"]) {
            return None;
        }
    }
    let mut groups = HashSet::new();
    for program in programs {
        let program = exact(program, &PROGRAM_ENTRY)?;
        let finding = program["finding"].as_str()?;
        if finding.len() != 24
            || !finding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !artifact_valid(program)
        {
            return None;
        }
        let handlers = program["handlers"].as_array()?;
        let group = serde_json::to_string(&PROGRAM.map(|f| &program[f])).ok()?;
        if handlers.is_empty() || !groups.insert(group.clone()) {
            return None;
        }
        for entry in handlers {
            let entry = exact(entry, &HANDLER_ENTRY)?;
            let handler = entry["handler"].as_str()?;
            let (start, end) = (offset(&entry["start"])?, offset(&entry["end"])?);
            if handler.is_empty()
                || handler.len() > 96
                || !handler
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b':')
                || end <= start
            {
                return None;
            }
            let key = format!(
                "handler:{group}:{}",
                serde_json::to_string(&HANDLER.map(|f| &entry[f])).ok()?
            );
            if !admit(key, &entry["name"]) {
                return None;
            }
        }
    }
    let mut out: Modules = HashMap::new();
    for module in modules {
        let module = exact(module, &["sha256", "functions"])?;
        if !hash(&module["sha256"]) {
            return None;
        }
        let sha = module["sha256"].as_str()?.to_owned();
        let functions = module["functions"].as_array()?;
        if functions.is_empty() || out.contains_key(&sha) {
            return None;
        }
        let mut named = BTreeMap::new();
        for entry in functions {
            let entry = exact(entry, &FUNCTION_ENTRY)?;
            let function = u32::try_from(entry["function"].as_u64()?).ok()?;
            if !admit(key(&sha, function), &entry["name"]) {
                return None;
            }
            named.insert(function, entry["name"].as_str()?.to_owned());
        }
        out.insert(sha, named);
    }
    // The compact serialization of the same members has the length the UI
    // measures: names hold no character either encoder escapes differently.
    (serde_json::to_vec(doc).ok()?.len() <= MAX_DOCUMENT_BYTES).then_some(out)
}

fn read_document(file: &Value) -> Option<(Value, Modules)> {
    if file["kind"] != "scratchpad" || file["language"] != "json" {
        return None;
    }
    let content = file["content"].as_str()?;
    // Duplicate members, escaped or not, are refused before a Value exists.
    let doc = evidence_package::parse_bytes(content.as_bytes()).ok()?;
    let names = validate(&doc)?;
    Some((doc, names))
}

/// What `locate` found in one library generation.
struct Located<'a> {
    status: Status,
    file: Option<&'a Value>,
    document: Option<Value>,
    names: Modules,
}

/// A suffix only makes a malformed document discoverable; ordinary JSON files
/// are never adopted by name alone. Several candidates are ambiguous.
fn locate(library: &Value) -> Located<'_> {
    let candidates: Vec<&Value> = library["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|file| {
            file["kind"] == "scratchpad"
                && file["language"] == "json"
                && (file["name"].as_str().is_some_and(|n| n.ends_with(SUFFIX))
                    || read_document(file).is_some())
        })
        .collect();
    match candidates.as_slice() {
        [] => Located {
            status: Status::None,
            file: None,
            document: None,
            names: HashMap::new(),
        },
        [file] => match read_document(file) {
            Some((document, names)) => Located {
                status: Status::Ready,
                file: Some(file),
                document: Some(document),
                names,
            },
            None => Located {
                status: Status::Malformed,
                file: Some(file),
                document: None,
                names: HashMap::new(),
            },
        },
        _ => Located {
            status: Status::Ambiguous,
            file: None,
            document: None,
            names: HashMap::new(),
        },
    }
}

fn names_of(library: &Value) -> Names {
    let located = locate(library);
    Names {
        status: located.status,
        generation: library["generation"].as_u64(),
        file: located
            .file
            .and_then(|file| file["name"].as_str().map(str::to_owned)),
        modules: if located.status == Status::Ready {
            located.names
        } else {
            HashMap::new()
        },
    }
}

// ---------------------------------------------------------------------------
// The cache.

/// Device, inode, length and modification time. Every library write renames
/// a new file into place, so a new generation always has a new inode.
pub(crate) type Fingerprint = Option<(u64, u64, u64, i64, i64)>;

#[derive(Default)]
pub struct Cache(Mutex<Option<(Fingerprint, Arc<Names>)>>);
impl Cache {
    /// The current names, rereading the library only when its file changed.
    /// An unreadable library joins nothing and says so.
    pub fn get(&self, store: &Store) -> Arc<Names> {
        let fingerprint = fingerprint(&store.path);
        if let Some((cached, names)) = self.0.lock().unwrap().as_ref()
            && *cached == fingerprint
        {
            return names.clone();
        }
        let names = Arc::new(match store.load() {
            Ok(library) => names_of(&library),
            Err(_) => Names::unavailable(),
        });
        *self.0.lock().unwrap() = Some((fingerprint, names.clone()));
        names
    }
}

#[cfg(unix)]
pub(crate) fn fingerprint(path: &std::path::Path) -> Fingerprint {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|meta| {
        (
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
        )
    })
}
#[cfg(not(unix))]
pub(crate) fn fingerprint(_: &std::path::Path) -> Fingerprint {
    None
}

// ---------------------------------------------------------------------------
// Joins. Each adds `analyst_name` beside a captured function identity and one
// `analyst_names` status member; nothing captured is changed or removed.

/// `inspect_wasm`: function headers, imports, declarations and the start row
/// by their `function_index`; call and `ref.func` rows by
/// `target_function_index`.
pub fn annotate_inspection(document: &mut Value, names: &Names) {
    let Some(sha) = document["sha256"].as_str().map(str::to_owned) else {
        return;
    };
    let total = document["imported_functions"].as_u64().unwrap_or(0)
        + document["defined_functions"].as_u64().unwrap_or(0);
    if let Some(module) = names.module(&sha)
        && let Some(rows) = document["rows"].as_array_mut()
    {
        for row in rows {
            let header = matches!(
                row["kind"].as_str(),
                Some("function" | "import" | "declaration" | "start")
            );
            let lookup = |field: &str| {
                row[field]
                    .as_u64()
                    .and_then(|index| u32::try_from(index).ok())
                    .and_then(|index| module.get(&index))
                    .cloned()
            };
            let own = header.then(|| lookup("function_index")).flatten();
            let target = lookup("target_function_index");
            if let Some(name) = own {
                row["analyst_name"] = json!(name);
            }
            if let Some(name) = target {
                row["target_analyst_name"] = json!(name);
            }
        }
    }
    // A windowed read can drop rows but not the module's names.
    document["analyst_names"] = names.module_member(&sha, total);
}

/// Appends members to a document built as text, before its closing brace.
pub fn append_members(mut document: String, members: &[(&str, Value)]) -> String {
    if members.is_empty() || !document.ends_with('}') {
        return document;
    }
    document.pop();
    for (key, value) in members {
        document.push(',');
        document.push_str(&serde_json::to_string(key).expect("JSON key"));
        document.push(':');
        document.push_str(&serde_json::to_string(value).expect("JSON value"));
    }
    document.push('}');
    document
}

/// `get_xrefs`: the selection and every row that names a Wasm function of the
/// selected module.
pub fn annotate_xrefs(document: &mut Value, names: &Names) {
    let selection = &document["selection"];
    let Some(sha) = selection["wasm_sha256"].as_str().map(str::to_owned) else {
        return;
    };
    let mut joined = 0usize;
    if let Some(module) = names.module(&sha) {
        let name_of = |value: &Value| {
            value
                .as_u64()
                .and_then(|index| u32::try_from(index).ok())
                .and_then(|index| module.get(&index))
                .cloned()
        };
        if let Some(name) = name_of(&document["selection"]["function_index"]) {
            document["selection"]["analyst_name"] = json!(name);
            joined += 1;
        }
        if let Some(pages) = document["pages"].as_object_mut() {
            for page in pages.values_mut() {
                for row in page["rows"].as_array_mut().into_iter().flatten() {
                    if let Some(name) = name_of(&row["function_index"]) {
                        row["analyst_name"] = json!(name);
                        joined += 1;
                    }
                }
            }
        }
    }
    document["analyst_names"] = names.summary(joined);
}

/// `get_flow_graph`: Wasm function nodes by their `sha256` and
/// `function_index`.
pub fn annotate_flow_graph(document: &mut Value, names: &Names) {
    let mut joined = 0usize;
    if !names.is_empty() {
        for node in document["nodes"].as_array_mut().into_iter().flatten() {
            if node["kind"] != "wasm" {
                continue;
            }
            let name = node["sha256"].as_str().and_then(|sha| {
                node["function_index"]
                    .as_u64()
                    .and_then(|index| u32::try_from(index).ok())
                    .and_then(|index| names.function(sha, index))
            });
            if let Some(name) = name.map(str::to_owned) {
                node["analyst_name"] = json!(name);
                joined += 1;
            }
        }
    }
    document["analyst_names"] = names.summary(joined);
}

/// Whether a JSON document names any module these names cover, read from its
/// `"sha256":"<hex>"` members in one pass without parsing it.
fn names_any_module(text: &str, names: &Names) -> bool {
    const KEY: &str = "\"sha256\":\"";
    text.match_indices(KEY).any(|(at, _)| {
        text.get(at + KEY.len()..at + KEY.len() + 64)
            .is_some_and(|sha| names.modules.contains_key(sha))
    })
}

/// The flow graph is cached as bytes. Unless it names a module that has a
/// researcher name, only the status member is appended, as text; otherwise
/// the graph is parsed, joined and encoded again, which its own node and
/// edge budgets bound. A name for an unrelated module costs one scan.
pub fn annotate_flow_graph_bytes(
    graph: axum::body::Bytes,
    names: &Names,
) -> Result<axum::body::Bytes> {
    let text =
        std::str::from_utf8(&graph).map_err(|_| Error::new(500, "Flow graph encoding failed"))?;
    if !names_any_module(text, names) {
        return Ok(append_members(text.to_owned(), &[("analyst_names", names.summary(0))]).into());
    }
    let mut document: Value = serde_json::from_slice(&graph)
        .map_err(|_| Error::new(500, "Flow graph encoding failed"))?;
    annotate_flow_graph(&mut document, names);
    Ok(serde_json::to_vec(&document)?.into())
}

/// `get_request_stack`: Wasm frames by `module_sha256` and `function_index`,
/// in the stack and in every task segment.
pub fn annotate_request_stack(document: &mut Value, names: &Names) {
    let mut joined = 0usize;
    if !names.is_empty() {
        let mut mark = |frames: Option<&mut Vec<Value>>| {
            for frame in frames.into_iter().flatten() {
                let name = frame["module_sha256"].as_str().and_then(|sha| {
                    frame["function_index"]
                        .as_u64()
                        .and_then(|index| u32::try_from(index).ok())
                        .and_then(|index| names.function(sha, index))
                });
                if let Some(name) = name.map(str::to_owned) {
                    frame["analyst_name"] = json!(name);
                    joined += 1;
                }
            }
        };
        mark(document["frames"].as_array_mut());
        for segment in document["task_segments"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            mark(segment["frames"].as_array_mut());
        }
    }
    document["analyst_names"] = names.summary(joined);
}

// ---------------------------------------------------------------------------
// The narrow write: one function's name, read-modify-written by the backend.

fn projection(file: &Value) -> Value {
    json!({"id":file["id"],"folder_id":file["folder_id"],"name":file["name"],
        "kind":file["kind"],"language":file["language"],"content":file["content"]})
}

/// Sets, replaces or clears one function's name and returns what changed.
/// Other names, other files and the folders are preserved; a stale library
/// generation is refused with 409 by `Store::replace`, never retried.
pub fn set_function_name(store: &Store, request: &Value) -> Result<Value> {
    set_function_name_with(store, request, || {})
}

/// `between` runs after the library is read and before it is replaced, where
/// another writer can land. The replacement carries the generation that was
/// read, so such a write is refused with 409 instead of being overwritten.
fn set_function_name_with(store: &Store, request: &Value, between: impl FnOnce()) -> Result<Value> {
    let object = request
        .as_object()
        .ok_or_else(|| Error::bad("Wasm function name request must be an object"))?;
    let allowed = ["action", "sha256", "function", "name", "expected_name"];
    if let Some(field) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::bad(format!(
            "Wasm function name request has an unknown field: {}",
            if field.len() <= 64 { field } else { "(long)" }
        )));
    }
    for field in ["sha256", "function", "name"] {
        if !object.contains_key(field) {
            return Err(Error::bad(format!(
                "Wasm function name request needs {field}"
            )));
        }
    }
    if !hash(&request["sha256"]) {
        return Err(Error::bad(
            "sha256 is the module's 64 lowercase hex character SHA-256",
        ));
    }
    let sha = request["sha256"].as_str().unwrap().to_owned();
    let function = request["function"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            Error::bad("function is an index in the full function index space, imports included")
        })?;
    let name = normalize_name(
        request["name"]
            .as_str()
            .ok_or_else(|| Error::bad("name is a string; an empty name clears it"))?,
    )?;
    let expected = match object.get("expected_name") {
        None => None,
        Some(Value::Null) => Some(String::new()),
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => {
            return Err(Error::bad(
                "expected_name is the current name, or null for an unnamed function",
            ));
        }
    };
    let library = store.load()?;
    let located = locate(&library);
    match located.status {
        Status::Ambiguous => {
            return Err(Error::conflict(format!(
                "Several names documents ({SUFFIX}) exist in Analyst. Keep exactly one; nothing was saved"
            )));
        }
        Status::Malformed => {
            return Err(Error::conflict(format!(
                "{} is malformed or uses an unsupported version. It stays unchanged; nothing was saved",
                located
                    .file
                    .and_then(|file| file["name"].as_str())
                    .unwrap_or(FILE_NAME)
            )));
        }
        _ => {}
    }
    let current = located
        .names
        .get(&sha)
        .and_then(|module| module.get(&function))
        .cloned()
        .unwrap_or_default();
    let generation = library["generation"].as_u64().unwrap_or(0);
    let result = |name: &str, changed: bool, generation: u64, file: &str| {
        json!({"schema":"wasm-function-name-result-v1","key":key(&sha, function),
            "sha256":sha,"function":function,"name":(!name.is_empty()).then_some(name),
            "previous_name":(!current.is_empty()).then_some(current.as_str()),
            "changed":changed,"library_generation":generation,"file":file})
    };
    if let Some(expected) = &expected
        && *expected != current
    {
        return Err(Error::conflict(if current.is_empty() {
            "The saved name was cleared elsewhere; nothing was saved. Read it again before renaming"
                .to_owned()
        } else {
            format!(
                "The saved name is now \"{current}\"; nothing was saved. Pass it as expected_name to replace it"
            )
        }));
    }
    let file_name = located
        .file
        .and_then(|file| file["name"].as_str())
        .unwrap_or(FILE_NAME)
        .to_owned();
    if current == name {
        return Ok(result(&name, false, generation, &file_name));
    }
    let mut document = located.document.unwrap_or_else(|| {
        json!({"document_kind":KIND,"contract_version":1,"scope":"local-analyst-library",
            "requests":[],"artifacts":[],"vm_programs":[]})
    });
    let mut modules: Vec<Value> = document
        .as_object_mut()
        .and_then(|object| object.remove("wasm_modules"))
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let at = modules.iter().position(|module| module["sha256"] == sha);
    match (at, name.is_empty()) {
        (Some(at), _) => {
            let functions = modules[at]["functions"].as_array_mut().unwrap();
            let entry = functions.iter().position(|e| e["function"] == function);
            match (entry, name.is_empty()) {
                (Some(entry), true) => {
                    functions.remove(entry);
                }
                (Some(entry), false) => functions[entry]["name"] = json!(name),
                (None, false) => functions.push(json!({"function":function,"name":name})),
                (None, true) => {}
            }
            if functions.is_empty() {
                modules.remove(at);
            }
        }
        (None, false) => {
            modules.push(json!({"sha256":sha,"functions":[{"function":function,"name":name}]}))
        }
        (None, true) => {}
    }
    // A library without Wasm names stays a version 1 document, which builds
    // that predate Wasm names keep reading.
    let object = document.as_object_mut().unwrap();
    if modules.is_empty() {
        object.insert("contract_version".into(), json!(1));
    } else {
        object.insert("contract_version".into(), json!(2));
        object.insert("wasm_modules".into(), Value::Array(modules));
    }
    if validate(&document).is_none() {
        return Err(Error::bad(format!(
            "The names document holds at most {MAX_NAMES} names, {MAX_GROUPS} Wasm modules and {} KiB, the Analyst file limit. Clear or shorten a name first; nothing was saved",
            MAX_DOCUMENT_BYTES / 1024
        ))
        .with_code(Code::ResourceLimit));
    }
    let content = serde_json::to_string(&document)?;
    let mut files: Vec<Value> = library["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|file| located.file.is_none_or(|own| own["id"] != file["id"]))
        .map(projection)
        .collect();
    match located.file {
        Some(own) => {
            let mut own = projection(own);
            own["content"] = json!(content);
            files.push(own);
        }
        None => {
            let folded: String = FILE_NAME.case_fold().collect();
            if library["folders"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|folder| {
                    folder["parent_id"] == 1
                        && folder["name"]
                            .as_str()
                            .is_some_and(|n| n.case_fold().collect::<String>() == folded)
                })
            {
                return Err(Error::conflict(format!(
                    "An Analyst folder is named {FILE_NAME}. Rename it before saving names"
                )));
            }
            let id = files
                .iter()
                .filter_map(|file| file["id"].as_u64())
                .max()
                .unwrap_or(0)
                + 1;
            files.push(
                json!({"id":id,"folder_id":1,"name":FILE_NAME,"kind":"scratchpad",
                "language":"json","content":content}),
            );
        }
    }
    between();
    let replacement = json!({"action":"replace_local_analyst_workspace",
        "expected_generation":generation,"folders":library["folders"],"files":files});
    let saved = store.replace(&replacement)?;
    Ok(result(
        &name,
        true,
        saved["generation"].as_u64().unwrap_or(generation + 1),
        &file_name,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Kind;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn doc(modules: Value) -> Value {
        json!({"document_kind":KIND,"contract_version":2,"scope":"local-analyst-library",
            "requests":[],"artifacts":[],"vm_programs":[],"wasm_modules":modules})
    }
    fn library(content: &str) -> Value {
        json!({"generation":3,"files":[{"id":1,"folder_id":1,"name":FILE_NAME,"kind":"scratchpad","language":"json","content":content}]})
    }

    #[test]
    fn version_two_names_follow_sha_and_index() {
        let value =
            doc(json!([{"sha256":SHA,"functions":[{"function":5,"name":"encode_payload"}]}]));
        let names = names_of(&library(&value.to_string()));
        assert_eq!(names.status, Status::Ready);
        assert_eq!(names.function(SHA, 5), Some("encode_payload"));
        assert_eq!(names.function(SHA, 4), None);
        assert_eq!(key(SHA, 5), format!("wasm-function:{SHA}:5"));
        let member = names.module_member(SHA, 5);
        assert_eq!(
            member["functions"],
            json!([]),
            "Index 5 is outside a 5-function module"
        );
        assert_eq!(
            names.module_member(SHA, 6)["functions"],
            json!([[5, "encode_payload"]])
        );
    }

    #[test]
    fn version_one_still_reads_and_refusals_match_the_ui() {
        let v1 = json!({"document_kind":KIND,"contract_version":1,"scope":"local-analyst-library","requests":[],"artifacts":[],"vm_programs":[]});
        assert_eq!(names_of(&library(&v1.to_string())).status, Status::Ready);
        let mut with_modules = v1.clone();
        with_modules["wasm_modules"] = json!([]);
        assert_eq!(
            names_of(&library(&with_modules.to_string())).status,
            Status::Malformed,
            "Version 1 is closed: wasm_modules needs version 2"
        );
        for bad in [
            doc(json!([{"sha256":SHA,"functions":[]}])),
            doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":" x"}]}])),
            doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":"a\u{202e}b"}]}])),
            doc(json!([{"sha256":SHA,"functions":[{"function":4294967296u64,"name":"x"}]}])),
            doc(
                json!([{"sha256":SHA,"functions":[{"function":1,"name":"x"},{"function":1,"name":"y"}]}]),
            ),
            doc(
                json!([{"sha256":SHA,"functions":[{"function":1,"name":"x"}]},{"sha256":SHA,"functions":[{"function":2,"name":"y"}]}]),
            ),
            doc(json!([{"sha256":SHA.to_uppercase(),"functions":[{"function":1,"name":"x"}]}])),
            doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":"x","note":"n"}]}])),
            doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":"x".repeat(81)}]}])),
        ] {
            assert_eq!(
                names_of(&library(&bad.to_string())).status,
                Status::Malformed,
                "{bad}"
            );
        }
        let duplicate = doc(json!([]))
            .to_string()
            .replace("\"requests\"", "\"requests\":[],\"r\\u0065quests\"");
        assert_eq!(
            names_of(&library(&duplicate)).status,
            Status::Malformed,
            "Escaped duplicates are refused"
        );
        let names = names_of(&json!({"generation":1,"files":[]}));
        assert_eq!(names.status, Status::None);
        let two = json!({"generation":1,"files":[
            {"id":1,"folder_id":1,"name":"a.reb-names.json","kind":"scratchpad","language":"json","content":"{}"},
            {"id":2,"folder_id":1,"name":"b.reb-names.json","kind":"scratchpad","language":"json","content":"{}"}]});
        assert_eq!(names_of(&two).status, Status::Ambiguous);
    }

    // Shared with tools/check-wasm-function-names.mjs: a fraction or exponent
    // is refused even where it equals an integer, as the UI refuses it.
    #[test]
    fn numbers_are_integers_written_as_integers() {
        let text =
            doc(json!([{"sha256":SHA,"functions":[{"function":5,"name":"encode_payload"}]}]))
                .to_string();
        assert_eq!(names_of(&library(&text)).status, Status::Ready);
        for (from, to) in [
            ("\"function\":5", "\"function\":5.0"),
            ("\"contract_version\":2", "\"contract_version\":2.0"),
            ("\"function\":5", "\"function\":5e0"),
        ] {
            assert!(text.contains(from), "{from}");
            assert_eq!(
                names_of(&library(&text.replace(from, to))).status,
                Status::Malformed,
                "{to}"
            );
        }
        let digits = text.replace("encode_payload", "1.5e3 is text");
        assert_eq!(
            names_of(&library(&digits)).status,
            Status::Ready,
            "Digits inside strings are text"
        );
    }

    #[test]
    fn the_count_and_byte_bounds_are_exact() {
        let functions: Vec<Value> = (0..500).map(|i| json!({"function":i,"name":"n"})).collect();
        assert!(validate(&doc(json!([{"sha256":SHA,"functions":functions}]))).is_some());
        let functions: Vec<Value> = (0..501).map(|i| json!({"function":i,"name":"n"})).collect();
        assert!(validate(&doc(json!([{"sha256":SHA,"functions":functions}]))).is_none());
        let functions: Vec<Value> = (0..400)
            .map(|i| json!({"function":i,"name":"n".repeat(80)}))
            .collect();
        assert!(
            validate(&doc(json!([{"sha256":SHA,"functions":functions}]))).is_none(),
            "Over 32 KiB"
        );
    }

    #[test]
    fn joins_add_beside_and_never_replace() {
        let value =
            doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":"encode_payload"}]}]));
        let names = names_of(&library(&value.to_string()));
        let mut inspection = json!({"sha256":SHA,"imported_functions":1,"defined_functions":1,"rows":[
            {"kind":"function","function_index":1,"text":"func 1 (type 0)"},
            {"kind":"instruction","function_index":1,"text":"call"},
            {"kind":"instruction","function_index":0,"target_function_index":1,"text":"call"}]});
        annotate_inspection(&mut inspection, &names);
        assert_eq!(inspection["rows"][0]["analyst_name"], "encode_payload");
        assert_eq!(inspection["rows"][0]["text"], "func 1 (type 0)");
        assert!(
            inspection["rows"][1].get("analyst_name").is_none(),
            "Body rows stay unnamed"
        );
        assert_eq!(
            inspection["rows"][2]["target_analyst_name"],
            "encode_payload"
        );
        assert_eq!(
            inspection["analyst_names"]["functions"],
            json!([[1, "encode_payload"]])
        );
        let text = append_members("{\"a\":1}".into(), &[("analyst_name", json!("x"))]);
        assert_eq!(text, "{\"a\":1,\"analyst_name\":\"x\"}");
        let mut stack = json!({"frames":[{"kind":"wasm","module_sha256":SHA,"function_index":1}],
            "task_segments":[{"frames":[{"kind":"wasm","module_sha256":SHA,"function_index":2}]}]});
        annotate_request_stack(&mut stack, &names);
        assert_eq!(stack["frames"][0]["analyst_name"], "encode_payload");
        assert!(
            stack["task_segments"][0]["frames"][0]
                .get("analyst_name")
                .is_none()
        );
        assert_eq!(stack["analyst_names"]["joined"], 1);
    }

    #[test]
    fn an_unrelated_name_leaves_the_flow_graph_unparsed() {
        let other = "b".repeat(64);
        let names = names_of(&library(
            &doc(json!([{"sha256":SHA,"functions":[{"function":1,"name":"encode_payload"}]}]))
                .to_string(),
        ));
        // Member order a reparse would sort: the bytes must come back as they were.
        let graph = format!(
            r#"{{"schema":"flow-graph-v1","nodes":[{{"kind":"wasm","sha256":"{other}","function_index":1,"id":0}}]}}"#
        );
        let out = annotate_flow_graph_bytes(graph.clone().into(), &names).unwrap();
        let out = std::str::from_utf8(&out).unwrap();
        assert!(out.starts_with(&graph[..graph.len() - 1]), "{out}");
        assert!(!out.contains("analyst_name\":\"encode_payload"));
        let named = graph.replace(&other, SHA);
        let out = annotate_flow_graph_bytes(named.into(), &names).unwrap();
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["nodes"][0]["analyst_name"], "encode_payload");
        assert_eq!(value["analyst_names"]["joined"], 1);
    }

    #[test]
    fn the_narrow_write_preserves_other_files_and_refuses_conflicts() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::new(root.path().join("analyst.json"), Kind::Analyst);
        let notes = json!({"action":"replace_local_analyst_workspace","expected_generation":0,
            "folders":[{"id":1,"name":"Analyst Workspace","parent_id":null}],
            "files":[{"id":7,"folder_id":1,"name":"notes.md","kind":"scratchpad","language":"markdown","content":"keep me"}]});
        store.replace(&notes).unwrap();
        let set = |name: &str, expected: Option<Value>| {
            let mut request =
                json!({"action":"set_wasm_function_name","sha256":SHA,"function":3,"name":name});
            if let Some(expected) = expected {
                request["expected_name"] = expected;
            }
            set_function_name(&store, &request)
        };
        let result = set("  encode_payload ", Some(Value::Null)).unwrap();
        assert_eq!(result["name"], "encode_payload");
        assert_eq!(result["changed"], true);
        let library = store.load().unwrap();
        assert_eq!(library["files"].as_array().unwrap().len(), 2);
        assert!(
            library["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["content"] == "keep me")
        );
        let names = names_of(&library);
        assert_eq!(names.function(SHA, 3), Some("encode_payload"));
        assert_eq!(set("encode_payload", None).unwrap()["changed"], false);
        let error = set("other", Some(Value::Null)).unwrap_err();
        assert_eq!(error.status, 409);
        assert!(set("bad\u{0007}", None).is_err());
        // A UI save landing between the read and the replace is not lost.
        let before = store.load().unwrap();
        let racing = set_function_name_with(
            &store,
            &json!({"action":"set_wasm_function_name","sha256":SHA,"function":4,"name":"agent"}),
            || {
                let library = store.load().unwrap();
                let mut files: Vec<Value> = library["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(projection)
                    .collect();
                files.push(json!({"id":99,"folder_id":1,"name":"ui.md","kind":"scratchpad","language":"markdown","content":"saved by the UI"}));
                store
                    .replace(&json!({"action":"replace_local_analyst_workspace",
                        "expected_generation":library["generation"],"folders":library["folders"],"files":files}))
                    .unwrap();
            },
        );
        assert_eq!(
            racing.unwrap_err().status,
            409,
            "The stale generation is refused"
        );
        let after = store.load().unwrap();
        assert_eq!(
            after["generation"],
            before["generation"].as_u64().unwrap() + 1,
            "Only the UI save landed"
        );
        assert!(
            after["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["content"] == "saved by the UI")
        );
        assert_eq!(
            names_of(&after).function(SHA, 4),
            None,
            "The agent write did not overwrite it"
        );
        let cleared = set("", Some(json!("encode_payload"))).unwrap();
        assert_eq!(cleared["name"], Value::Null);
        assert_eq!(cleared["previous_name"], "encode_payload");
        let library = store.load().unwrap();
        let file = library["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == FILE_NAME)
            .unwrap();
        let saved: Value = serde_json::from_str(file["content"].as_str().unwrap()).unwrap();
        assert_eq!(
            saved["contract_version"], 1,
            "No Wasm names left: version 1 again"
        );
        assert!(saved.get("wasm_modules").is_none());
    }
}
