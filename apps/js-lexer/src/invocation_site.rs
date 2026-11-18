//! The function index behind native JavaScript invocation site queries
//! (protocol/native-js-invocation-v1.md), and the query over it. The
//! deobfuscation worker builds the index from one syntax tree of the whole
//! source, so text inside a string, template or comment never binds a name.
//! The worker and the Origin Trace backend answer name and position queries
//! from the same index with this code, so a backend that keeps the index of
//! a source answers its later queries without parsing it again. The index
//! holds byte offsets and syntax facts only; the backend checks every offset
//! an answer reports against the verified artifact text.
use serde::{Deserialize, Serialize};

pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_SEGMENTS: usize = 8;
pub const MAX_CANDIDATES: usize = 32;
/// In a document's main world these three name the same global object, and
/// invocation capture never arms a worker isolate, where `self` would differ.
const GLOBAL_OBJECTS: [&str; 3] = ["window", "self", "globalThis"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Function,
    Arrow,
    Method,
    Getter,
    Setter,
    Generator,
    Constructor,
}

/// Why V8 would not arm a function at its anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unsupported {
    ArrowBareParameter,
    AsyncArrow,
    Generator,
    ClassConstructor,
    NoParameterList,
}

/// One name a definition binds. `global` paths are rooted at the global
/// object and keep no global-object prefix; the others are rooted at an
/// identifier or, for an unbound object literal, nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub global: bool,
    pub segments: Vec<String>,
    /// The name as written, as display text.
    pub text: String,
}

impl Binding {
    /// The binding of `segments` as written, such as `window.api.run`.
    pub fn new(segments: Vec<String>, text: String) -> Option<Self> {
        if segments.is_empty() || segments.len() > MAX_SEGMENTS + 1 {
            return None;
        }
        let global = segments.len() > 1 && GLOBAL_OBJECTS.contains(&segments[0].as_str());
        let segments = if global {
            segments[1..].to_vec()
        } else {
            segments
        };
        Some(Self {
            global,
            segments,
            text,
        })
    }
    fn matches(&self, name: &Name) -> bool {
        self.segments == name.segments && (!name.global || self.global)
    }
}

/// One function definition of the source, in document order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Function {
    pub kind: Kind,
    /// The `(` that opens the parameter list, which is V8's start position
    /// for every kind V8 can arm at a `(`. Null for a bare-parameter arrow.
    pub anchor_byte: Option<u32>,
    pub start: u32,
    pub end: u32,
    /// Where a position starts selecting it: its own start, or the head that
    /// binds it (`window.hsw=`, `var hsw=`, `hsw:`).
    pub definition_start: u32,
    pub unsupported: Option<Unsupported>,
    /// Every name it binds, the one it is listed under first.
    pub bindings: Vec<Binding>,
}

/// A class field initializer or static block, which V8 runs in a function
/// it synthesizes, so a position in it names no definition of the source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Initializer {
    pub start: u32,
    pub end: u32,
    /// The first byte V8's function covers: a field's value, or the block.
    pub from: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Index {
    pub source_bytes: usize,
    /// In document order, an enclosing definition before those it encloses.
    pub functions: Vec<Function>,
    pub initializers: Vec<Initializer>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Candidate {
    pub kind: Kind,
    pub anchor_byte: Option<u32>,
    pub start: u32,
    pub end: u32,
    /// The name this definition binds, as written, when it binds one.
    pub binding: Option<String>,
    pub unsupported: Option<Unsupported>,
}

impl Function {
    fn candidate(&self, binding: Option<&str>) -> Candidate {
        Candidate {
            kind: self.kind,
            anchor_byte: self.anchor_byte,
            start: self.start,
            end: self.end,
            binding: binding.map(str::to_owned),
            unsupported: self.unsupported,
        }
    }
}

/// The answer to one query, `reb-invocation-site-worker-v1`.
#[derive(Debug, Serialize)]
pub struct Response {
    schema: &'static str,
    pub ok: bool,
    pub error: Option<String>,
    pub source_bytes: usize,
    pub matches: Vec<Candidate>,
    pub match_count: usize,
    /// With no exact match: definitions whose name ends in the same segment.
    pub related: Vec<Candidate>,
    pub related_count: usize,
    pub selected: Option<Candidate>,
    /// Why a position names no function, when it does not.
    pub reason: Option<&'static str>,
}

fn response(source_bytes: usize) -> Response {
    Response {
        schema: "reb-invocation-site-worker-v1",
        ok: true,
        error: None,
        source_bytes,
        matches: Vec::new(),
        match_count: 0,
        related: Vec::new(),
        related_count: 0,
        selected: None,
        reason: None,
    }
}

pub fn invalid(message: &str, source_bytes: usize) -> Response {
    Response {
        ok: false,
        error: Some(message.to_owned()),
        ..response(source_bytes)
    }
}

/// A requested name: an optional global-object prefix and 1 to 8 segments.
pub struct Name {
    global: bool,
    segments: Vec<String>,
}

pub fn segment(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '$' || first == '_' || first.is_alphabetic())
        && chars.all(|c| c == '$' || c == '_' || c.is_alphanumeric())
}

pub fn parse_name(value: &str) -> Option<Name> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES {
        return None;
    }
    let mut segments = value.split('.').map(str::to_owned).collect::<Vec<_>>();
    if segments.len() > MAX_SEGMENTS || !segments.iter().all(|part| segment(part)) {
        return None;
    }
    let global = segments.len() > 1 && GLOBAL_OBJECTS.contains(&segments[0].as_str());
    if global {
        segments.remove(0);
    }
    Some(Name { global, segments })
}

pub enum Query<'a> {
    Name(&'a Name),
    /// A byte offset that names a character of the indexed source.
    Offset(u32),
}

impl Index {
    pub fn answer(&self, query: Query) -> Response {
        let mut result = response(self.source_bytes);
        match query {
            Query::Name(name) => {
                let last = name.segments.last();
                for function in &self.functions {
                    if let Some(binding) = function.bindings.iter().find(|b| b.matches(name)) {
                        result.match_count += 1;
                        if result.matches.len() < MAX_CANDIDATES {
                            result.matches.push(function.candidate(Some(&binding.text)));
                        }
                    } else if let Some(binding) = function
                        .bindings
                        .iter()
                        .find(|binding| binding.segments.last() == last)
                    {
                        result.related_count += 1;
                        if result.related.len() < MAX_CANDIDATES {
                            result.related.push(function.candidate(Some(&binding.text)));
                        }
                    }
                }
            }
            Query::Offset(offset) => {
                // The innermost definition whose head or body holds the
                // position; the first in document order among equals.
                let mut best: Option<&Function> = None;
                for function in &self.functions {
                    let width = function.end.saturating_sub(function.definition_start);
                    if function.definition_start <= offset
                        && offset < function.end
                        && best.is_none_or(|b| width < b.end.saturating_sub(b.definition_start))
                    {
                        best = Some(function);
                    }
                }
                // A class field initializer or static block between the
                // position and the selected definition's body is a function
                // V8 synthesizes. One that encloses the body is outside it.
                if self.initializers.iter().any(|initializer| {
                    initializer.from <= offset
                        && offset < initializer.end
                        && !best.is_some_and(|function| {
                            initializer.start <= function.start && initializer.end >= function.end
                        })
                }) {
                    result.reason = Some("class_initializer");
                    return result;
                }
                match best {
                    Some(function) => {
                        result.selected = Some(
                            function.candidate(function.bindings.first().map(|b| b.text.as_str())),
                        )
                    }
                    None => result.reason = Some("no_function"),
                }
            }
        }
        result
    }
}
