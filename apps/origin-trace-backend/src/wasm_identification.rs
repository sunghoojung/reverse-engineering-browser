//! Static library identification for one captured module: which toolchain
//! and runtime built it, which functions are well-known glue, runtime or libc
//! code, and where known cryptographic and encoding constants sit.
//!
//! Every conclusion lists the exact bytes it rests on (a section, an import,
//! an export, a name or a constant, each with its module byte offset) and a
//! confidence. Nothing is concluded from absence: a module without a
//! producers section is not "not Rust", it is unlabeled. Suggestions are
//! analyzer output kept apart from captured names and from analyst names, and
//! the module is never executed. Raw evidence is not changed.
use crate::{
    error::{Error, Result},
    wasm_constants::{self, ConstantSet, Encoding, Run, Width},
    wasm_graph,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::{
    BinaryReader, DataKind, Encoding as BinaryEncoding, ExternalKind, KnownCustom, Name, Operator,
    Parser, Payload, TypeRef,
};

/// The block graph's input budget: real modules are tens of MiB.
pub const MAX_BYTES: usize = wasm_graph::MAX_BYTES;
/// Inside the native helper's five-second process deadline, so a partial
/// report still reaches the app.
const DEADLINE: Duration = Duration::from_secs(4);
const MAX_CONCLUSIONS: usize = 32;
const MAX_EVIDENCE: usize = 8;
const MAX_PRODUCERS: usize = 16;
const MAX_FEATURES: usize = 32;
const MAX_CUSTOM_SECTIONS: usize = 32;
/// The longest list a page carries: producers, features and custom sections.
const MAX_LISTED: usize = 32;
const MAX_SUGGESTIONS_PER_FUNCTION: usize = 4;
/// Suggestions kept in one report. Each is one compact row; pages of them
/// are cut to the page byte budget.
const MAX_SUGGESTIONS: usize = 16_384;
pub const SUGGESTION_PAGE: usize = 1024;
/// Records read and kept from one module: the rest are counted. A module
/// can declare millions of names; labeling stops at the deadline anyway.
const MAX_STORED_RECORDS: usize = 65_536;
/// Data runs and candidate matches kept before merging and suppression.
/// A table repeated across a whole segment costs a count past these.
const MAX_RUNS: usize = 8192;
const MAX_CANDIDATES: usize = 512;
const MAX_MATCHES: usize = 64;
const MAX_REFERENCES: usize = 4;
const MAX_SITES: usize = 4;
const MAX_MATCH_SEGMENTS: usize = 8;
/// Bytes of a data match returned as `hex`. They are captured content, which
/// `--omit-content` drops; the match identity is the offsets and counts.
const MATCH_PREVIEW_BYTES: usize = 64;
/// One page of the report, pretty-printed, stays inside the 131,072-byte MCP
/// inline limit with room for the artifact identity. Everything but the
/// suggestions is held to `FIXED_BYTES`, trimmed further when it would not
/// fit, and suggestion rows fill the rest.
const PAGE_BYTES: usize = 126_000;
const FIXED_BYTES: usize = 96_000;
/// Captured text inside a label stays short enough that a read-only result,
/// which omits strings over 160 characters, keeps the whole label.
const LABEL_TEXT_BYTES: usize = 96;
const URL_BYTES: usize = 512;

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

/// Escaped, single-line, bounded text of at most `limit` bytes.
fn bounded(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for character in text.chars().flat_map(char::escape_debug) {
        if out.len() + character.len_utf8() > limit {
            out.push_str("...");
            break;
        }
        out.push(character);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

struct Toolchain {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
}

#[rustfmt::skip]
const TOOLCHAINS: [Toolchain; 20] = [
    Toolchain { id: "rust", label: "Rust", kind: "language" },
    Toolchain { id: "c_cpp", label: "C or C++", kind: "language" },
    Toolchain { id: "clang", label: "clang (LLVM)", kind: "compiler" },
    Toolchain { id: "llvm_wasm_ld", label: "LLVM wasm-ld", kind: "linker" },
    Toolchain { id: "llvm_object", label: "Unlinked LLVM object file", kind: "linker" },
    Toolchain { id: "emscripten", label: "Emscripten", kind: "runtime" },
    Toolchain { id: "wasm_bindgen", label: "wasm-bindgen", kind: "bindings" },
    Toolchain { id: "wasi", label: "WASI preview 1", kind: "system_interface" },
    Toolchain { id: "wasi_libc", label: "wasi-libc", kind: "runtime" },
    Toolchain { id: "go", label: "Go (js/wasm ABI, gc or TinyGo)", kind: "language" },
    Toolchain { id: "tinygo", label: "TinyGo", kind: "compiler" },
    Toolchain { id: "assemblyscript", label: "AssemblyScript", kind: "language" },
    Toolchain { id: "dotnet", label: ".NET (Mono WebAssembly runtime)", kind: "runtime" },
    Toolchain { id: "kotlin", label: "Kotlin/Wasm", kind: "language" },
    Toolchain { id: "dart", label: "Dart (dart2wasm)", kind: "language" },
    Toolchain { id: "swift", label: "Swift (SwiftWasm)", kind: "language" },
    Toolchain { id: "zig", label: "Zig", kind: "language" },
    Toolchain { id: "binaryen", label: "Binaryen (wasm-opt)", kind: "optimizer" },
    Toolchain { id: "asyncify", label: "Binaryen Asyncify", kind: "runtime" },
    Toolchain { id: "component_model", label: "WebAssembly component tooling (wit-bindgen, wit-component)", kind: "bindings" },
];

/// One piece of evidence: what was read and where.
#[derive(Clone)]
struct Evidence {
    source: &'static str,
    byte_offset: usize,
    detail: String,
    function_index: Option<u32>,
}

impl Evidence {
    fn json(&self) -> Value {
        json!({"record":self.source,"byte_offset":self.byte_offset,"detail":self.detail,
            "function_index":self.function_index})
    }
}

/// One toolchain's strongest confidence, the evidence kept with its own
/// strength, and the count of every piece of evidence seen.
type Conclusion = (Confidence, Vec<(Confidence, Evidence)>, usize);

#[derive(Default)]
struct Conclusions {
    by_id: BTreeMap<&'static str, Conclusion>,
}

impl Conclusions {
    fn add(&mut self, id: &'static str, confidence: Confidence, evidence: Evidence) {
        let entry = self
            .by_id
            .entry(id)
            .or_insert_with(|| (confidence, Vec::new(), 0));
        entry.0 = entry.0.max(confidence);
        entry.2 += 1;
        // Strong evidence displaces weak evidence once the list is full, so
        // a capped list never hides the reason for the confidence it reports.
        if entry.1.len() < MAX_EVIDENCE {
            entry.1.push((confidence, evidence));
        } else if let Some(weakest) = entry
            .1
            .iter()
            .enumerate()
            .filter(|(_, (kept, _))| *kept < confidence)
            .min_by_key(|(_, (kept, _))| *kept)
            .map(|(index, _)| index)
        {
            entry.1[weakest] = (confidence, evidence);
        }
    }
}

/// A suggested label for one function.
struct Suggestion {
    function: u32,
    label: String,
    category: &'static str,
    library: &'static str,
    confidence: Confidence,
    source: &'static str,
    byte_offset: usize,
}

struct Import<'a> {
    module: &'a str,
    name: &'a str,
    offset: usize,
    function: Option<u32>,
}

struct Export<'a> {
    name: &'a str,
    kind: ExternalKind,
    index: u32,
    offset: usize,
}

struct Segment<'a> {
    index: u32,
    data: &'a [u8],
    data_offset: usize,
    address: Option<u64>,
}

struct Custom<'a> {
    name: &'a str,
    data: &'a [u8],
    data_offset: usize,
    end: usize,
    known: Option<KnownCustom<'a>>,
}

/// Omissions in first-seen order, each once with how often it happened, so a
/// module of 65,536 malformed sections yields one line, not 65,536.
#[derive(Clone, Default)]
struct Omissions(Vec<(String, usize)>);

impl Omissions {
    fn push(&mut self, text: impl Into<String>) {
        let text = text.into();
        match self.0.iter_mut().find(|(known, _)| *known == text) {
            Some((_, count)) => *count += 1,
            None => self.0.push((text, 1)),
        }
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn render(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|(text, count)| match count {
                1 => text.clone(),
                count => format!("{text} ({count} times)"),
            })
            .collect()
    }
}

struct Module<'a> {
    imports: Vec<Import<'a>>,
    exports: Vec<Export<'a>>,
    names: Vec<(u32, &'a str, usize)>,
    /// Every record read, including the ones past `MAX_STORED_RECORDS`.
    import_count: usize,
    export_count: usize,
    name_count: usize,
    module_name: Option<(&'a str, usize)>,
    name_section: Option<usize>,
    customs: Vec<Custom<'a>>,
    defined_functions: usize,
    imported_functions: u32,
    segments: Vec<Segment<'a>>,
    segment_count: usize,
    /// The deadline passed while sections were still being read.
    stopped: bool,
    /// Custom sections read, including the ones past `MAX_STORED_RECORDS`.
    custom_count: usize,
    omissions: Omissions,
}

/// Records past the storage limit are counted; storing stops. The first
/// time a kind reaches it, the omission says so.
fn keep<T>(list: &mut Vec<T>, count: &mut usize, item: T, kind: &str, omissions: &mut Omissions) {
    *count += 1;
    if list.len() < MAX_STORED_RECORDS {
        list.push(item);
    } else if list.len() == MAX_STORED_RECORDS && *count == MAX_STORED_RECORDS + 1 {
        omissions.push(format!(
            "{kind} limit of {MAX_STORED_RECORDS} reached; later ones are counted, not read."
        ));
    }
}

fn read_module(bytes: &[u8], deadline: Instant) -> Result<Module<'_>> {
    if bytes.is_empty() {
        return Err(Error::protocol("The WASM module is empty"));
    }
    let mut module = Module {
        imports: Vec::new(),
        exports: Vec::new(),
        names: Vec::new(),
        import_count: 0,
        export_count: 0,
        name_count: 0,
        module_name: None,
        name_section: None,
        customs: Vec::new(),
        defined_functions: 0,
        imported_functions: 0,
        segments: Vec::new(),
        segment_count: 0,
        stopped: false,
        custom_count: 0,
        omissions: Omissions::default(),
    };
    let mut ended = false;
    let mut read = 0usize;
    // Polled every 4096 records of any kind, so a million tiny records
    // cannot outlast the report's one deadline.
    let mut expired = || {
        read += 1;
        read.is_multiple_of(4096) && Instant::now() > deadline
    };
    'payloads: for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(bad)? {
            Payload::Version {
                num: 1,
                encoding: BinaryEncoding::Module,
                ..
            } => {}
            Payload::Version { .. } => {
                return Err(Error::protocol(
                    "Only WASM core module version 1 is supported",
                ));
            }
            Payload::ImportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    if expired() {
                        module.stopped = true;
                        break 'payloads;
                    }
                    let (offset, import) = entry.map_err(bad)?;
                    let function = if matches!(import.ty, TypeRef::Func(_)) {
                        let index = module.imported_functions;
                        module.imported_functions += 1;
                        Some(index)
                    } else {
                        None
                    };
                    let item = Import {
                        module: import.module,
                        name: import.name,
                        offset,
                        function,
                    };
                    keep(
                        &mut module.imports,
                        &mut module.import_count,
                        item,
                        "Import",
                        &mut module.omissions,
                    );
                }
            }
            Payload::ExportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    if expired() {
                        module.stopped = true;
                        break 'payloads;
                    }
                    let (offset, export) = entry.map_err(bad)?;
                    let item = Export {
                        name: export.name,
                        kind: export.kind,
                        index: export.index,
                        offset,
                    };
                    keep(
                        &mut module.exports,
                        &mut module.export_count,
                        item,
                        "Export",
                        &mut module.omissions,
                    );
                }
            }
            // Bodies are read again by the immediate scan, so none is kept.
            Payload::CodeSectionEntry(_) => {
                module.defined_functions += 1;
                if expired() {
                    module.stopped = true;
                    break 'payloads;
                }
            }
            Payload::DataSection(reader) => {
                for entry in reader.into_iter() {
                    if expired() {
                        module.stopped = true;
                        break 'payloads;
                    }
                    let entry = entry.map_err(bad)?;
                    let address = match &entry.kind {
                        DataKind::Active { offset_expr, .. } => {
                            match offset_expr.get_operators_reader().read() {
                                Ok(Operator::I32Const { value }) => Some(u64::from(value as u32)),
                                Ok(Operator::I64Const { value }) => Some(value as u64),
                                _ => None,
                            }
                        }
                        DataKind::Passive => None,
                    };
                    let item = Segment {
                        index: module.segment_count as u32,
                        data: entry.data,
                        data_offset: entry.range.end - entry.data.len(),
                        address,
                    };
                    keep(
                        &mut module.segments,
                        &mut module.segment_count,
                        item,
                        "Data segment",
                        &mut module.omissions,
                    );
                }
            }
            Payload::CustomSection(reader) => {
                let known = reader.as_known();
                if let KnownCustom::Name(section) = &known {
                    module.name_section = Some(reader.data_offset());
                    for subsection in section.clone() {
                        match subsection {
                            Ok(Name::Module { name, name_range }) => {
                                module.module_name = Some((name, name_range.start));
                            }
                            Ok(Name::Function(map)) => {
                                for naming in map.into_iter_with_offsets() {
                                    if expired() {
                                        module.stopped = true;
                                        break 'payloads;
                                    }
                                    match naming {
                                        Ok((offset, naming)) => {
                                            let item = (naming.index, naming.name, offset);
                                            keep(
                                                &mut module.names,
                                                &mut module.name_count,
                                                item,
                                                "Name",
                                                &mut module.omissions,
                                            );
                                        }
                                        Err(_) => {
                                            module.omissions.push(
                                                "The name section's function names are malformed; later names were not read.",
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            // The name section is advisory: a malformed one
                            // never fails a report built from the rest.
                            Err(_) => {
                                module.omissions.push(
                                    "The name section is malformed; later subsections were not read.",
                                );
                                break;
                            }
                        }
                    }
                }
                if expired() {
                    module.stopped = true;
                    break 'payloads;
                }
                let item = Custom {
                    name: reader.name(),
                    data: reader.data(),
                    data_offset: reader.data_offset(),
                    end: reader.range().end,
                    known: match known {
                        KnownCustom::Producers(_) => Some(known),
                        _ => None,
                    },
                };
                keep(
                    &mut module.customs,
                    &mut module.custom_count,
                    item,
                    "Custom section",
                    &mut module.omissions,
                );
            }
            Payload::End(_) => ended = true,
            _ => {}
        }
    }
    if module.stopped {
        module.omissions.push(
            "Identification deadline reached while reading sections; later records and sections were not read, and counts cover what was read.",
        );
    } else if !ended {
        module
            .omissions
            .push("Module traversal stopped before its end.");
    }
    Ok(module)
}

/// Producers names the toolchain declared, mapped to the conclusions they
/// support. A name this table does not know stays in the producers list.
fn producer_toolchain(field: &str, name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    match field {
        "language" => match name.as_str() {
            "rust" => Some("rust"),
            "assemblyscript" => Some("assemblyscript"),
            "go" => Some("go"),
            "tinygo" => Some("tinygo"),
            "zig" => Some("zig"),
            "swift" => Some("swift"),
            "kotlin" => Some("kotlin"),
            "dart" => Some("dart"),
            text if text == "c"
                || text.starts_with("c++")
                || text.starts_with("c8")
                || text.starts_with("c9")
                || text.starts_with("c1")
                || text.starts_with("c2") =>
            {
                Some("c_cpp")
            }
            _ => None,
        },
        "processed-by" => match name.as_str() {
            "rustc" => Some("rust"),
            "clang" => Some("clang"),
            "wasm-bindgen" => Some("wasm_bindgen"),
            "wasm-opt" | "binaryen" => Some("binaryen"),
            "emscripten" => Some("emscripten"),
            "tinygo" => Some("tinygo"),
            "lld" | "wasm-ld" => Some("llvm_wasm_ld"),
            "swiftc" => Some("swift"),
            "dart2wasm" => Some("dart"),
            "kotlin" => Some("kotlin"),
            "assemblyscript" => Some("assemblyscript"),
            "go" => Some("go"),
            text if text.starts_with("wit-component") || text.starts_with("wit-bindgen") => {
                Some("component_model")
            }
            _ => None,
        },
        "sdk" => (name == "emscripten").then_some("emscripten"),
        _ => None,
    }
}

const RUST_CRATES: [&str; 18] = [
    "core",
    "alloc",
    "std",
    "compiler_builtins",
    "dlmalloc",
    "wee_alloc",
    "hashbrown",
    "wasm_bindgen",
    "js_sys",
    "web_sys",
    "serde",
    "serde_json",
    "getrandom",
    "rand",
    "rand_core",
    "console_error_panic_hook",
    "once_cell",
    "log",
];

/// Segments of a legacy-mangled name (`_ZN...E`) that ends at its `E`. An
/// Itanium function name carries parameter types after the `E`
/// (`_ZN4core6Engine4stepEv`), which no Rust legacy symbol does, so such a
/// name is not read as one.
fn mangled_segments(name: &str) -> Option<Vec<&str>> {
    let mut rest = name
        .strip_prefix("_ZN")
        .or_else(|| name.strip_prefix("__ZN"))?;
    let mut segments = Vec::new();
    loop {
        if rest == "E" {
            return (!segments.is_empty()).then_some(segments);
        }
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || segments.len() >= 64 {
            return None;
        }
        let length: usize = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        if rest.len() < length || !rest.is_char_boundary(length) {
            return None;
        }
        segments.push(&rest[..length]);
        rest = &rest[length..];
    }
}

fn rust_hash(segment: &str) -> bool {
    segment.len() == 17
        && segment.starts_with('h')
        && segment[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The crate a Rust symbol belongs to, from its legacy mangling or its
/// demangled path, and whether the symbol is certainly Rust. A mangled name
/// counts only with its `17h<hash>` segment: a C++ namespace that happens to
/// be called `core` or `log` names no crate.
///
/// A legacy name may carry the `.llvm.<n>` suffix LLVM adds to promoted
/// local symbols. A v0 name (`_R...`) is always Rust. A demangled name
/// without its `::h<hash>` tail that has a parameter list, a `const`
/// qualifier or a destructor is C++ as wasm-ld writes it into the name
/// section, so it names no crate.
fn rust_crate(name: &str) -> (Option<&str>, bool) {
    let name = match name.rfind(".llvm.") {
        Some(at)
            if at + 6 < name.len()
                && name[at + 6..].bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            &name[..at]
        }
        _ => name,
    };
    if let Some(found) = v0_crate(name) {
        return (
            RUST_CRATES.iter().find(|known| **known == found).copied(),
            true,
        );
    }
    if let Some(segments) = mangled_segments(name) {
        if !segments.last().is_some_and(|last| rust_hash(last)) {
            return (None, false);
        }
        let first = segments[0]
            .trim_start_matches('_')
            .trim_start_matches("$LT$");
        let first = first.split("..").next().unwrap_or(first);
        let known = RUST_CRATES.iter().find(|known| **known == first).copied();
        return (known, true);
    }
    if name.starts_with("_Z") {
        return (None, false);
    }
    let trimmed = name
        .trim_start_matches(['<', '&'])
        .trim_start_matches("mut ");
    let crate_name = trimmed.split("::").next().unwrap_or("");
    let certain = name.rsplit("::").next().is_some_and(rust_hash) && name.contains("::");
    if !certain && (name.contains('(') || name.ends_with(" const") || name.contains('~')) {
        return (None, false);
    }
    let known = trimmed
        .contains("::")
        .then(|| {
            RUST_CRATES
                .iter()
                .find(|known| **known == crate_name)
                .copied()
        })
        .flatten();
    (known, certain)
}

/// The crate of a Rust v0 symbol: the identifier after the first crate root
/// `C` and its optional `s<base62>_` disambiguator. `_R` must be followed by
/// a path tag, so a C name such as `_ReadFile` is not read as one.
fn v0_crate(name: &str) -> Option<&str> {
    let rest = name
        .strip_prefix("_R")
        .or_else(|| name.strip_prefix("__R"))?;
    if !rest.starts_with(['C', 'N', 'M', 'X', 'Y', 'I', 'B']) {
        return None;
    }
    let mut at = rest.find('C')? + 1;
    if rest[at..].starts_with('s') {
        at += rest[at..].find('_')? + 1;
    }
    let digits = rest[at..].bytes().take_while(u8::is_ascii_digit).count();
    let length: usize = rest[at..at + digits].parse().ok()?;
    at += digits;
    if rest[at..].starts_with('_') {
        at += 1;
    }
    rest.get(at..at + length)
        .filter(|crate_name| !crate_name.is_empty())
}

/// Lowercased alphanumeric tokens, split at punctuation and at a lowercase
/// to uppercase step, so `sha256Update` and `crypto/sha256.block` both
/// yield `sha256`.
fn tokens(name: &str) -> Vec<String> {
    let source = mangled_segments(name).map_or_else(|| name.to_owned(), |parts| parts.join(" "));
    let mut out = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for character in source.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        current.push(character.to_ascii_lowercase());
        if out.len() >= 64 {
            break;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[rustfmt::skip]
const ALGORITHM_TOKENS: [(&str, &str, &str); 46] = [
    ("sha1", "SHA-1", "crypto"),
    ("sha224", "SHA-224", "crypto"),
    ("sha256", "SHA-256", "crypto"),
    ("sha384", "SHA-384", "crypto"),
    ("sha512", "SHA-512", "crypto"),
    ("sha2", "SHA-2", "crypto"),
    ("sha3", "SHA-3", "crypto"),
    ("keccak", "Keccak", "crypto"),
    ("md4", "MD4", "crypto"),
    ("md5", "MD5", "crypto"),
    ("ripemd160", "RIPEMD-160", "crypto"),
    ("aes", "AES", "crypto"),
    ("rijndael", "AES", "crypto"),
    ("chacha", "ChaCha", "crypto"),
    ("chacha20", "ChaCha20", "crypto"),
    ("salsa20", "Salsa20", "crypto"),
    ("poly1305", "Poly1305", "crypto"),
    ("blake2", "BLAKE2", "crypto"),
    ("blake2b", "BLAKE2b", "crypto"),
    ("blake2s", "BLAKE2s", "crypto"),
    ("blake3", "BLAKE3", "crypto"),
    ("hmac", "HMAC", "crypto"),
    ("pbkdf2", "PBKDF2", "crypto"),
    ("hkdf", "HKDF", "crypto"),
    ("argon2", "Argon2", "crypto"),
    ("scrypt", "scrypt", "crypto"),
    ("bcrypt", "bcrypt", "crypto"),
    ("curve25519", "Curve25519", "crypto"),
    ("x25519", "X25519", "crypto"),
    ("ed25519", "Ed25519", "crypto"),
    ("secp256k1", "secp256k1", "crypto"),
    ("p256", "P-256", "crypto"),
    ("rsa", "RSA", "crypto"),
    ("ecdsa", "ECDSA", "crypto"),
    ("ecdh", "ECDH", "crypto"),
    ("crc32", "CRC-32", "checksum"),
    ("crc32c", "CRC-32C", "checksum"),
    ("adler32", "Adler-32", "checksum"),
    ("siphash", "SipHash", "hash_mix"),
    ("murmur3", "MurmurHash3", "hash_mix"),
    ("murmurhash3", "MurmurHash3", "hash_mix"),
    ("xxhash", "xxHash", "hash_mix"),
    ("xxh3", "XXH3", "hash_mix"),
    ("fnv1a", "FNV-1a", "hash_mix"),
    ("base64", "Base64", "encoding"),
    ("hex", "hex encoding", "encoding"),
];

/// Exactly named runtime and library functions. The label never claims
/// more than the name: `malloc` is some C allocator, not a specific one.
#[rustfmt::skip]
const EXACT: [(&str, &str, &str, &str, Confidence); 74] = {
    use Confidence::{High, Medium};
    [
        ("__wbindgen_malloc", "wasm-bindgen allocator: malloc", "allocator", "wasm-bindgen", High),
        ("__wbindgen_realloc", "wasm-bindgen allocator: realloc", "allocator", "wasm-bindgen", High),
        ("__wbindgen_free", "wasm-bindgen allocator: free", "allocator", "wasm-bindgen", High),
        ("__wbindgen_exn_store", "wasm-bindgen exception store", "runtime", "wasm-bindgen", High),
        ("__wbindgen_add_to_stack_pointer", "wasm-bindgen shadow stack adjustment", "runtime", "wasm-bindgen", High),
        ("__wbindgen_start", "wasm-bindgen start function", "entry", "wasm-bindgen", High),
        ("__rust_alloc", "Rust global allocator: alloc", "allocator", "Rust", High),
        ("__rust_dealloc", "Rust global allocator: dealloc", "allocator", "Rust", High),
        ("__rust_realloc", "Rust global allocator: realloc", "allocator", "Rust", High),
        ("__rust_alloc_zeroed", "Rust global allocator: alloc_zeroed", "allocator", "Rust", High),
        ("__rg_alloc", "Rust allocator shim: alloc", "allocator", "Rust", High),
        ("__rg_dealloc", "Rust allocator shim: dealloc", "allocator", "Rust", High),
        ("__rg_realloc", "Rust allocator shim: realloc", "allocator", "Rust", High),
        ("__rg_alloc_zeroed", "Rust allocator shim: alloc_zeroed", "allocator", "Rust", High),
        ("rust_begin_unwind", "Rust panic handler", "runtime", "Rust", High),
        ("__rust_start_panic", "Rust panic start", "runtime", "Rust", High),
        ("malloc", "C allocator: malloc", "allocator", "libc", Medium),
        ("free", "C allocator: free", "allocator", "libc", Medium),
        ("calloc", "C allocator: calloc", "allocator", "libc", Medium),
        ("realloc", "C allocator: realloc", "allocator", "libc", Medium),
        ("aligned_alloc", "C allocator: aligned_alloc", "allocator", "libc", Medium),
        ("posix_memalign", "C allocator: posix_memalign", "allocator", "libc", Medium),
        ("memalign", "C allocator: memalign", "allocator", "libc", Medium),
        ("dlmalloc", "dlmalloc: malloc", "allocator", "dlmalloc", High),
        ("dlfree", "dlmalloc: free", "allocator", "dlmalloc", High),
        ("dlrealloc", "dlmalloc: realloc", "allocator", "dlmalloc", High),
        ("dlcalloc", "dlmalloc: calloc", "allocator", "dlmalloc", High),
        ("sbrk", "libc: sbrk heap growth", "allocator", "libc", Medium),
        ("memcpy", "libc: memcpy", "libc", "libc", Medium),
        ("memmove", "libc: memmove", "libc", "libc", Medium),
        ("memset", "libc: memset", "libc", "libc", Medium),
        ("memcmp", "libc: memcmp", "libc", "libc", Medium),
        ("bcmp", "libc: bcmp", "libc", "libc", Medium),
        ("strlen", "libc: strlen", "libc", "libc", Medium),
        ("strcmp", "libc: strcmp", "libc", "libc", Medium),
        ("strncmp", "libc: strncmp", "libc", "libc", Medium),
        ("strcpy", "libc: strcpy", "libc", "libc", Medium),
        ("strncpy", "libc: strncpy", "libc", "libc", Medium),
        ("strchr", "libc: strchr", "libc", "libc", Medium),
        ("strrchr", "libc: strrchr", "libc", "libc", Medium),
        ("strstr", "libc: strstr", "libc", "libc", Medium),
        ("strerror", "libc: strerror", "libc", "libc", Medium),
        ("printf", "libc stdio: printf", "libc", "libc", Medium),
        ("fprintf", "libc stdio: fprintf", "libc", "libc", Medium),
        ("snprintf", "libc stdio: snprintf", "libc", "libc", Medium),
        ("vfprintf", "libc stdio: vfprintf", "libc", "libc", Medium),
        ("vsnprintf", "libc stdio: vsnprintf", "libc", "libc", Medium),
        ("puts", "libc stdio: puts", "libc", "libc", Medium),
        ("fwrite", "libc stdio: fwrite", "libc", "libc", Medium),
        ("fflush", "libc stdio: fflush", "libc", "libc", Medium),
        ("abort", "libc: abort", "libc", "libc", Medium),
        ("exit", "libc: exit", "libc", "libc", Medium),
        ("__errno_location", "libc: errno location", "libc", "libc", Medium),
        ("qsort", "libc: qsort", "libc", "libc", Medium),
        ("_start", "WASI command entry (_start)", "entry", "WASI", Medium),
        ("_initialize", "WASI reactor initializer (_initialize)", "entry", "WASI", Medium),
        ("__wasm_call_ctors", "Static constructors (__wasm_call_ctors)", "entry", "LLVM", High),
        ("main", "C main entry", "entry", "libc", Medium),
        ("__main_argc_argv", "C main entry (argc, argv)", "entry", "libc", Medium),
        ("__main_void", "C main entry (no arguments)", "entry", "libc", Medium),
        ("__original_main", "C main entry (original)", "entry", "libc", Medium),
        ("stackSave", "Emscripten stack helper: stackSave", "runtime", "Emscripten", High),
        ("stackRestore", "Emscripten stack helper: stackRestore", "runtime", "Emscripten", High),
        ("stackAlloc", "Emscripten stack helper: stackAlloc", "runtime", "Emscripten", High),
        ("__cxa_allocate_exception", "C++ ABI: allocate exception", "runtime", "C++ ABI", Medium),
        ("__cxa_throw", "C++ ABI: throw", "runtime", "C++ ABI", Medium),
        ("__cxa_begin_catch", "C++ ABI: begin catch", "runtime", "C++ ABI", Medium),
        ("__cxa_end_catch", "C++ ABI: end catch", "runtime", "C++ ABI", Medium),
        ("__cxa_atexit", "C++ ABI: atexit", "runtime", "C++ ABI", Medium),
        ("__cxa_pure_virtual", "C++ ABI: pure virtual call", "runtime", "C++ ABI", Medium),
        ("_Znwm", "C++ operator new", "allocator", "C++ ABI", Medium),
        ("_Znwj", "C++ operator new", "allocator", "C++ ABI", Medium),
        ("_ZdlPv", "C++ operator delete", "allocator", "C++ ABI", Medium),
        ("go_scheduler", "TinyGo scheduler", "runtime", "TinyGo", High),
    ]
};

const ASSEMBLYSCRIPT_RUNTIME: [&str; 10] = [
    "__new",
    "__pin",
    "__unpin",
    "__collect",
    "__rtti_base",
    "__setArgumentsLength",
    "__alloc",
    "__retain",
    "__release",
    "__instanceof",
];

const LINKER_SYMBOLS: [&str; 14] = [
    "__wasm_call_ctors",
    "__heap_base",
    "__data_end",
    "__dso_handle",
    "__stack_pointer",
    "__indirect_function_table",
    "__wasm_apply_data_relocs",
    "__global_base",
    "__memory_base",
    "__table_base",
    "__stack_low",
    "__stack_high",
    "__heap_end",
    "__tls_base",
];

const GO_STD: [&str; 19] = [
    "fmt.",
    "strings.",
    "strconv.",
    "sync.",
    "sync/",
    "sort.",
    "errors.",
    "reflect.",
    "unicode/",
    "unicode.",
    "encoding/",
    "internal/",
    "math.",
    "math/",
    "os.",
    "time.",
    "io.",
    "bytes.",
    "bufio.",
];

/// What a wasm-bindgen import name calls in JavaScript: the name between
/// `__wbg_` and the trailing hash, or the whole rest when there is no hash.
fn bindgen_target(rest: &str) -> &str {
    if let Some((head, hash)) = rest.rsplit_once('_')
        && (8..=16).contains(&hash.len())
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !head.is_empty()
    {
        return head;
    }
    rest
}

/// What a suggestion says about a function: its category, the library it
/// belongs to and how strongly the cited record supports it.
#[derive(Clone, Copy)]
struct Kind(&'static str, &'static str, Confidence);

/// The record a suggestion or conclusion rests on.
struct Site<'a> {
    function: Option<u32>,
    source: &'static str,
    offset: usize,
    shown: &'a str,
}

/// A matched rule: the toolchain it supports, if any, and the label.
type Rule = (Option<(&'static str, Confidence)>, String, Kind);

fn tool(id: &'static str, confidence: Confidence) -> Option<(&'static str, Confidence)> {
    Some((id, confidence))
}

fn text(value: &str) -> String {
    bounded(value, LABEL_TEXT_BYTES)
}

struct Labeler<'a> {
    suggestions: Vec<Suggestion>,
    /// Hashes of the labels each function already has, so a function that
    /// is both exported and named under one name gets its label once.
    per_function: HashMap<u32, Vec<u64>>,
    /// Suggestions found past `MAX_SUGGESTIONS`, counted and not stored.
    dropped: usize,
    /// The producers section declares C or C++.
    cpp_declared: bool,
    conclusions: &'a mut Conclusions,
}

fn label_hash(label: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    hasher.finish()
}

impl Labeler<'_> {
    fn suggest(&mut self, site: &Site<'_>, label: String, kind: Kind) {
        let Some(function) = site.function else {
            return;
        };
        let hash = label_hash(&label);
        let labels = self.per_function.entry(function).or_default();
        if labels.len() >= MAX_SUGGESTIONS_PER_FUNCTION || labels.contains(&hash) {
            return;
        }
        labels.push(hash);
        if self.suggestions.len() >= MAX_SUGGESTIONS {
            self.dropped += 1;
            return;
        }
        self.suggestions.push(Suggestion {
            function,
            label,
            category: kind.0,
            library: kind.1,
            confidence: kind.2,
            source: site.source,
            byte_offset: site.offset,
        });
    }

    fn conclude(&mut self, site: &Site<'_>, id: &'static str, confidence: Confidence) {
        let evidence = Evidence {
            source: site.source,
            byte_offset: site.offset,
            detail: format!("{} {}", site.source, site.shown),
            function_index: site.function,
        };
        self.conclusions.add(id, confidence, evidence);
    }

    fn apply(&mut self, site: &Site<'_>, rule: Option<Rule>) {
        if let Some((toolchain, label, kind)) = rule {
            if let Some((id, confidence)) = toolchain {
                self.conclude(site, id, confidence);
            }
            if !label.is_empty() {
                self.suggest(site, label, kind);
            }
        }
    }

    /// Imports name their host module, which most toolchains fix.
    fn import(&mut self, import: &Import<'_>) {
        use Confidence::{High, Medium};
        let (module, name) = (import.module, import.name);
        let shown = text(&format!("{module}.{name}"));
        let site = Site {
            function: import.function,
            source: "import",
            offset: import.offset,
            shown: &shown,
        };
        let bindgen_module = matches!(
            module,
            "wbg" | "__wbindgen_placeholder__" | "__wbindgen_externref_xform__"
        );
        let rule: Option<Rule> = if let Some(rest) = name.strip_prefix("__wbg_") {
            let label = format!("JS glue: {}", text(bindgen_target(rest)));
            Some((
                tool("wasm_bindgen", High),
                label,
                Kind("js_glue", "wasm-bindgen", High),
            ))
        } else if let Some(rest) = name.strip_prefix("__wbindgen_") {
            let label = format!("wasm-bindgen intrinsic: {}", text(rest));
            Some((
                tool("wasm_bindgen", High),
                label,
                Kind("runtime", "wasm-bindgen", High),
            ))
        } else if bindgen_module {
            let label = format!("JS glue: {}", text(name));
            Some((
                tool("wasm_bindgen", High),
                label,
                Kind("js_glue", "wasm-bindgen", Medium),
            ))
        } else {
            match module {
                "wasi_snapshot_preview1" | "wasi_unstable" => {
                    let label = format!("WASI {}", text(name));
                    Some((tool("wasi", High), label, Kind("wasi", "WASI", High)))
                }
                "gojs" | "go" => Some(match name.strip_prefix("syscall/js.") {
                    Some(rest) => {
                        let label = format!("Go syscall/js bridge: {}", text(rest));
                        (tool("go", High), label, Kind("js_glue", "Go", High))
                    }
                    None => {
                        let label = format!("Go runtime host call: {}", text(name));
                        (tool("go", High), label, Kind("runtime", "Go", High))
                    }
                }),
                "dotnet" => {
                    let label = format!(".NET runtime import: {}", text(name));
                    Some((tool("dotnet", High), label, Kind("runtime", ".NET", High)))
                }
                "js_code" => {
                    let label = format!("Kotlin js() code: {}", text(name));
                    Some((
                        tool("kotlin", Medium),
                        label,
                        Kind("js_glue", "Kotlin/Wasm", Medium),
                    ))
                }
                "dart2wasm" => {
                    let label = format!("Dart JS interop: {}", text(name));
                    Some((tool("dart", High), label, Kind("js_glue", "Dart", High)))
                }
                "wasm:js-string" => {
                    let label = format!("JS String Builtin: {}", text(name));
                    Some((None, label, Kind("js_glue", "JS String Builtins", High)))
                }
                _ => Self::host_import(module, name),
            }
        };
        self.apply(&site, rule);
    }

    /// Imports from a shared host module such as `env`, named by convention.
    fn host_import(module: &str, name: &str) -> Option<Rule> {
        use Confidence::{High, Low, Medium};
        let emscripten = |label: String, category, confidence| {
            Some((
                tool("emscripten", confidence),
                label,
                Kind(category, "Emscripten", confidence),
            ))
        };
        if name.starts_with("emscripten_") || name.starts_with("_emscripten_") {
            emscripten(
                format!("Emscripten runtime: {}", text(name)),
                "runtime",
                High,
            )
        } else if let Some(rest) = name.strip_prefix("__syscall_") {
            emscripten(
                format!("Emscripten syscall: {}", text(rest)),
                "syscall",
                High,
            )
        } else if name.starts_with("_embind_") || name.starts_with("_emval_") {
            emscripten(
                format!("Emscripten embind: {}", text(name)),
                "js_glue",
                High,
            )
        } else if let Some(rest) = name.strip_prefix("invoke_") {
            emscripten(
                format!("Emscripten invoke wrapper: {}", text(rest)),
                "runtime",
                Medium,
            )
        } else if let Some(rest) = name.strip_prefix("syscall/js.") {
            let label = format!("TinyGo syscall/js bridge: {}", text(rest));
            Some((
                tool("tinygo", Medium),
                label,
                Kind("js_glue", "TinyGo", Medium),
            ))
        } else if name.starts_with("mono_wasm_") {
            let label = format!(".NET runtime import: {}", text(name));
            Some((
                tool("dotnet", Medium),
                label,
                Kind("runtime", ".NET", Medium),
            ))
        } else if module == "env" && matches!(name, "abort" | "trace" | "seed") {
            let label = match name {
                "abort" => "Abort handler (AssemblyScript names it env.abort)",
                "trace" => "AssemblyScript trace",
                _ => "AssemblyScript random seed",
            };
            let kind = Kind("runtime", "AssemblyScript", Low);
            Some((tool("assemblyscript", Low), label.into(), kind))
        } else if name.starts_with("__cxa_") {
            let label = format!("C++ ABI: {}", text(name));
            Some((None, label, Kind("runtime", "C++ ABI", Medium)))
        } else {
            None
        }
    }

    /// Exports and name-section names share one vocabulary.
    fn symbol(&mut self, name: &str, function: Option<u32>, source: &'static str, offset: usize) {
        use Confidence::{Low, Medium};
        let shown = text(name);
        let site = Site {
            function,
            source,
            offset,
            shown: &shown,
        };
        let exact = EXACT.iter().find(|(exact, ..)| *exact == name);
        if let Some((_, label, category, library, confidence)) = exact {
            let toolchain = match *library {
                "wasm-bindgen" => tool("wasm_bindgen", *confidence),
                "Rust" => tool("rust", *confidence),
                "Emscripten" => tool("emscripten", *confidence),
                "TinyGo" => tool("tinygo", *confidence),
                _ => None,
            };
            let kind = Kind(category, library, *confidence);
            self.apply(&site, Some((toolchain, (*label).into(), kind)));
        }
        if LINKER_SYMBOLS.contains(&name) {
            self.conclude(&site, "llvm_wasm_ld", Medium);
        }
        if ASSEMBLYSCRIPT_RUNTIME.contains(&name) {
            let label = format!("AssemblyScript runtime: {}", text(name));
            let kind = Kind("runtime", "AssemblyScript", Medium);
            self.apply(&site, Some((tool("assemblyscript", Medium), label, kind)));
        }
        if name == "getsp" {
            let kind = Kind("runtime", "Go", Medium);
            let label = "Go stack pointer helper".into();
            self.apply(&site, Some((tool("go", Medium), label, kind)));
        }
        if (name == "_start" || name == "_initialize") && source == "export" {
            self.conclude(&site, "wasi", Low);
        }
        // An exactly named symbol already carries its most specific label.
        if exact.is_none() {
            let rule = Self::symbol_rule(name, source, self.cpp_declared);
            self.apply(&site, rule);
        }
        // The most specific algorithm a name mentions: `sha2::sha256` is SHA-256.
        let algorithm = tokens(name)
            .iter()
            .filter_map(|token| ALGORITHM_TOKENS.iter().find(|(key, ..)| key == token))
            .max_by_key(|(key, ..)| key.len());
        if let Some((_, algorithm, category)) = algorithm {
            let label = format!("Name suggests {algorithm}");
            self.suggest(&site, label, Kind(category, "name", Low));
        }
    }

    /// Prefix and namespace rules for an export or a name-section name.
    fn symbol_rule(name: &str, source: &'static str, cpp_declared: bool) -> Option<Rule> {
        use Confidence::{High, Low, Medium};
        let named = |id, confidence, label: String, kind| Some((tool(id, confidence), label, kind));
        if let Some(rest) = name.strip_prefix("__wbindgen_") {
            let label = format!("wasm-bindgen runtime: {}", text(rest));
            named(
                "wasm_bindgen",
                High,
                label,
                Kind("runtime", "wasm-bindgen", High),
            )
        } else if let Some(rest) = name.strip_prefix("__wbg_") {
            let label = match rest.strip_suffix("_free") {
                Some(object) => format!("wasm-bindgen object destructor: {}", text(object)),
                None => format!("wasm-bindgen glue: {}", text(bindgen_target(rest))),
            };
            named(
                "wasm_bindgen",
                High,
                label,
                Kind("export_glue", "wasm-bindgen", High),
            )
        } else if name.starts_with("emscripten_") || name.starts_with("_emscripten_") {
            let confidence = if source == "export" { High } else { Medium };
            let label = format!("Emscripten runtime: {}", text(name));
            named(
                "emscripten",
                confidence,
                label,
                Kind("runtime", "Emscripten", High),
            )
        } else if name.starts_with("dynCall_") {
            let label = format!("Emscripten dynCall thunk: {}", text(name));
            named(
                "emscripten",
                High,
                label,
                Kind("runtime", "Emscripten", High),
            )
        } else if let Some(rest) = name.strip_prefix("asyncify_") {
            let label = format!("Binaryen Asyncify: {}", text(rest));
            named("asyncify", High, label, Kind("runtime", "Binaryen", High))
        } else if name.starts_with("emmalloc_") {
            let label = format!("Emscripten emmalloc: {}", text(name));
            named(
                "emscripten",
                Medium,
                label,
                Kind("allocator", "Emscripten", High),
            )
        } else if name.starts_with("mono_wasm_")
            || (source == "export" && name.starts_with("mono_"))
        {
            let label = format!(".NET runtime: {}", text(name));
            named("dotnet", Medium, label, Kind("runtime", ".NET", Medium))
        } else if name.starts_with("__wasi_") || name.starts_with("__wasilibc_") {
            let label = format!("wasi-libc: {}", text(name));
            named(
                "wasi_libc",
                Medium,
                label,
                Kind("libc", "wasi-libc", Medium),
            )
        } else if let Some(path) = name.strip_prefix("~lib/") {
            let category = if path.starts_with("rt/") {
                "runtime"
            } else {
                "std"
            };
            let label = format!("AssemblyScript std library: {}", text(path));
            named(
                "assemblyscript",
                High,
                label,
                Kind(category, "AssemblyScript", High),
            )
        } else if let Some(rest) = name.strip_prefix("syscall/js.") {
            let label = format!("Go syscall/js: {}", text(rest));
            named("go", Medium, label, Kind("js_glue", "Go", Medium))
        } else if name.starts_with("runtime.") {
            let label = format!("Go runtime: {}", text(name));
            named("go", Medium, label, Kind("runtime", "Go", Medium))
        } else if name.starts_with("crypto/") {
            let label = format!("Go crypto library: {}", text(name));
            Some((None, label, Kind("crypto", "Go", Medium)))
        } else if GO_STD.iter().any(|prefix| name.starts_with(prefix)) && !name.contains("::") {
            let label = format!("Go standard library: {}", text(name));
            Some((None, label, Kind("std", "Go", Low)))
        } else if ["_ZNSt3__", "_ZNKSt3__", "std::__1::", "std::__2::"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            let label = "libc++ standard library".into();
            named("c_cpp", Medium, label, Kind("std", "libc++", Medium))
        } else {
            let (crate_name, certain) = rust_crate(name);
            // A module whose producers declare C or C++ explains a namespace
            // like `std::` or `log::` without a hash as C++.
            if !certain && cpp_declared {
                return None;
            }
            let confidence = if certain { High } else { Medium };
            match crate_name {
                Some(crate_name) => {
                    let category = match crate_name {
                        "core" | "alloc" | "std" | "compiler_builtins" => "std",
                        "dlmalloc" | "wee_alloc" => "allocator",
                        "wasm_bindgen" | "js_sys" | "web_sys" => "js_glue",
                        _ => "library",
                    };
                    let label = format!("Rust {crate_name} library");
                    named(
                        "rust",
                        confidence,
                        label,
                        Kind(category, "Rust", confidence),
                    )
                }
                // A certainly-Rust symbol of a crate this table does not
                // know supports the toolchain but labels nothing.
                None if certain => Some((tool("rust", High), String::new(), Kind("", "", High))),
                None => None,
            }
        }
    }
}

fn custom_conclusions(custom: &Custom<'_>, conclusions: &mut Conclusions) {
    use Confidence::{High, Medium};
    let shown = bounded(custom.name, LABEL_TEXT_BYTES);
    let detail = format!("custom section {shown}");
    let id = match custom.name {
        "target_features" => Some(("llvm_wasm_ld", Medium)),
        "linking" => Some(("llvm_object", High)),
        name if name.starts_with("reloc.") => Some(("llvm_object", High)),
        "dylink" | "dylink.0" => Some(("llvm_wasm_ld", Medium)),
        "emscripten_metadata" => Some(("emscripten", High)),
        "go:buildid" | "go.buildid" => Some(("go", High)),
        "__wasm_bindgen_unstable" => Some(("wasm_bindgen", High)),
        name if name.starts_with("component-type") => Some(("component_model", High)),
        _ => None,
    };
    if let Some((id, confidence)) = id {
        conclusions.add(
            id,
            confidence,
            Evidence {
                source: "custom_section",
                byte_offset: custom.data_offset,
                detail,
                function_index: None,
            },
        );
    }
}

/// A length-prefixed string custom section (`sourceMappingURL`,
/// `external_debug_info`).
fn custom_string(custom: &Custom<'_>) -> Option<String> {
    let mut reader = BinaryReader::new(custom.data, custom.data_offset);
    reader
        .read_unlimited_string()
        .ok()
        .map(|text| bounded(text, URL_BYTES))
}

/// Rows the producers and target_features sections contribute, kept up to
/// module-wide limits however many sections declare them. Past its limit a
/// target_features section is not read at all; producers are still read,
/// because a later entry can still name the toolchain.
#[derive(Default)]
struct Declared {
    producers: Vec<Value>,
    features: Vec<Value>,
    producers_cut: bool,
    features_cut: bool,
    /// Producer values read, polled against the deadline.
    values_read: usize,
}

fn target_features(custom: &Custom<'_>, declared: &mut Declared, omissions: &mut Omissions) {
    if declared.features.len() >= MAX_FEATURES {
        declared.features_cut = true;
        return;
    }
    let mut reader = BinaryReader::new(custom.data, custom.data_offset);
    let Ok(count) = reader.read_var_u32() else {
        omissions.push("A target_features section is malformed; it was not read.");
        return;
    };
    for _ in 0..count {
        if declared.features.len() >= MAX_FEATURES {
            declared.features_cut = true;
            return;
        }
        let offset = reader.original_position();
        let (Ok(prefix), Ok(name)) = (reader.read_u8(), reader.read_string()) else {
            omissions
                .push("A target_features section is malformed; its later features were not read.");
            return;
        };
        declared.features.push(json!({"prefix":(prefix as char).to_string(),"name":bounded(name, LABEL_TEXT_BYTES),"byte_offset":offset}));
    }
}

/// Reads one producers section; false when the deadline passed inside it.
fn producers(
    custom: &Custom<'_>,
    conclusions: &mut Conclusions,
    declared: &mut Declared,
    omissions: &mut Omissions,
    deadline: Instant,
) -> bool {
    let Some(KnownCustom::Producers(reader)) = &custom.known else {
        return true;
    };
    for field in reader.clone().into_iter_with_offsets() {
        let Ok((_, field)) = field else {
            omissions.push("A producers section is malformed; its later fields were not read.");
            return true;
        };
        for value in field.values.into_iter_with_offsets() {
            declared.values_read += 1;
            if declared.values_read.is_multiple_of(4096) && Instant::now() > deadline {
                return false;
            }
            let Ok((offset, value)) = value else {
                omissions.push("A producers section is malformed; its later values were not read.");
                return true;
            };
            let name = bounded(value.name, LABEL_TEXT_BYTES);
            let version = bounded(value.version, LABEL_TEXT_BYTES);
            if let Some(id) = producer_toolchain(field.name, value.name) {
                conclusions.add(
                    id,
                    Confidence::High,
                    Evidence {
                        source: "producers",
                        byte_offset: offset,
                        detail: format!(
                            "{}: {name}{}",
                            bounded(field.name, 32),
                            if version.is_empty() {
                                String::new()
                            } else {
                                format!(" {version}")
                            }
                        ),
                        function_index: None,
                    },
                );
            }
            if declared.producers.len() < MAX_PRODUCERS {
                declared.producers.push(json!({"field":bounded(field.name, 32),"name":name,"version":version,"byte_offset":offset}));
            } else {
                declared.producers_cut = true;
            }
        }
    }
    true
}

/// One reported constant match.
struct Match {
    set: usize,
    location: &'static str,
    /// Element indexes covered; no set has more than 256 elements.
    covered: [u64; 4],
    /// Data matches: the lowest element index and one past the last run's
    /// last element, so a following run can be checked for continuation.
    first: usize,
    end_index: usize,
    byte_offset: usize,
    byte_end: usize,
    /// The end of the first segment's part, which bounds the hex preview:
    /// the bytes after it in a merged match are another segment's header.
    preview_end: usize,
    segments: Vec<u32>,
    encoding: Option<Encoding>,
    runs: usize,
    /// The memory address of `byte_offset` and of the match's end, when the
    /// segments' offsets are constants.
    address: Option<u64>,
    address_end: Option<u64>,
    references: Vec<Value>,
    reference_count: usize,
    /// Immediate matches.
    function: Option<u32>,
    sites: Vec<Value>,
    site_count: usize,
    /// Values matched, and for a 64-bit set also their 32-bit halves, so an
    /// i32 hit on a half is explained by the 64-bit match.
    values: BTreeSet<u64>,
}

impl Match {
    fn matched(&self) -> usize {
        self.covered
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
    fn complete(&self) -> bool {
        self.matched() == wasm_constants::catalog()[self.set].total()
    }
    fn cover(&mut self, from: usize, to: usize) {
        for index in from..to {
            self.covered[index / 64] |= 1 << (index % 64);
        }
    }
    fn json(&self, bytes: &[u8], references: usize, sites: usize) -> Value {
        let set: &ConstantSet = &wasm_constants::catalog()[self.set];
        let mut value = json!({"id":set.id,"label":set.label,"family":set.family,"location":self.location,
            "match":if self.complete() {"complete"} else {"partial"},"matched":self.matched(),"total":set.total(),
            "byte_offset":self.byte_offset,"byte_end":self.byte_end});
        if self.location == "data" {
            let end = self.preview_end.min(self.byte_offset + MATCH_PREVIEW_BYTES);
            let kept = &self.references[..self.references.len().min(references)];
            value["data_segment"] = json!(self.segments[0]);
            value["data_segments"] = json!(self.segments);
            value["encoding"] = json!(self.encoding.map(Encoding::name));
            value["runs"] = json!(self.runs);
            value["memory_address"] = json!(self.address);
            value["referenced_by"] = json!(kept);
            value["reference_count"] = json!(self.reference_count);
            value["references_truncated"] = json!(self.reference_count > kept.len());
            value["hex"] = json!(hex::encode(&bytes[self.byte_offset..end]));
        } else {
            let kept = &self.sites[..self.sites.len().min(sites)];
            value["function_index"] = json!(self.function);
            value["sites"] = json!(kept);
            value["site_count"] = json!(self.site_count);
            value["sites_truncated"] = json!(self.site_count > kept.len());
        }
        value
    }
}

fn element_width(set: &ConstantSet) -> usize {
    match set.width {
        Width::Byte => 1,
        Width::Word32 => 4,
        Width::Word64 => 8,
    }
}

fn data_match(run: &Run, segment: &Segment<'_>) -> Match {
    let mut entry = Match {
        set: run.set,
        location: "data",
        covered: [0; 4],
        first: run.first,
        end_index: run.end_index,
        byte_offset: segment.data_offset + run.start,
        byte_end: segment.data_offset + run.end,
        preview_end: segment.data_offset + run.end,
        segments: vec![segment.index],
        encoding: Some(run.encoding),
        runs: 1,
        address: segment
            .address
            .map(|base| base.wrapping_add(run.start as u64)),
        address_end: segment
            .address
            .map(|base| base.wrapping_add(run.end as u64)),
        references: Vec::new(),
        reference_count: 0,
        function: None,
        sites: Vec::new(),
        site_count: 0,
        values: BTreeSet::new(),
    };
    entry.cover(run.first, run.end_index);
    entry
}

/// Candidate matches kept so far, the ones counted past `MAX_CANDIDATES`,
/// and whether the deadline stopped the work.
#[derive(Default)]
struct Candidates {
    kept: Vec<Match>,
    dropped: usize,
    expired: bool,
}

impl Candidates {
    fn push(&mut self, entry: Match) {
        if self.kept.len() < MAX_CANDIDATES {
            self.kept.push(entry);
        } else {
            self.dropped += 1;
        }
    }
}

/// Runs of one set and encoding in one segment become one match when each
/// run continues the table where the previous one stopped. One pass over the
/// runs sorted by position; the deadline is polled every 1024 runs.
fn cluster(mut runs: Vec<Run>, segment: &Segment<'_>, deadline: Instant, out: &mut Candidates) {
    let catalog = wasm_constants::catalog();
    runs.sort_unstable_by_key(|run| (run.set, run.encoding as u8, run.start));
    let mut current: Option<Match> = None;
    for (position, run) in runs.iter().enumerate() {
        if position.is_multiple_of(1024) && Instant::now() > deadline {
            out.expired = true;
            return;
        }
        let set = &catalog[run.set];
        let span = set.total() * element_width(set);
        if let Some(open) = current.as_mut()
            && open.set == run.set
            && open.encoding == Some(run.encoding)
            && segment.data_offset + run.start <= open.byte_end + span
            && run.first >= open.end_index
        {
            open.runs += 1;
            open.byte_end = open.byte_end.max(segment.data_offset + run.end);
            open.preview_end = open.byte_end;
            open.address_end = segment
                .address
                .map(|base| base.wrapping_add(run.end as u64));
            open.end_index = run.end_index;
            open.cover(run.first, run.end_index);
            continue;
        }
        if let Some(done) = current.replace(data_match(run, segment)) {
            out.push(done);
        }
    }
    if let Some(done) = current {
        out.push(done);
    }
}

/// A table split across segments whose memory addresses touch, as Binaryen's
/// memory packing leaves it, is one match: the next segment in the file
/// continues at the address and the element where the previous part stopped.
/// Only consecutive segments in file order merge, so a merged match never
/// spans an unrelated segment and its byte range runs forward. The second
/// value counts the parts left separate because a match reached
/// `MAX_MATCH_SEGMENTS`.
fn merge_segments(mut matches: Vec<Match>) -> (Vec<Match>, usize) {
    matches.sort_unstable_by_key(|entry| {
        (
            entry.set,
            entry.encoding.map(|e| e as u8),
            entry.address.unwrap_or(u64::MAX),
            entry.byte_offset,
        )
    });
    let mut out: Vec<Match> = Vec::with_capacity(matches.len());
    let mut separate = 0usize;
    for entry in matches {
        if let Some(previous) = out.last_mut()
            && previous.set == entry.set
            && previous.encoding == entry.encoding
            && previous.address_end.is_some()
            && previous.address_end == entry.address
            && entry.first >= previous.end_index
            && previous.segments.last().map(|last| last + 1) == entry.segments.first().copied()
            && entry.byte_offset >= previous.byte_end
        {
            if previous.segments.len() >= MAX_MATCH_SEGMENTS {
                separate += 1;
            } else {
                for (word, other) in previous.covered.iter_mut().zip(entry.covered) {
                    *word |= other;
                }
                previous.end_index = entry.end_index;
                previous.byte_end = entry.byte_end;
                previous.address_end = entry.address_end;
                previous.runs += entry.runs;
                previous.segments.extend(entry.segments);
                continue;
            }
        }
        out.push(entry);
    }
    (out, separate)
}

/// Whether `container`, whose byte range holds `entry`'s, fully explains it:
/// it is larger, or as large and complete where `entry` is partial.
fn explains(entry_size: usize, entry: &Match, container_size: usize, container: &Match) -> bool {
    container_size > entry_size
        || (container_size == entry_size && container.complete() && !entry.complete())
}

/// Drops a data match another match fully explains: MD5's four words inside
/// a SHA-1 state, the Base62 alphabet inside a Base64 one. One pass over the
/// matches sorted by start, widest first: the widest range seen so far is
/// the only container a later match needs to be compared with.
fn suppress_data(mut matches: Vec<Match>, deadline: Instant, expired: &mut bool) -> Vec<Match> {
    matches.sort_unstable_by_key(|entry| {
        (
            entry.byte_offset,
            std::cmp::Reverse(entry.byte_end),
            !entry.complete(),
        )
    });
    let mut kept: Vec<Match> = Vec::with_capacity(matches.len());
    let mut widest: Option<usize> = None;
    for (position, entry) in matches.into_iter().enumerate() {
        if position.is_multiple_of(1024) && Instant::now() > deadline {
            *expired = true;
            break;
        }
        let size = entry.byte_end.saturating_sub(entry.byte_offset);
        if let Some(index) = widest {
            let container = &kept[index];
            if container.byte_end >= entry.byte_end
                && explains(
                    size,
                    &entry,
                    container.byte_end.saturating_sub(container.byte_offset),
                    container,
                )
            {
                continue;
            }
        }
        // A match merged across segments spans their headers too, so it is
        // never the container that explains another match.
        if entry.segments.len() == 1
            && widest.is_none_or(|index| entry.byte_end > kept[index].byte_end)
        {
            widest = Some(kept.len());
        }
        kept.push(entry);
    }
    kept
}

/// The same rule for one function's immediate matches, by value sets. A
/// function holds at most one match per set, so this stays small.
fn suppress_immediates(matches: Vec<Match>) -> Vec<Match> {
    let keep = (0..matches.len())
        .map(|a| {
            !(0..matches.len()).any(|b| {
                b != a
                    && matches[a].values.is_subset(&matches[b].values)
                    && explains(
                        matches[a].values.len(),
                        &matches[a],
                        matches[b].values.len(),
                        &matches[b],
                    )
            })
        })
        .collect::<Vec<_>>();
    matches
        .into_iter()
        .zip(keep)
        .filter_map(|(entry, keep)| keep.then_some(entry))
        .collect()
}

#[derive(Default)]
struct Hit {
    indexes: BTreeSet<u32>,
    first: usize,
    sites: Vec<Value>,
    site_count: usize,
}

fn memarg_offset(op: &Operator<'_>) -> Option<u64> {
    use Operator::*;
    match op {
        I32Load { memarg }
        | I64Load { memarg }
        | F32Load { memarg }
        | F64Load { memarg }
        | I32Load8S { memarg }
        | I32Load8U { memarg }
        | I32Load16S { memarg }
        | I32Load16U { memarg }
        | I64Load8S { memarg }
        | I64Load8U { memarg }
        | I64Load16S { memarg }
        | I64Load16U { memarg }
        | I64Load32S { memarg }
        | I64Load32U { memarg }
        | V128Load { memarg } => Some(memarg.offset),
        _ => None,
    }
}

struct Scan {
    functions_scanned: usize,
    immediates: usize,
    stopped: bool,
}

/// Where data matches sit in memory: an exact start address, which a
/// function's `i32.const` or `i64.const` names when it takes the table's
/// address, and the whole range, which a load's constant offset falls into
/// when it reads the table at a fixed index. Any other immediate inside a
/// range is not a reference: Emscripten's data starts at 1024, so loop
/// bounds and sizes land inside tables all the time.
struct Targets {
    starts: HashMap<u64, Vec<usize>>,
    ranges: Vec<(u64, u64, usize)>,
}

impl Targets {
    fn new(matches: &[Match]) -> Self {
        let mut starts: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut ranges = Vec::new();
        for (index, entry) in matches.iter().enumerate() {
            if let (Some(start), Some(end)) = (entry.address, entry.address_end) {
                starts.entry(start).or_default().push(index);
                ranges.push((start, end, index));
            }
        }
        ranges.sort_unstable();
        Self { starts, ranges }
    }
}

fn reference(entry: &mut Match, function: u32, offset: usize, via: &'static str) {
    entry.reference_count += 1;
    if entry.references.len() < MAX_REFERENCES {
        entry
            .references
            .push(json!({"function_index":function,"byte_offset":offset,"via":via}));
    }
}

/// Walks every body once: constant immediates against the immediate table,
/// and integer immediates and load offsets against the data matches. The
/// bodies are read from the module again rather than kept, so a module of
/// millions of tiny functions costs no stored list.
fn scan_functions(
    bytes: &[u8],
    imported_functions: u32,
    data_matches: &mut [Match],
    deadline: Instant,
    out: &mut Candidates,
) -> Result<Scan> {
    let table = wasm_constants::immediates();
    let catalog = wasm_constants::catalog();
    let targets = Targets::new(data_matches);
    let mut scan = Scan {
        functions_scanned: 0,
        immediates: 0,
        stopped: false,
    };
    let mut position = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
        let body = match payload.map_err(bad)? {
            Payload::CodeSectionEntry(body) => body,
            Payload::DataSection(_) | Payload::End(_) => break,
            _ => continue,
        };
        if Instant::now() > deadline {
            scan.stopped = true;
            break;
        }
        let function = imported_functions + position;
        position += 1;
        let mut hits: BTreeMap<u16, Hit> = BTreeMap::new();
        let mut reader = body.get_operators_reader().map_err(bad)?;
        let mut count = 0usize;
        // Two value constants in a row can spell one 64-bit element, high or
        // low half first. A value constant is one the next instruction
        // consumes; an i32.const followed by another constant is an operand
        // such as a store address, so `i32.const addr; i32.const lo;
        // i32.store; i32.const addr; i32.const hi; i32.store` pairs lo with
        // hi. `held` waits for the next instruction to classify it, and
        // `previous` is the last value constant not yet paired.
        let mut held: Option<(u32, usize)> = None;
        let mut previous: Option<(u32, usize)> = None;
        let record = |hits: &mut BTreeMap<u16, Hit>,
                      entries: Option<&Vec<(u16, u32)>>,
                      offset: usize,
                      operator: &'static str| {
            for (set, index) in entries.into_iter().flatten() {
                let hit = hits.entry(*set).or_insert_with(|| Hit {
                    first: offset,
                    ..Hit::default()
                });
                hit.indexes.insert(*index);
                hit.site_count += 1;
                if hit.sites.len() < MAX_SITES {
                    hit.sites
                        .push(json!({"byte_offset":offset,"operator":operator}));
                }
            }
        };
        let pair = |hits: &mut BTreeMap<u16, Hit>, high: u32, low: u32, offset: usize| {
            let wide = (u64::from(high) << 32) | u64::from(low);
            let entries = table.high.get(&high).map(|list| {
                list.iter()
                    .filter(|(set, index)| catalog[*set as usize].values[*index as usize] == wide)
                    .copied()
                    .collect::<Vec<_>>()
            });
            let found = entries.as_ref().is_some_and(|list| !list.is_empty());
            record(hits, entries.as_ref(), offset, "i32.const pair");
            found
        };
        let address = |value: u64, offset: usize, data_matches: &mut [Match]| {
            for index in targets.starts.get(&value).into_iter().flatten() {
                reference(
                    &mut data_matches[*index],
                    function,
                    offset,
                    "address_immediate",
                );
            }
        };
        let load = |value: u64, offset: usize, data_matches: &mut [Match]| {
            if value == 0 {
                return;
            }
            let end = targets
                .ranges
                .partition_point(|(start, ..)| *start <= value);
            for (start, stop, index) in targets.ranges[..end].iter().rev().take(4) {
                if value >= *start && value < *stop {
                    reference(&mut data_matches[*index], function, offset, "load_offset");
                }
            }
        };
        while !reader.eof() {
            count += 1;
            if count.is_multiple_of(4096) && Instant::now() > deadline {
                scan.stopped = true;
                break;
            }
            let (op, offset) = reader.read_with_offset().map_err(bad)?;
            if let Some((value, at)) = held.take()
                && !matches!(op, Operator::I32Const { .. })
            {
                previous = match previous {
                    Some((first, first_at))
                        if pair(&mut hits, first, value, first_at)
                            || pair(&mut hits, value, first, first_at) =>
                    {
                        None
                    }
                    _ => Some((value, at)),
                };
            }
            match op {
                Operator::I32Const { value } => {
                    scan.immediates += 1;
                    let value = value as u32;
                    record(&mut hits, table.four.get(&value), offset, "i32.const");
                    address(u64::from(value), offset, data_matches);
                    held = Some((value, offset));
                }
                Operator::I64Const { value } => {
                    scan.immediates += 1;
                    let value = value as u64;
                    record(&mut hits, table.eight.get(&value), offset, "i64.const");
                    // Go keeps 32-bit arithmetic in i64 registers.
                    if let Ok(narrow) = u32::try_from(value) {
                        record(&mut hits, table.four.get(&narrow), offset, "i64.const");
                    }
                    address(value, offset, data_matches);
                }
                // A float immediate is matched by its bits: an optimizer can
                // move an integer constant through a float store.
                Operator::F32Const { value } => {
                    scan.immediates += 1;
                    record(
                        &mut hits,
                        table.four.get(&value.bits()),
                        offset,
                        "f32.const",
                    );
                }
                Operator::F64Const { value } => {
                    scan.immediates += 1;
                    record(
                        &mut hits,
                        table.eight.get(&value.bits()),
                        offset,
                        "f64.const",
                    );
                }
                Operator::V128Const { value } => {
                    scan.immediates += 1;
                    let lanes = value.bytes();
                    for lane in lanes.as_chunks::<4>().0 {
                        let word = u32::from_le_bytes(*lane);
                        record(&mut hits, table.four.get(&word), offset, "v128.const");
                    }
                    for lane in lanes.as_chunks::<8>().0 {
                        let word = u64::from_le_bytes(*lane);
                        record(&mut hits, table.eight.get(&word), offset, "v128.const");
                    }
                }
                ref other => {
                    if let Some(memory_offset) = memarg_offset(other) {
                        load(memory_offset, offset, data_matches);
                    }
                }
            }
        }
        if scan.stopped {
            break;
        }
        scan.functions_scanned += 1;
        let mut found = Vec::new();
        for (set_number, hit) in hits {
            let set = &catalog[set_number as usize];
            if hit.indexes.len() < set.immediate_min {
                continue;
            }
            let mut values = BTreeSet::new();
            for index in &hit.indexes {
                let value = set.values[*index as usize];
                values.insert(value);
                if set.width == Width::Word64 {
                    values.insert(value >> 32);
                    values.insert(value & 0xffff_ffff);
                }
            }
            let mut entry = Match {
                set: set_number as usize,
                location: "immediate",
                covered: [0; 4],
                first: 0,
                end_index: 0,
                byte_offset: hit.first,
                byte_end: hit.first,
                preview_end: hit.first,
                segments: Vec::new(),
                encoding: None,
                runs: 0,
                address: None,
                address_end: None,
                references: Vec::new(),
                reference_count: 0,
                function: Some(function),
                sites: hit.sites,
                site_count: hit.site_count,
                values,
            };
            for index in &hit.indexes {
                entry.cover(*index as usize, *index as usize + 1);
            }
            found.push(entry);
        }
        for entry in suppress_immediates(found) {
            out.push(entry);
        }
    }
    Ok(scan)
}

/// The identification report for one stored artifact.
pub fn load(root: &Path, id: &str, offset: usize, limit: usize) -> Result<Value> {
    let artifact = wasm_graph::artifact(root, id)?;
    let mut document = identify(&artifact.bytes, offset, limit)?;
    document["artifact_id"] = artifact.artifact_id;
    document["sha256"] = artifact.sha256;
    Ok(document)
}

/// The size reb-api mcp checks: it inlines a result only when both its
/// compact and its pretty-printed text fit the limit, and pretty is never
/// the smaller.
fn serialized(value: &Value) -> usize {
    serde_json::to_string_pretty(value).map_or(usize::MAX, |text| text.len())
}

/// Builds the report. `offset` and `limit` page the suggestion rows only;
/// every other part is whole on every page, held to `FIXED_BYTES`.
pub fn identify(bytes: &[u8], offset: usize, limit: usize) -> Result<Value> {
    identify_within(bytes, offset, limit, DEADLINE)
}

/// `identify` with its time budget named, so the deadline paths are tested
/// without a module large enough to reach the real one.
fn identify_within(bytes: &[u8], offset: usize, limit: usize, budget: Duration) -> Result<Value> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::bad("WASM identification input exceeds 64 MiB"));
    }
    // One deadline for the whole report: reading, labeling, both scans and
    // the merge all poll it, and each says where it stopped.
    let deadline = Instant::now() + budget;
    let module = read_module(bytes, deadline)?;
    let mut omissions = module.omissions.clone();
    let mut conclusions = Conclusions::default();

    let mut declared = Declared::default();
    let mut source_map = Value::Null;
    let mut debug_info = Value::Null;
    let mut custom_rows = Vec::new();
    let mut customs_read = 0usize;
    for custom in &module.customs {
        if Instant::now() > deadline {
            omissions.push(format!(
                "Identification deadline reached while reading custom sections; {customs_read} of {} were read.",
                module.customs.len()
            ));
            break;
        }
        customs_read += 1;
        custom_conclusions(custom, &mut conclusions);
        match custom.name {
            "producers" => {
                if !producers(
                    custom,
                    &mut conclusions,
                    &mut declared,
                    &mut omissions,
                    deadline,
                ) {
                    omissions.push(format!(
                        "Identification deadline reached while reading custom sections; {customs_read} of {} were read.",
                        module.customs.len()
                    ));
                    break;
                }
            }
            "target_features" => target_features(custom, &mut declared, &mut omissions),
            "sourceMappingURL" => {
                source_map = json!({"url":custom_string(custom),"byte_offset":custom.data_offset});
            }
            "external_debug_info" => {
                debug_info = json!({"url":custom_string(custom),"byte_offset":custom.data_offset});
            }
            _ => {}
        }
        if custom_rows.len() < MAX_CUSTOM_SECTIONS {
            custom_rows.push(json!({"name":bounded(custom.name, LABEL_TEXT_BYTES),"byte_offset":custom.data_offset,
                "byte_end":custom.end,"bytes":custom.data.len()}));
        }
    }
    if module.custom_count > MAX_CUSTOM_SECTIONS {
        omissions.push(format!(
            "Custom section limit of {MAX_CUSTOM_SECTIONS} reached; {} later custom sections are not listed.",
            module.custom_count - MAX_CUSTOM_SECTIONS
        ));
    }
    if declared.producers_cut {
        omissions.push(format!(
            "Producer limit of {MAX_PRODUCERS} reached; later producers are read for conclusions, not listed."
        ));
    }
    if declared.features_cut {
        omissions.push(format!(
            "Target feature limit of {MAX_FEATURES} reached; later features are not listed."
        ));
    }
    let producer_rows = declared.producers;
    let feature_rows = declared.features;

    let cpp_declared = conclusions
        .by_id
        .get("c_cpp")
        .is_some_and(|(confidence, ..)| *confidence == Confidence::High);
    let mut labeler = Labeler {
        suggestions: Vec::new(),
        per_function: HashMap::new(),
        dropped: 0,
        cpp_declared,
        conclusions: &mut conclusions,
    };
    let mut labeled = 0usize;
    let mut labeling_stopped = false;
    let records = module.imports.len() + module.exports.len() + module.names.len();
    for position in 0..records {
        if position.is_multiple_of(4096) && Instant::now() > deadline {
            labeling_stopped = true;
            break;
        }
        labeled += 1;
        if let Some(import) = module.imports.get(position) {
            labeler.import(import);
        } else if let Some(export) = module.exports.get(position - module.imports.len()) {
            let function = (export.kind == ExternalKind::Func).then_some(export.index);
            labeler.symbol(export.name, function, "export", export.offset);
        } else {
            let (index, name, offset) =
                module.names[position - module.imports.len() - module.exports.len()];
            labeler.symbol(name, Some(index), "name", offset);
        }
    }
    if labeling_stopped {
        omissions.push(format!(
            "Identification deadline reached while labeling; {labeled} of {records} imports, exports and names were read."
        ));
    }
    let dropped_suggestions = labeler.dropped;
    let labeled_functions = labeler.per_function.len();
    let mut suggestions = labeler.suggestions;
    suggestions.sort_by_key(|entry| entry.function);
    let suggestion_total = suggestions.len() + dropped_suggestions;
    if dropped_suggestions > 0 {
        omissions.push(format!(
            "Suggestion limit reached; {dropped_suggestions} later suggestions are counted, not listed."
        ));
    }
    if offset > suggestions.len() {
        return Err(Error::bad("row_offset exceeds the suggestion count"));
    }

    // Data first: immediates look for references to the tables it finds.
    let mut candidates = Candidates::default();
    let data_bytes: usize = module
        .segments
        .iter()
        .map(|segment| segment.data.len())
        .sum();
    let mut data_scanned = 0usize;
    let mut data_stopped = module.stopped;
    let mut room = MAX_RUNS;
    let mut runs_dropped = 0usize;
    for segment in &module.segments {
        let mut expired = || Instant::now() > deadline;
        let scan = wasm_constants::scan_data(segment.data, &mut expired, &mut room);
        data_scanned += scan.scanned;
        runs_dropped += scan.dropped;
        cluster(scan.runs, segment, deadline, &mut candidates);
        if scan.stop.is_some() || candidates.expired {
            data_stopped = true;
            omissions.push(format!(
                "Identification deadline reached in data segment {}; {} of {data_bytes} data bytes were scanned.",
                segment.index, data_scanned
            ));
            break;
        }
    }
    if runs_dropped > 0 {
        omissions.push(format!(
            "Data run limit of {MAX_RUNS} reached; {runs_dropped} later runs of known tables are counted, not matched."
        ));
    }
    let data_dropped = std::mem::take(&mut candidates.dropped);
    let mut suppress_stopped = false;
    let (merged, separate) = merge_segments(std::mem::take(&mut candidates.kept));
    if separate > 0 {
        omissions.push(format!(
            "A table spans more than {MAX_MATCH_SEGMENTS} segments; {separate} later parts are listed as separate matches."
        ));
    }
    let mut data_matches = suppress_data(merged, deadline, &mut suppress_stopped);
    if suppress_stopped {
        omissions.push("Identification deadline reached while merging data matches; later candidates were dropped.");
    }
    // A module the deadline stopped reading is not read again for bodies.
    let scan = if module.stopped {
        Scan {
            functions_scanned: 0,
            immediates: 0,
            stopped: true,
        }
    } else {
        scan_functions(
            bytes,
            module.imported_functions,
            &mut data_matches,
            deadline,
            &mut candidates,
        )?
    };
    if scan.stopped || (module.stopped && scan.functions_scanned < module.defined_functions) {
        omissions.push(format!(
            "Identification deadline reached; constant immediates of {} of {} function bodies were scanned.",
            scan.functions_scanned, module.defined_functions
        ));
    }
    let candidates_dropped = data_dropped + candidates.dropped;
    if candidates_dropped > 0 {
        omissions.push(format!(
            "Constant candidate limit of {MAX_CANDIDATES} reached; {candidates_dropped} later candidates are counted, not merged or listed."
        ));
    }
    let mut matches = data_matches;
    matches.extend(candidates.kept);
    // Complete and larger matches first, so a cut keeps the strongest.
    matches.sort_by_key(|entry| {
        (
            !entry.complete(),
            std::cmp::Reverse(entry.matched()),
            entry.location != "data",
            entry.byte_offset,
        )
    });
    let match_total = matches.len() + candidates_dropped;
    let complete_matches = matches.iter().filter(|entry| entry.complete()).count();

    let mut ordered = conclusions.by_id.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(b.1.2.cmp(&a.1.2)));
    ordered.truncate(MAX_CONCLUSIONS);
    // Strongest evidence first, so the summary chip and any trimmed list keep
    // the reason for the confidence a conclusion reports.
    for (_, (_, evidence, _)) in ordered.iter_mut() {
        evidence.sort_by_key(|(strength, _)| std::cmp::Reverse(*strength));
    }
    let toolchain_labels = ordered
        .iter()
        .filter(|(_, (confidence, ..))| *confidence != Confidence::Low)
        .map(|(id, _)| tool_label(id))
        .collect::<Vec<_>>();

    // The fixed part at decreasing detail until it fits its budget: evidence
    // per conclusion, listed sections and the references and sites per match.
    let levels = [
        (MAX_EVIDENCE, MAX_LISTED, MAX_REFERENCES),
        (2, 8, 2),
        (1, 2, 1),
    ];
    let mut document = Value::Null;
    for (level, (evidence_limit, list_limit, detail_limit)) in levels.into_iter().enumerate() {
        let conclusion_rows = ordered
            .iter()
            .map(|(id, (confidence, evidence, count))| {
                let toolchain = TOOLCHAINS.iter().find(|tool| tool.id == *id).expect("known toolchain");
                let kept = &evidence[..evidence.len().min(evidence_limit)];
                json!({"id":id,"label":toolchain.label,"kind":toolchain.kind,
                    "confidence":confidence.name(),"evidence_count":count,"evidence_truncated":*count > kept.len(),
                    "evidence":kept.iter().map(|(strength, item)| {
                        let mut row = item.json();
                        row["confidence"] = json!(strength.name());
                        row
                    }).collect::<Vec<_>>()})
            })
            .collect::<Vec<_>>();
        let list = |rows: &[Value]| rows[..rows.len().min(list_limit)].to_vec();
        let mut level_omissions = omissions.clone();
        if level > 0 {
            level_omissions.push(format!(
                "Report trimmed to fit one page: at most {evidence_limit} evidence items per conclusion, {list_limit} listed producers, features and custom sections, and {detail_limit} references or sites per match."
            ));
        }
        let match_limit = if level == 0 {
            MAX_MATCHES
        } else {
            MAX_MATCHES >> level
        };
        let listed = matches.len().min(match_limit);
        if matches.len() > listed {
            level_omissions.push(format!(
                "Constant match limit of {listed} reached; {} later matches are counted, not listed.",
                matches.len() - listed
            ));
        }
        document = json!({
            "schema":"wasm-identification-v1","artifact_id":null,"sha256":null,"byte_size":bytes.len(),
            "status":if level_omissions.is_empty() {"complete"} else {"partial"},
            "evidence":"static_identification",
            "summary":{"toolchains":toolchain_labels,"labeled_functions":labeled_functions,
                "suggestions":suggestion_total,"constant_matches":match_total,"complete_constant_matches":complete_matches},
            "toolchain":{"conclusions":conclusion_rows,"producers":list(&producer_rows),"target_features":list(&feature_rows),
                "source_mapping_url":source_map,"external_debug_info":debug_info,"custom_sections":list(&custom_rows),
                "name_section":{"present":module.name_section.is_some(),"byte_offset":module.name_section,
                    "module_name":module.module_name.map(|(name, _)| bounded(name, LABEL_TEXT_BYTES)),
                    "function_names":module.name_count}},
            "functions":{"imported_functions":module.imported_functions,"defined_functions":module.defined_functions,
                "labeled_functions":labeled_functions,
                "suggestion_fields":["function_index","label","category","library","confidence","source","byte_offset"],
                "suggestions":[],
                "suggestion_window":{"offset":offset,"rows":0,"total_rows":suggestions.len(),"next_offset":null}},
            "constants":{"matches":matches.iter().take(match_limit)
                .map(|entry| entry.json(bytes, detail_limit, detail_limit)).collect::<Vec<_>>()},
            "coverage":{"data_segments":module.segment_count,"data_bytes":data_bytes,"data_bytes_scanned":data_scanned,
                "data_scan_complete":!data_stopped,"functions_scanned":scan.functions_scanned,
                "immediates_scanned":scan.immediates},
            "omissions":level_omissions.render(),
            "limits":{"max_input_bytes":MAX_BYTES,"deadline_ms":DEADLINE.as_millis() as u64,"max_conclusions":MAX_CONCLUSIONS,
                "max_evidence_per_conclusion":MAX_EVIDENCE,"max_suggestions":MAX_SUGGESTIONS,"suggestion_page":SUGGESTION_PAGE,
                "max_suggestions_per_function":MAX_SUGGESTIONS_PER_FUNCTION,"max_constant_matches":MAX_MATCHES,
                "max_references_per_match":MAX_REFERENCES,"max_sites_per_match":MAX_SITES,"match_preview_bytes":MATCH_PREVIEW_BYTES,
                "max_label_text_bytes":LABEL_TEXT_BYTES,"max_stored_records":MAX_STORED_RECORDS,
                "page_bytes":PAGE_BYTES,"fixed_bytes":FIXED_BYTES},
            "notice":"Static identification only. Labels and toolchain conclusions are analyzer suggestions from the cited bytes, never captured or analyst names; a constant match shows the values are present, not that an algorithm runs; an address reference is an immediate naming a matched table's start or a load offset inside it, not an observed load. Nothing is concluded from absence."
        });
        if serialized(&document) <= FIXED_BYTES {
            break;
        }
    }

    // Suggestion rows fill what the page budget leaves; at least one row is
    // returned so paging always advances. A row pretty-prints as nine lines
    // three levels deep, six spaces more indented than on its own, plus its
    // separator.
    let mut room = PAGE_BYTES.saturating_sub(serialized(&document));
    let mut window = Vec::new();
    for entry in suggestions.iter().skip(offset).take(limit) {
        let row = json!([
            entry.function,
            entry.label,
            entry.category,
            entry.library,
            entry.confidence.name(),
            entry.source,
            entry.byte_offset
        ]);
        let size = serialized(&row) + 9 * 6 + 2;
        if !window.is_empty() && size > room {
            break;
        }
        room = room.saturating_sub(size);
        window.push(row);
    }
    let place = |document: &mut Value, window: &[Value]| {
        let next = offset + window.len();
        document["functions"]["suggestion_window"] = json!({"offset":offset,"rows":window.len(),
            "total_rows":suggestions.len(),"next_offset":if next < suggestions.len() {json!(next)} else {Value::Null}});
        document["functions"]["suggestions"] = Value::Array(window.to_vec());
    };
    place(&mut document, &window);
    // The estimate is checked against the page itself: rows come off the end
    // until it fits, always leaving one.
    while window.len() > 1 && serialized(&document) > PAGE_BYTES {
        let cut = (window.len() / 16).max(1);
        window.truncate(window.len() - cut);
        place(&mut document, &window);
    }
    Ok(document)
}

fn tool_label(id: &str) -> &'static str {
    TOOLCHAINS
        .iter()
        .find(|tool| tool.id == id)
        .map_or("", |tool| tool.label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/wasm-identification")
    }

    fn sources() -> Vec<PathBuf> {
        let mut sources = std::fs::read_dir(fixtures())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "wat"))
            .collect::<Vec<_>>();
        sources.sort();
        assert!(sources.len() >= 4, "identification WAT sources are missing");
        sources
    }

    fn report(name: &str) -> Value {
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        identify(&bytes, 0, SUGGESTION_PAGE).unwrap()
    }

    fn conclusion<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
        report["toolchain"]["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
    }

    fn labels(report: &Value, function: u32) -> Vec<String> {
        report["functions"]["suggestions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row[0] == function)
            .map(|row| row[1].as_str().unwrap().to_owned())
            .collect()
    }

    fn constant<'a>(report: &'a Value, id: &str) -> Vec<&'a Value> {
        report["constants"]["matches"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["id"] == id)
            .collect()
    }

    /// The checked-in binaries are exactly what the pinned assembler builds
    /// from the checked-in sources. Run `make wasm-identification-fixtures`
    /// after editing a `.wat`.
    #[test]
    fn identification_fixtures_match_their_wat_sources() {
        for source in sources() {
            let built = wat::parse_file(&source).unwrap();
            wasmparser::Validator::new().validate_all(&built).unwrap();
            let binary = source.with_extension("wasm");
            let checked_in = std::fs::read(&binary).unwrap_or_else(|_| {
                panic!(
                    "{} is missing; run make wasm-identification-fixtures",
                    binary.display()
                )
            });
            assert!(
                built == checked_in,
                "{} drifted from its source; run make wasm-identification-fixtures",
                binary.display()
            );
        }
    }

    #[test]
    #[ignore = "writes fixtures; run through make wasm-identification-fixtures"]
    fn write_identification_fixtures() {
        for source in sources() {
            let built = wat::parse_file(&source).unwrap();
            std::fs::write(source.with_extension("wasm"), built).unwrap();
        }
    }

    #[test]
    fn rust_wasm_bindgen_module_is_identified_with_evidence() {
        let report = report("rust-wasm-bindgen.wasm");
        assert_eq!(report["schema"], "wasm-identification-v1");
        assert_eq!(report["status"], "complete", "{report:#}");
        let rust = conclusion(&report, "rust").unwrap();
        assert_eq!(rust["confidence"], "high");
        assert!(
            rust["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["record"] == "producers" && row["detail"] == "language: Rust")
        );
        let bindgen = conclusion(&report, "wasm_bindgen").unwrap();
        assert_eq!(bindgen["confidence"], "high");
        // Every piece of evidence names a position inside the module.
        let size = report["byte_size"].as_u64().unwrap();
        for row in report["toolchain"]["conclusions"].as_array().unwrap() {
            for evidence in row["evidence"].as_array().unwrap() {
                assert!(
                    evidence["byte_offset"].as_u64().unwrap() < size,
                    "{evidence}"
                );
            }
        }
        assert!(conclusion(&report, "llvm_wasm_ld").is_some());
        assert_eq!(
            report["toolchain"]["target_features"][0]["name"],
            "mutable-globals"
        );
        assert_eq!(
            report["toolchain"]["source_mapping_url"]["url"],
            "https://cdn.test/app.wasm.map"
        );
        assert_eq!(labels(&report, 0), ["JS glue: fetch"]);
        assert_eq!(
            labels(&report, 1),
            ["wasm-bindgen intrinsic: object_drop_ref"]
        );
        assert!(labels(&report, 2).contains(&"Name suggests SHA-256".to_owned()));
        assert!(labels(&report, 5).contains(&"wasm-bindgen allocator: malloc".to_owned()));
        assert_eq!(labels(&report, 7), ["Rust core library"]);
        // The custom function the module exports is not labeled.
        assert!(labels(&report, 8).is_empty());
        let table = constant(&report, "sha256_k");
        let table = table.iter().find(|row| row["location"] == "data").unwrap();
        assert_eq!(table["match"], "complete");
        assert_eq!(
            (table["matched"].as_u64(), table["total"].as_u64()),
            (Some(64), Some(64))
        );
        assert_eq!(table["encoding"], "u32_le");
        assert_eq!(table["memory_address"], 1_048_576);
        assert_eq!(table["referenced_by"][0]["function_index"], 2);
        assert_eq!(table["referenced_by"][0]["via"], "address_immediate");
        assert_eq!(table["hex"].as_str().unwrap().len(), 128);
        let initial = constant(&report, "sha256_h");
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0]["location"], "immediate");
        assert_eq!(initial[0]["function_index"], 3);
        assert_eq!(initial[0]["matched"], 8);
        let alphabet = constant(&report, "base64_standard");
        assert_eq!(alphabet[0]["match"], "complete");
        assert_eq!(alphabet[0]["referenced_by"][0]["via"], "load_offset");
        assert_eq!(alphabet[0]["referenced_by"][0]["function_index"], 4);
        // The Base62 prefix is explained by the complete Base64 alphabet.
        assert!(constant(&report, "base62_alphanumeric").is_empty());
        assert_eq!(report["summary"]["labeled_functions"], 8);
    }

    #[test]
    fn emscripten_module_reports_partial_tables_as_partial() {
        let report = report("emscripten-c.wasm");
        assert_eq!(
            conclusion(&report, "emscripten").unwrap()["confidence"],
            "high"
        );
        assert_eq!(conclusion(&report, "wasi").unwrap()["confidence"], "high");
        assert_eq!(conclusion(&report, "c_cpp").unwrap()["confidence"], "high");
        assert_eq!(conclusion(&report, "clang").unwrap()["confidence"], "high");
        assert_eq!(
            labels(&report, 0),
            ["Emscripten runtime: emscripten_resize_heap"]
        );
        assert_eq!(labels(&report, 1), ["Emscripten syscall: openat"]);
        assert_eq!(labels(&report, 3), ["WASI fd_write"]);
        assert_eq!(labels(&report, 5), ["C allocator: malloc"]);
        let sbox = constant(&report, "aes_sbox");
        assert_eq!(sbox[0]["match"], "complete");
        assert_eq!(sbox[0]["referenced_by"][0]["via"], "load_offset");
        assert_eq!(sbox[0]["referenced_by"][0]["function_index"], 8);
        let crc = constant(&report, "crc32_table");
        assert_eq!(crc[0]["match"], "partial");
        assert_eq!(
            (crc[0]["matched"].as_u64(), crc[0]["total"].as_u64()),
            (Some(32), Some(256))
        );
        // Four MD5 words without the fifth SHA-1 word stay MD5.
        assert_eq!(constant(&report, "md5_h")[0]["match"], "complete");
        assert!(constant(&report, "sha1_h").is_empty());
        assert_eq!(constant(&report, "chacha_sigma")[0]["match"], "complete");
        assert!(constant(&report, "salsa_tau").is_empty());
        let sine = constant(&report, "md5_t");
        assert_eq!(sine[0]["location"], "immediate");
        assert_eq!(
            (sine[0]["match"].as_str(), sine[0]["matched"].as_u64()),
            (Some("partial"), Some(4))
        );
    }

    #[test]
    fn go_module_matches_i64_immediates_and_suppresses_explained_sets() {
        let report = report("go-js.wasm");
        assert_eq!(conclusion(&report, "go").unwrap()["confidence"], "high");
        assert!(
            conclusion(&report, "go").unwrap()["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["record"] == "custom_section")
        );
        assert_eq!(labels(&report, 1), ["Go syscall/js bridge: valueGet"]);
        assert_eq!(constant(&report, "fnv1_64")[0]["match"], "complete");
        let sha1 = constant(&report, "sha1_h");
        assert_eq!(sha1[0]["match"], "complete");
        assert_eq!(sha1[0]["sites"][0]["operator"], "i64.const");
        assert!(constant(&report, "md5_h").is_empty());
        assert!(
            labels(&report, 4)
                .contains(&"Go crypto library: crypto/sha1.(*digest).Reset".to_owned())
        );
    }

    #[test]
    fn nothing_is_concluded_from_absence() {
        let report = report("unlabeled.wasm");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["toolchain"]["conclusions"], json!([]));
        assert_eq!(report["functions"]["suggestions"], json!([]));
        assert_eq!(report["constants"]["matches"], json!([]));
        assert_eq!(report["toolchain"]["name_section"]["present"], false);
    }

    #[test]
    fn malformed_empty_component_and_oversized_inputs_are_named_errors() {
        let empty = identify(&[], 0, 1).unwrap_err();
        assert_eq!(
            (empty.status, empty.message.as_str()),
            (422, "The WASM module is empty")
        );
        let garbage = identify(b"\0asm\x01\0\0\0\x01\xff", 0, 1).unwrap_err();
        assert_eq!(garbage.status, 422);
        assert!(
            garbage.message.starts_with("WASM decoding failed"),
            "{}",
            garbage.message
        );
        let component = identify(b"\0asm\x0d\0\x01\0", 0, 1).unwrap_err();
        assert_eq!(component.status, 422);
        let oversized = identify(&vec![0; MAX_BYTES + 1], 0, 1).unwrap_err();
        assert_eq!(oversized.status, 400);
        // A malformed name section is advisory: the report names it.
        let mut bytes = wat::parse_str(r#"(module (func $f))"#).unwrap();
        let name = bytes
            .windows(4)
            .position(|window| window == b"name")
            .unwrap();
        bytes[name + 4] = 0x01;
        bytes[name + 5] = 0x7f;
        let report = identify(&bytes, 0, 1).unwrap();
        assert_eq!(report["status"], "partial");
        assert!(
            report["omissions"][0]
                .as_str()
                .unwrap()
                .contains("name section")
        );
    }

    #[test]
    fn suggestion_rows_page_and_captured_text_stays_bounded() {
        let mut text = String::from("(module");
        for index in 0..40 {
            text.push_str(&format!(
                r#" (import "wbg" "__wbg_{}{index}_0123456789abcdef" (func))"#,
                "x".repeat(300)
            ));
        }
        text.push(')');
        let bytes = wat::parse_str(&text).unwrap();
        let first = identify(&bytes, 0, 16).unwrap();
        let window = &first["functions"]["suggestion_window"];
        assert_eq!(
            (window["rows"].as_u64(), window["total_rows"].as_u64()),
            (Some(16), Some(40))
        );
        assert_eq!(window["next_offset"], 16);
        let last = identify(&bytes, 32, 16).unwrap();
        assert_eq!(
            last["functions"]["suggestion_window"]["next_offset"],
            Value::Null
        );
        assert_eq!(last["functions"]["suggestions"][0][0], 32);
        for row in first["functions"]["suggestions"].as_array().unwrap() {
            assert!(row[1].as_str().unwrap().len() <= 160, "{row}");
        }
        assert!(identify(&bytes, 41, 16).is_err());
    }

    #[test]
    #[ignore = "prints the fixture reports for review"]
    fn print_fixture_reports() {
        for source in sources() {
            println!(
                "{}\n{:#}",
                source.display(),
                report(
                    source
                        .with_extension("wasm")
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                )
            );
        }
    }

    #[test]
    fn an_expired_data_scan_stops_and_says_so() {
        let data = vec![0u8; 200_000];
        let mut expired = || true;
        let mut room = 8;
        let scan = wasm_constants::scan_data(&data, &mut expired, &mut room);
        assert!(scan.runs.is_empty() && scan.scanned == 0 && scan.stop.is_some());
    }

    /// Raw module builders, as the review's generators wrote them: some
    /// adversarial shapes are too large or too irregular for a .wat source.
    mod raw {
        pub fn leb(mut n: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    out.push(byte);
                    return out;
                }
                out.push(byte | 0x80);
            }
        }
        pub fn sleb(mut n: i64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if (n == 0 && byte & 0x40 == 0) || (n == -1 && byte & 0x40 != 0) {
                    out.push(byte);
                    return out;
                }
                out.push(byte | 0x80);
            }
        }
        pub fn section(id: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![id];
            out.extend(leb(payload.len() as u64));
            out.extend(payload);
            out
        }
        pub fn name(text: &str) -> Vec<u8> {
            let mut out = leb(text.len() as u64);
            out.extend(text.as_bytes());
            out
        }
        pub fn vector(items: &[Vec<u8>]) -> Vec<u8> {
            let mut out = leb(items.len() as u64);
            for item in items {
                out.extend(item);
            }
            out
        }
        pub fn module(sections: &[Vec<u8>]) -> Vec<u8> {
            let mut out = b"\0asm\x01\0\0\0".to_vec();
            for section in sections {
                out.extend(section);
            }
            out
        }
        /// One memory, then active segments at constant addresses.
        pub fn memory(pages: u64) -> Vec<u8> {
            let mut payload = vec![1, 0];
            payload.extend(leb(pages));
            section(5, &payload)
        }
        pub fn data(segments: &[(u32, Vec<u8>)]) -> Vec<u8> {
            let items = segments
                .iter()
                .map(|(address, bytes)| {
                    let mut item = vec![0, 0x41];
                    item.extend(sleb(i64::from(*address as i32)));
                    item.push(0x0b);
                    item.extend(leb(bytes.len() as u64));
                    item.extend(bytes);
                    item
                })
                .collect::<Vec<_>>();
            section(11, &vector(&items))
        }
        /// `count` functions of type () -> (), each with this body's
        /// instructions (an `end` is appended).
        pub fn functions(count: usize, instructions: &[u8]) -> Vec<Vec<u8>> {
            let mut body = vec![0];
            body.extend(instructions);
            body.push(0x0b);
            let mut sized = leb(body.len() as u64);
            sized.extend(&body);
            vec![
                section(1, &[1, 0x60, 0, 0]),
                section(3, &vector(&vec![vec![0]; count])),
                section(10, &vector(&vec![sized; count])),
            ]
        }
        pub fn i32_const(value: u32) -> Vec<u8> {
            let mut out = vec![0x41];
            out.extend(sleb(i64::from(value as i32)));
            out.push(0x1a);
            out
        }
        pub fn names(names: &[(u32, String)]) -> Vec<u8> {
            let map = vector(
                &names
                    .iter()
                    .map(|(index, text)| {
                        let mut item = leb(u64::from(*index));
                        item.extend(name(text));
                        item
                    })
                    .collect::<Vec<_>>(),
            );
            let mut payload = name("name");
            payload.push(1);
            payload.extend(leb(map.len() as u64));
            payload.extend(map);
            section(0, &payload)
        }
        pub fn words(values: &[u32]) -> Vec<u8> {
            values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect()
        }
    }

    fn crc_bytes() -> Vec<u8> {
        raw::words(&wasm_constants::crc_table(0xedb8_8320, true))
    }

    #[test]
    fn a_table_repeated_across_a_segment_is_counted_not_merged_pairwise() {
        let quarter = raw::words(&wasm_constants::SHA256_K[..4]);
        let segment = quarter.repeat(32_000);
        let bytes = raw::module(&[raw::memory(8), raw::data(&[(1024, segment)])]);
        let started = Instant::now();
        let report = identify_within(&bytes, 0, 16, Duration::from_secs(300)).unwrap();
        // Pairwise merging of these runs took 28 s in a release build; the
        // bound leaves room for a debug build on a loaded machine.
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(report["status"], "partial");
        assert!(report["constants"]["matches"].as_array().unwrap().len() <= MAX_MATCHES);
        let omissions = report["omissions"].to_string();
        assert!(omissions.contains("Data run limit"), "{omissions}");
        assert!(omissions.contains("candidate limit"), "{omissions}");
    }

    #[test]
    fn merging_and_suppression_stop_at_the_deadline_and_say_so() {
        let quarter = raw::words(&wasm_constants::SHA256_K[..4]);
        let segment_bytes = quarter.repeat(4096);
        let segment = Segment {
            index: 0,
            data: &segment_bytes,
            data_offset: 0,
            address: Some(1024),
        };
        let mut room = MAX_RUNS;
        let scan = wasm_constants::scan_data(&segment_bytes, &mut || false, &mut room);
        assert_eq!(scan.runs.len(), 4096);
        let past = Instant::now() - Duration::from_millis(1);
        let mut late = Candidates::default();
        cluster(scan.runs.clone(), &segment, past, &mut late);
        assert!(late.expired && late.kept.is_empty());
        let mut timely = Candidates::default();
        cluster(scan.runs, &segment, Instant::now() + DEADLINE, &mut timely);
        assert_eq!(
            (timely.kept.len(), timely.dropped),
            (MAX_CANDIDATES, 4096 - MAX_CANDIDATES)
        );
        let mut expired = false;
        let kept = suppress_data(timely.kept, past, &mut expired);
        assert!(expired && kept.is_empty());
        // The whole report keeps one deadline: every phase says it stopped.
        let bytes = raw::module(&[
            raw::memory(2),
            raw::data(&[(1024, quarter.repeat(64))]),
            raw::names(&[(0, "malloc".into())]),
        ]);
        let report = identify_within(&bytes, 0, 16, Duration::ZERO).unwrap();
        let omissions = report["omissions"].to_string();
        assert!(
            omissions.contains("deadline reached while labeling"),
            "{omissions}"
        );
        assert!(
            omissions.contains("deadline reached in data segment 0"),
            "{omissions}"
        );
        assert_eq!(report["coverage"]["data_scan_complete"], false);
    }

    #[test]
    fn millions_of_names_are_counted_past_the_stored_limit() {
        let count = MAX_STORED_RECORDS + 4000;
        let names = (0..count as u32)
            .map(|index| (index, format!("core::fmt::f{index}")))
            .collect::<Vec<_>>();
        let bytes = raw::module(&[raw::names(&names)]);
        // Counting is under test, not the deadline: a debug build on a loaded
        // machine can need more than four seconds to label this many names.
        let report = identify_within(&bytes, 0, 8, Duration::from_secs(300)).unwrap();
        assert_eq!(report["toolchain"]["name_section"]["function_names"], count);
        let omissions = report["omissions"].to_string();
        assert!(
            omissions.contains("Name limit of 65536 reached"),
            "{omissions}"
        );
        assert!(
            omissions.contains("Suggestion limit reached"),
            "{omissions}"
        );
        assert_eq!(report["summary"]["suggestions"], MAX_STORED_RECORDS);
        assert_eq!(report["functions"]["labeled_functions"], MAX_STORED_RECORDS);
        assert_eq!(
            report["functions"]["suggestion_window"]["total_rows"],
            MAX_SUGGESTIONS
        );
    }

    #[test]
    fn itanium_names_in_a_core_namespace_are_not_rust() {
        let exports = raw::vector(&[
            [raw::name("_ZN4core6Engine4stepEv"), vec![0, 0]].concat(),
            [raw::name("_ZN3log6Logger5writeEv"), vec![0, 1]].concat(),
        ]);
        let mut producers = raw::name("producers");
        producers.extend(raw::vector(&[[
            raw::name("language"),
            raw::vector(&[[raw::name("C++14"), raw::name("")].concat()]),
        ]
        .concat()]));
        let mut sections = raw::functions(2, &[]);
        sections.insert(2, raw::section(7, &exports));
        sections.push(raw::section(0, &producers));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        assert!(conclusion(&report, "rust").is_none(), "{report:#}");
        assert!(conclusion(&report, "c_cpp").is_some());
        assert!(
            labels(&report, 0).is_empty() && labels(&report, 1).is_empty(),
            "{report:#}"
        );
        // A hashed legacy symbol still is Rust.
        assert_eq!(
            rust_crate("_ZN4core9panicking5panic17h0123456789abcdefE"),
            (Some("core"), true)
        );
        assert_eq!(rust_crate("_ZN4core9panicking5panicE"), (None, false));
    }

    #[test]
    fn a_function_exported_and_named_alike_is_labeled_once() {
        let exports = raw::vector(
            &(0..40u32)
                .map(|index| {
                    [
                        raw::name(&format!("__wbindgen_x{index}")),
                        vec![0],
                        raw::leb(u64::from(index)),
                    ]
                    .concat()
                })
                .collect::<Vec<_>>(),
        );
        let names = (0..40u32)
            .map(|index| (index, format!("__wbindgen_x{index}")))
            .collect::<Vec<_>>();
        let mut sections = raw::functions(40, &[]);
        sections.insert(2, raw::section(7, &exports));
        sections.push(raw::names(&names));
        let report = identify(&raw::module(&sections), 0, SUGGESTION_PAGE).unwrap();
        assert_eq!(report["summary"]["suggestions"], 40);
        assert_eq!(labels(&report, 7), ["wasm-bindgen runtime: x7"]);
    }

    #[test]
    fn every_page_fits_the_mcp_inline_limit() {
        // 130 data matches, and 1200 functions that each name all of them,
        // hold the golden ratio and carry a long label.
        let quarter = raw::words(&wasm_constants::SHA256_K[..4]);
        let mut segment = Vec::new();
        let mut body = Vec::new();
        for index in 0..130u32 {
            segment.extend(&quarter);
            segment.extend([0u8; 16]);
            body.extend(raw::i32_const(65_536 + index * 32));
        }
        for _ in 0..8 {
            body.extend(raw::i32_const(0x9e37_79b9));
        }
        let mut sections = raw::functions(1200, &body);
        sections.insert(2, raw::memory(2));
        sections.push(raw::data(&[(65_536, segment)]));
        let names = (0..1200u32)
            .map(|index| (index, format!("emscripten_{}{index}", "x".repeat(90))))
            .collect::<Vec<_>>();
        sections.push(raw::names(&names));
        let bytes = raw::module(&sections);
        let mut offset = 0;
        let mut rows = 0;
        loop {
            let mut page = identify(&bytes, offset, SUGGESTION_PAGE).unwrap();
            page["artifact_id"] = json!("18446744073709551615");
            page["sha256"] = json!("f".repeat(64));
            // reb-api mcp inlines a result only when both forms fit.
            let compact = serde_json::to_vec(&page).unwrap().len();
            let pretty = serde_json::to_string_pretty(&page).unwrap().len();
            assert!(
                compact <= 131_072 && pretty <= 131_072,
                "page at {offset}: {compact} compact and {pretty} pretty bytes"
            );
            rows += page["functions"]["suggestion_window"]["rows"]
                .as_u64()
                .unwrap();
            match page["functions"]["suggestion_window"]["next_offset"].as_u64() {
                Some(next) => offset = next as usize,
                None => break,
            }
        }
        assert_eq!(rows, 1200);
        assert!(offset > 0, "the rows took more than one page");
    }

    #[test]
    fn only_a_table_start_or_a_load_inside_it_is_a_reference() {
        let sbox = wasm_constants::aes_sbox().to_vec();
        let mut body = raw::i32_const(1100);
        body.extend(raw::i32_const(1024));
        body.extend([0x41, 0, 0x2d, 0, 0xd0, 0x08, 0x1a]); // i32.load8_u offset=1104
        let mut sections = raw::functions(1, &body);
        sections.insert(2, raw::memory(1));
        sections.push(raw::data(&[(1024, sbox)]));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let sbox = &constant(&report, "aes_sbox")[0];
        let vias = sbox["referenced_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["via"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        // 1100 is inside the table but names no start: a loop bound or a size.
        assert_eq!(vias, ["address_immediate", "load_offset"], "{sbox:#}");
    }

    #[test]
    fn a_table_split_across_adjacent_segments_is_one_match() {
        let table = crc_bytes();
        let split = raw::module(&[
            raw::memory(1),
            raw::data(&[(1024, table[..512].to_vec()), (1536, table[512..].to_vec())]),
        ]);
        let report = identify(&split, 0, 16).unwrap();
        let crc = constant(&report, "crc32_table");
        assert_eq!(crc.len(), 1, "{report:#}");
        assert_eq!(
            (crc[0]["match"].as_str(), crc[0]["matched"].as_u64()),
            (Some("complete"), Some(256))
        );
        assert_eq!(crc[0]["data_segments"], json!([0, 1]));
        // Not adjacent in memory: two partial matches stay two.
        let apart = raw::module(&[
            raw::memory(1),
            raw::data(&[(1024, table[..512].to_vec()), (4096, table[512..].to_vec())]),
        ]);
        assert_eq!(
            constant(&identify(&apart, 0, 16).unwrap(), "crc32_table").len(),
            2
        );
    }

    #[test]
    fn sha512_initial_values_as_i32_halves_are_sha512() {
        let mut body = Vec::new();
        for value in &wasm_constants::SHA512_H[..4] {
            body.extend(raw::i32_const((value >> 32) as u32));
            body.extend(raw::i32_const(*value as u32));
        }
        let report = identify(&raw::module(&raw::functions(1, &body)), 0, 16).unwrap();
        let wide = constant(&report, "sha512_h");
        assert_eq!(wide.len(), 1, "{report:#}");
        assert_eq!(
            (
                wide[0]["matched"].as_u64(),
                wide[0]["sites"][0]["operator"].as_str()
            ),
            (Some(4), Some("i32.const pair"))
        );
        assert!(constant(&report, "sha256_h").is_empty(), "{report:#}");
    }

    #[test]
    fn one_missing_element_makes_a_table_partial() {
        let table = crc_bytes();
        let full = identify(
            &raw::module(&[raw::memory(1), raw::data(&[(1024, table.clone())])]),
            0,
            16,
        )
        .unwrap();
        assert_eq!(constant(&full, "crc32_table")[0]["match"], "complete");
        let cut = raw::module(&[
            raw::memory(1),
            raw::data(&[(1024, table[..table.len() - 4].to_vec())]),
        ]);
        let report = identify(&cut, 0, 16).unwrap();
        let crc = &constant(&report, "crc32_table")[0];
        assert_eq!(
            (
                crc["match"].as_str(),
                crc["matched"].as_u64(),
                crc["total"].as_u64()
            ),
            (Some("partial"), Some(255), Some(256))
        );
        assert_eq!(report["summary"]["complete_constant_matches"], 0);
    }

    fn custom(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = raw::name(name);
        body.extend(payload);
        raw::section(0, &body)
    }

    fn features(count: usize) -> Vec<u8> {
        let items = (0..count)
            .map(|index| [vec![b'+'], raw::name(&format!("f{index:02}"))].concat())
            .collect::<Vec<_>>();
        raw::vector(&items)
    }

    fn producers_section(field: &str, values: &[&str]) -> Vec<u8> {
        let values = values
            .iter()
            .map(|value| [raw::name(value), raw::name("1")].concat())
            .collect::<Vec<_>>();
        custom(
            "producers",
            &raw::vector(&[[raw::name(field), raw::vector(&values)].concat()]),
        )
    }

    fn omission_lines(report: &Value) -> Vec<String> {
        report["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn feature_and_producer_caps_hold_across_every_section() {
        let many_features = (0..3000)
            .map(|_| custom("target_features", &features(32)))
            .collect::<Vec<_>>();
        let report = identify(&raw::module(&many_features), 0, 16).unwrap();
        assert_eq!(
            report["toolchain"]["target_features"]
                .as_array()
                .unwrap()
                .len(),
            MAX_FEATURES
        );
        assert_eq!(
            report["toolchain"]["custom_sections"]
                .as_array()
                .unwrap()
                .len(),
            MAX_CUSTOM_SECTIONS
        );
        let lines = omission_lines(&report);
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("Target feature limit of 32"))
        );
        assert!(serde_json::to_vec(&report).unwrap().len() < 16_384);

        let values = (0..17)
            .map(|index| format!("tool{index}"))
            .collect::<Vec<_>>();
        let values = values.iter().map(String::as_str).collect::<Vec<_>>();
        let mut many_producers = (0..2000)
            .map(|_| producers_section("processed-by", &values))
            .collect::<Vec<_>>();
        // A toolchain named only by the last section is still concluded.
        many_producers.push(producers_section("language", &["Rust"]));
        let report = identify(&raw::module(&many_producers), 0, 16).unwrap();
        assert_eq!(
            report["toolchain"]["producers"].as_array().unwrap().len(),
            MAX_PRODUCERS
        );
        assert_eq!(conclusion(&report, "rust").unwrap()["confidence"], "high");
        let lines = omission_lines(&report);
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("Producer limit of 16"))
        );
    }

    #[test]
    fn target_features_sections_past_the_cap_are_not_read() {
        // Once 32 features are listed, later sections are skipped unread, so
        // a malformed one after them is never parsed or reported.
        let mut sections = vec![custom("target_features", &features(32))];
        sections.extend((0..100).map(|_| custom("target_features", &[0x80])));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let lines = omission_lines(&report);
        assert!(
            !lines.iter().any(|line| line.contains("malformed")),
            "{lines:#?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("Target feature limit of 32")),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_match_merged_across_segments_is_never_a_container() {
        let catalog = wasm_constants::catalog();
        let set = |id: &str| catalog.iter().position(|set| set.id == id).unwrap();
        let entry = |set: usize, start: usize, end: usize, segments: Vec<u32>, elements: usize| {
            let mut entry = Match {
                set,
                location: "data",
                covered: [0; 4],
                first: 0,
                end_index: elements,
                byte_offset: start,
                byte_end: end,
                preview_end: end,
                segments,
                encoding: Some(Encoding::U32Le),
                runs: 1,
                address: None,
                address_end: None,
                references: Vec::new(),
                reference_count: 0,
                function: None,
                sites: Vec::new(),
                site_count: 0,
                values: BTreeSet::new(),
            };
            entry.cover(0, elements);
            entry
        };
        let merged = entry(set("crc32_table"), 0, 2000, vec![0, 1], 256);
        let inside = entry(set("md5_h"), 600, 616, vec![1], 4);
        let mut expired = false;
        let kept = suppress_data(
            vec![merged, inside],
            Instant::now() + DEADLINE,
            &mut expired,
        );
        assert_eq!(
            kept.len(),
            2,
            "the merged span suppressed a match it does not explain"
        );
        // A single-segment container still explains what it holds.
        let container = entry(set("sha1_h"), 600, 620, vec![1], 5);
        let inside = entry(set("md5_h"), 600, 616, vec![1], 4);
        let kept = suppress_data(
            vec![container, inside],
            Instant::now() + DEADLINE,
            &mut expired,
        );
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn many_malformed_sections_make_one_counted_omission() {
        let sections = (0..70_000)
            .map(|_| custom("target_features", &[0x80]))
            .collect::<Vec<_>>();
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let lines = omission_lines(&report);
        assert!(lines.len() <= 3, "{lines:#?}");
        assert!(
            lines.contains(
                &"A target_features section is malformed; it was not read. (65536 times)"
                    .to_owned()
            ),
            "{lines:#?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("Custom section limit of 65536 reached")),
            "{lines:#?}"
        );
        assert!(serde_json::to_vec(&report).unwrap().len() < 16_384);
    }

    #[test]
    fn reading_and_custom_sections_stop_at_the_deadline() {
        // Enough imports to reach the reader's poll, which runs every 4096 records.
        let imports = (0..5000)
            .map(|index| {
                [
                    raw::name("env"),
                    raw::name(&format!("f{index}")),
                    vec![0, 0],
                ]
                .concat()
            })
            .collect::<Vec<_>>();
        let bytes = raw::module(&[
            raw::section(1, &[1, 0x60, 0, 0]),
            raw::section(2, &raw::vector(&imports)),
        ]);
        let report = identify_within(&bytes, 0, 16, Duration::ZERO).unwrap();
        let omissions = report["omissions"].to_string();
        assert!(
            omissions.contains("deadline reached while reading sections"),
            "{omissions}"
        );
        assert!(report["functions"]["imported_functions"].as_u64().unwrap() < 5000);
        let sections = (0..4)
            .map(|_| custom("target_features", &features(2)))
            .collect::<Vec<_>>();
        let report = identify_within(&raw::module(&sections), 0, 16, Duration::ZERO).unwrap();
        let omissions = report["omissions"].to_string();
        assert!(
            omissions.contains("deadline reached while reading custom sections; 0 of 4"),
            "{omissions}"
        );
    }

    #[test]
    fn demangled_cpp_names_are_not_rust_and_rust_symbol_forms_are() {
        let cpp = [
            "std::terminate()",
            "std::exception::~exception()",
            "log::Logger::write(char const*)",
            "core::Engine::step()",
            "std::bad_alloc::what() const",
        ];
        let names = cpp
            .iter()
            .enumerate()
            .map(|(index, name)| (index as u32, (*name).to_owned()))
            .collect::<Vec<_>>();
        let mut sections = raw::functions(cpp.len(), &[]);
        sections.push(raw::names(&names));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        assert!(conclusion(&report, "rust").is_none(), "{report:#}");
        // A C or C++ producer explains an unhashed `core::` path too.
        let mut sections = raw::functions(1, &[]);
        sections.push(raw::names(&[(0, "core::fmt::write".into())]));
        sections.push(producers_section("language", &["C++14"]));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        assert!(conclusion(&report, "rust").is_none(), "{report:#}");
        assert!(labels(&report, 0).is_empty());
        for (name, crate_name) in [
            (
                "_ZN4core3fmt5write17h0123456789abcdefE.llvm.1234567890",
                "core",
            ),
            ("_RNvNtCs1234abcd_4core3fmt5write", "core"),
            (
                "_RNvMs_NtCsdpfyVJ4iRU_5alloc7raw_vecINtB4_6RawVecpE7reserve",
                "alloc",
            ),
        ] {
            assert_eq!(rust_crate(name), (Some(crate_name), true), "{name}");
        }
        assert_eq!(rust_crate("_ReadFile"), (None, false));
    }

    #[test]
    fn segments_merge_only_forward_and_consecutive() {
        let table = crc_bytes();
        // The second half first in the file: two forward parts, no merged span.
        let reversed = raw::module(&[
            raw::memory(1),
            raw::data(&[(1536, table[512..].to_vec()), (1024, table[..512].to_vec())]),
        ]);
        let report = identify(&reversed, 0, 16).unwrap();
        let parts = constant(&report, "crc32_table");
        assert_eq!(parts.len(), 2, "{report:#}");
        for part in &parts {
            assert!(
                part["byte_offset"].as_u64() < part["byte_end"].as_u64(),
                "{part}"
            );
        }
        // An unrelated segment between the halves: they stay apart, and the
        // complete SHA-256 table between them is still reported.
        let k = raw::words(&wasm_constants::SHA256_K);
        let sandwich = raw::module(&[
            raw::memory(1),
            raw::data(&[
                (1024, table[..512].to_vec()),
                (8192, k),
                (1536, table[512..].to_vec()),
            ]),
        ]);
        let report = identify(&sandwich, 0, 16).unwrap();
        assert_eq!(constant(&report, "crc32_table").len(), 2, "{report:#}");
        assert_eq!(
            constant(&report, "sha256_k")[0]["match"],
            "complete",
            "{report:#}"
        );
        // Past eight segments the rest is a separate match, and that is said.
        let parts = (0..10)
            .map(|part| {
                (
                    1024 + part * 104,
                    table[part as usize * 104..((part as usize + 1) * 104).min(1024)].to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let report = identify(&raw::module(&[raw::memory(1), raw::data(&parts)]), 0, 16).unwrap();
        assert_eq!(constant(&report, "crc32_table").len(), 2, "{report:#}");
        assert!(
            report["omissions"]
                .to_string()
                .contains("spans more than 8 segments"),
            "{report:#}"
        );
    }

    #[test]
    fn sha512_halves_stored_to_static_addresses_are_sha512() {
        let mut body = Vec::new();
        for (index, value) in wasm_constants::SHA512_H.iter().enumerate() {
            let address = 2048 + 8 * index as i64;
            for (half, offset) in [(*value as u32, 0u8), ((value >> 32) as u32, 4)] {
                body.push(0x41);
                body.extend(raw::sleb(address));
                body.push(0x41);
                body.extend(raw::sleb(i64::from(half as i32)));
                body.extend([0x36, 2, offset]);
            }
        }
        let mut sections = raw::functions(1, &body);
        sections.insert(2, raw::memory(1));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let wide = constant(&report, "sha512_h");
        assert_eq!(
            (wide.len(), wide[0]["match"].as_str()),
            (1, Some("complete")),
            "{report:#}"
        );
        assert!(constant(&report, "sha256_h").is_empty(), "{report:#}");
    }

    #[test]
    fn the_strongest_evidence_comes_first() {
        let imports = raw::vector(&[
            [raw::name("env"), raw::name("invoke_vi"), vec![0, 0]].concat(),
            [raw::name("env"), raw::name("invoke_ii"), vec![0, 0]].concat(),
        ]);
        let exports = raw::vector(&[[raw::name("emscripten_stack_init"), vec![0, 2]].concat()]);
        let mut sections = raw::functions(1, &[]);
        sections.insert(1, raw::section(2, &imports));
        sections.insert(3, raw::section(7, &exports));
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let emscripten = conclusion(&report, "emscripten").unwrap();
        assert_eq!(emscripten["confidence"], "high");
        assert_eq!(
            emscripten["evidence"][0]["confidence"], "high",
            "{emscripten:#}"
        );
        assert_eq!(emscripten["evidence"][0]["record"], "export");
    }

    #[test]
    fn a_trimmed_page_states_how_many_matches_it_left_out() {
        // Long evidence for many toolchains and 100 referenced matches push
        // the fixed part past its budget, so the page is trimmed.
        let quarter = raw::words(&wasm_constants::SHA256_K[..16]);
        let mut segments = Vec::new();
        let mut body = Vec::new();
        for index in 0..100u32 {
            segments.push((4096 + index * 80, quarter.clone()));
            body.extend(raw::i32_const(4096 + index * 80));
        }
        let mut sections = raw::functions(40, &body);
        let prefixes = [
            "emscripten_",
            "__wbindgen_",
            "asyncify_",
            "~lib/",
            "mono_wasm_",
            "__wasi_",
            "runtime.",
            "dynCall_",
        ];
        let names = (0..40u32)
            .map(|index| {
                (
                    index,
                    format!("{}{}{index}", prefixes[index as usize % 8], "x".repeat(150)),
                )
            })
            .collect::<Vec<_>>();
        sections.insert(2, raw::memory(4));
        sections.push(raw::data(&segments));
        sections.push(raw::names(&names));
        for index in 0..40 {
            sections.push(custom(&format!("{}{index}", "c".repeat(120)), &[]));
        }
        let report = identify(&raw::module(&sections), 0, 16).unwrap();
        let lines = omission_lines(&report);
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("Report trimmed to fit one page")),
            "{lines:#?}"
        );
        let listed = report["constants"]["matches"].as_array().unwrap().len();
        let total = report["summary"]["constant_matches"].as_u64().unwrap() as usize;
        assert!(listed < MAX_MATCHES);
        let expected = format!(
            "Constant match limit of {listed} reached; {} later matches are counted, not listed.",
            total - listed
        );
        assert!(lines.contains(&expected), "{expected}\n{lines:#?}");
    }

    /// Every SHA-2 table digests as the sha2 crate does, so a copied table
    /// cannot drift silently.
    #[test]
    fn sha2_tables_reproduce_sha2_digests() {
        use sha2::Digest;
        use wasm_constants::{SHA224_H, SHA256_H, SHA256_K, SHA384_H, SHA512_H, SHA512_K};
        fn sha256(initial: &[u32; 8], message: &[u8], out: usize) -> Vec<u8> {
            let mut state = *initial;
            let mut data = message.to_vec();
            data.push(0x80);
            while data.len() % 64 != 56 {
                data.push(0);
            }
            data.extend(((message.len() as u64) * 8).to_be_bytes());
            for block in data.chunks(64) {
                let mut w = [0u32; 64];
                for i in 0..16 {
                    w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
                }
                for i in 16..64 {
                    let s0 =
                        w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                    let s1 =
                        w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[i - 7])
                        .wrapping_add(s1);
                }
                let mut v = state;
                for i in 0..64 {
                    let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                    let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                    let t1 = v[7]
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(SHA256_K[i])
                        .wrapping_add(w[i]);
                    let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                    let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                    let t2 = s0.wrapping_add(maj);
                    v = [
                        t1.wrapping_add(t2),
                        v[0],
                        v[1],
                        v[2],
                        v[3].wrapping_add(t1),
                        v[4],
                        v[5],
                        v[6],
                    ];
                }
                for (slot, value) in state.iter_mut().zip(v) {
                    *slot = slot.wrapping_add(value);
                }
            }
            state
                .iter()
                .flat_map(|word| word.to_be_bytes())
                .take(out)
                .collect()
        }
        fn sha512(initial: &[u64; 8], message: &[u8], out: usize) -> Vec<u8> {
            let mut state = *initial;
            let mut data = message.to_vec();
            data.push(0x80);
            while data.len() % 128 != 112 {
                data.push(0);
            }
            data.extend(((message.len() as u128) * 8).to_be_bytes());
            for block in data.chunks(128) {
                let mut w = [0u64; 80];
                for i in 0..16 {
                    w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
                }
                for i in 16..80 {
                    let s0 =
                        w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                    let s1 =
                        w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                    w[i] = w[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[i - 7])
                        .wrapping_add(s1);
                }
                let mut v = state;
                for i in 0..80 {
                    let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
                    let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                    let t1 = v[7]
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(SHA512_K[i])
                        .wrapping_add(w[i]);
                    let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
                    let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                    let t2 = s0.wrapping_add(maj);
                    v = [
                        t1.wrapping_add(t2),
                        v[0],
                        v[1],
                        v[2],
                        v[3].wrapping_add(t1),
                        v[4],
                        v[5],
                        v[6],
                    ];
                }
                for (slot, value) in state.iter_mut().zip(v) {
                    *slot = slot.wrapping_add(value);
                }
            }
            state
                .iter()
                .flat_map(|word| word.to_be_bytes())
                .take(out)
                .collect()
        }
        for message in [&b""[..], b"abc", &[0x5a; 200]] {
            assert_eq!(
                sha256(&SHA256_H, message, 32),
                sha2::Sha256::digest(message).to_vec()
            );
            assert_eq!(
                sha256(&SHA224_H, message, 28),
                sha2::Sha224::digest(message).to_vec()
            );
            assert_eq!(
                sha512(&SHA512_H, message, 64),
                sha2::Sha512::digest(message).to_vec()
            );
            assert_eq!(
                sha512(&SHA384_H, message, 48),
                sha2::Sha384::digest(message).to_vec()
            );
        }
    }

    #[test]
    fn md5_crc_and_aes_tables_reproduce_known_vectors() {
        fn md5(message: &[u8]) -> String {
            const SHIFTS: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
            let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
            let mut data = message.to_vec();
            data.push(0x80);
            while data.len() % 64 != 56 {
                data.push(0);
            }
            data.extend(((message.len() as u64) * 8).to_le_bytes());
            for block in data.chunks(64) {
                let m = (0..16)
                    .map(|i| u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()))
                    .collect::<Vec<_>>();
                let [mut a, mut b, mut c, mut d] = state;
                for i in 0..64 {
                    let (f, g) = match i / 16 {
                        0 => ((b & c) | (!b & d), i),
                        1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                        2 => (b ^ c ^ d, (3 * i + 5) % 16),
                        _ => (c ^ (b | !d), (7 * i) % 16),
                    };
                    let rotated = a
                        .wrapping_add(f)
                        .wrapping_add(wasm_constants::MD5_T[i])
                        .wrapping_add(m[g])
                        .rotate_left(SHIFTS[(i / 16) * 4 + i % 4]);
                    (a, b, c, d) = (d, b.wrapping_add(rotated), b, c);
                }
                for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
                    *slot = slot.wrapping_add(value);
                }
            }
            hex::encode(
                state
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        }
        assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        let check = |polynomial, reflected, init: u32, xorout: u32| {
            let table = wasm_constants::crc_table(polynomial, reflected);
            let mut crc = init;
            for byte in b"123456789" {
                crc = if reflected {
                    (crc >> 8) ^ table[((crc ^ u32::from(*byte)) & 0xff) as usize]
                } else {
                    (crc << 8) ^ table[(((crc >> 24) ^ u32::from(*byte)) & 0xff) as usize]
                };
            }
            crc ^ xorout
        };
        assert_eq!(check(0xedb8_8320, true, !0, !0), 0xcbf4_3926);
        assert_eq!(check(0x82f6_3b78, true, !0, !0), 0xe306_9283);
        assert_eq!(check(0x04c1_1db7, false, !0, !0), 0xfc89_1918);
        let sbox = wasm_constants::aes_sbox();
        assert_eq!(
            (sbox[0x00], sbox[0x01], sbox[0x53], sbox[0xff]),
            (0x63, 0x7c, 0xed, 0x16)
        );
        let te0 = &wasm_constants::catalog()
            .iter()
            .find(|set| set.id == "aes_te0")
            .unwrap()
            .values;
        let td0 = &wasm_constants::catalog()
            .iter()
            .find(|set| set.id == "aes_td0")
            .unwrap()
            .values;
        assert_eq!((te0[0], te0[1]), (0xc663_63a5, 0xf87c_7c84));
        assert_eq!(td0[0], 0x51f4_a750);
        // Each set id is unique, so a match names one set.
        let ids = wasm_constants::catalog()
            .iter()
            .map(|set| set.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), wasm_constants::catalog().len());
    }
}
