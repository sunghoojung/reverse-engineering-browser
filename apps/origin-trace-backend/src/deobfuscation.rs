use crate::{
    error::{Error, Result},
    worker,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::LazyLock,
    time::Duration,
};
use tokio::{process::Command, sync::Mutex};
const SOURCE_MAX: usize = 4 * 1024 * 1024;
pub struct Deobfuscator {
    path: PathBuf,
    lock: Mutex<()>,
}
impl Deobfuscator {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }
    pub async fn analyze(
        &self,
        source: &str,
        assume_intrinsics: bool,
        derived: bool,
    ) -> Result<Value> {
        if source.is_empty() || source.len() > SOURCE_MAX {
            return Err(Error::bad(
                "Source is empty or exceeds the deobfuscation byte limit",
            ));
        }
        if !worker::executable(&self.path) {
            return Err(Error::new(
                503,
                "The Rust JavaScript analysis worker is unavailable",
            ));
        }
        let _guard = self.lock.try_lock().map_err(|_| {
            Error::conflict("Deobfuscation worker is busy; retry when analysis finishes")
        })?;
        let mut input =
            serde_json::to_vec(&json!({"source":source,"assume_intrinsics":assume_intrinsics}))?;
        input.push(b'\n');
        let output = worker::run(
            Command::new(&self.path)
                .env_clear()
                .env("LANG", "C")
                .env("LC_ALL", "C"),
            &input,
            32 * 1024 * 1024,
            Duration::from_secs(5),
        )
        .await?;
        if !output.success {
            return Err(Error::new(
                502,
                "JavaScript analysis worker terminated unexpectedly; original source is preserved",
            ));
        }
        let response: Value = serde_json::from_slice(&output.bytes)
            .map_err(|_| Error::new(502, "Deobfuscation worker returned malformed JSON"))?;
        let representation = representation(source, &response, assume_intrinsics)?;
        let stats = metrics(source);
        let classification = classify(&stats);
        let analysis = json!({"schema":"deobfuscation-analysis-v1","source":{"url":null,"sha256":hex::encode(Sha256::digest(source.as_bytes())),"byte_size":source.len(),"lines":source.matches('\n').count()+1},"classification":classification,"stats":stats,"assumptions":representation["assumptions"],"representation":{"status":if representation["text"]==source {"unchanged"} else {"derived"},"derived_bytes":representation["text"].as_str().unwrap().len(),"segment_count":representation["segments"].as_array().unwrap().len(),"truncated":representation["truncated"],"transformations":representation["transformations"]},"string_tables":tables(source),"omissions":["Unsupported decoder operations, custom prototype hooks, mutable or escaping tables, and cross-scope propagation remain unresolved."],"limits":{"max_source_bytes":SOURCE_MAX,"max_derived_bytes":2097152,"max_segments":250000,"max_string_tables":64,"max_string_entries":2048}});
        let mut result = json!({"schema":"deobfuscation-analysis-v1","engine":"rust-oxc","original_source":source,"source_truncated":false,"analysis":analysis});
        if derived {
            result["representation"] = representation;
        }
        Ok(result)
    }
}
fn representation(source: &str, response: &Value, intrinsics: bool) -> Result<Value> {
    let malformed = || Error::new(502, "Deobfuscation worker returned an invalid response");
    if response["schema"] != "reb-deobfuscator-worker-v1" {
        return Err(malformed());
    }
    if response["ok"] != true {
        return Err(Error::new(422, "JavaScript could not be parsed"));
    }
    let assumptions = json!(if intrinsics {
        vec!["standard-intrinsics"]
    } else {
        Vec::<&str>::new()
    });
    if response["assumptions"] != assumptions || !response["transformations_truncated"].is_boolean()
    {
        return Err(malformed());
    }
    let rewrites = response["transformations"]
        .as_array()
        .filter(|a| a.len() <= 4096)
        .ok_or_else(malformed)?;
    let derived = response["derived_source"].as_str().ok_or_else(malformed)?;
    let mut rebuilt = String::new();
    let mut segments = Vec::new();
    let mut offset = 0;
    let mut counts = BTreeMap::<String, usize>::new();
    for rewrite in rewrites {
        let start = rewrite["original_start"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(malformed)?;
        let end = rewrite["original_end"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(malformed)?;
        if start < offset
            || end <= start
            || end > source.len()
            || !source.is_char_boundary(start)
            || !source.is_char_boundary(end)
        {
            return Err(malformed());
        }
        if start > offset {
            append(
                &mut rebuilt,
                &mut segments,
                "verbatim",
                offset,
                start,
                &source[offset..start],
            );
        }
        append(
            &mut rebuilt,
            &mut segments,
            "replacement",
            start,
            end,
            rewrite["replacement"].as_str().ok_or_else(malformed)?,
        );
        let kind = rewrite["kind"]
            .as_str()
            .filter(|s| s.len() <= 128)
            .ok_or_else(malformed)?;
        *counts.entry(kind.into()).or_default() += 1;
        offset = end;
    }
    if offset < source.len() {
        append(
            &mut rebuilt,
            &mut segments,
            "verbatim",
            offset,
            source.len(),
            &source[offset..],
        );
    }
    if rebuilt != derived {
        return Err(malformed());
    }
    Ok(
        json!({"text":derived,"assumptions":assumptions,"offset_unit":"utf-8-byte","segments":segments,"truncated":response["transformations_truncated"],"transformations":counts.into_iter().map(|(kind,count)|json!({"id":kind,"kind":"rewrite","count":count,"detail":"Static AST rewrite with original-source mapping; no JavaScript execution."})).collect::<Vec<_>>()}),
    )
}
fn append(
    output: &mut String,
    segments: &mut Vec<Value>,
    kind: &str,
    start: usize,
    end: usize,
    text: &str,
) {
    let begin = output.len();
    output.push_str(text);
    segments.push(json!({"kind":kind,"original_start":start,"original_end":end,"derived_start":begin,"derived_end":output.len()}));
}
static PATTERNS: LazyLock<BTreeMap<&'static str, Regex>> = LazyLock::new(|| {
    [
    ("hex_escapes",r"\\x[0-9a-fA-F]{2}"),
    ("unicode_escapes",r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]{1,6}\})"),
    ("obfuscated_identifiers",r"\b_0x[0-9a-fA-F]{2,}\b"),
    ("base64_blobs",r"[A-Za-z0-9+/]{200,}={0,2}"),
    ("percent_blobs",r"(?:%[0-9a-fA-F]{2}){64,}"),
    ("dynamic_code_calls",r"\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(|document\.write\s*\("),
    ("packer_signature",r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,"),
    ("blob_decoders",r"(?:atob|fromCharCode|decodeURIComponent|unescape)\s*\("),
    ("identifier",r"[A-Za-z_$][\w$]*"),
    ("number",r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?n?)"),
    ("string",r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#),
    ("string_array",r#"\[\s*(?:(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*,\s*){7,}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*\]"#),
    ("code_array",r"\[\s*(?:\d{1,7}\s*,\s*){7,}\d{1,7}\s*\]"),
    ("integer",r"\d{1,7}"),
    ("function",r"function\s+([A-Za-z_$][\w$]*)\s*\("),
].into_iter().map(|(key,pattern)|(key,Regex::new(pattern).expect("source analysis pattern"))).collect()
});
#[derive(Clone, Copy)]
struct Token {
    kind: &'static str,
    start: usize,
    end: usize,
}
fn scan(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut previous = "";
    while index < source.len() {
        let ch = source[index..].chars().next().unwrap();
        let start = index;
        let mut end = index + ch.len_utf8();
        let mut kind = "punct";
        if ch.is_whitespace() {
            kind = "whitespace";
            while end < source.len() {
                let ch = source[end..].chars().next().unwrap();
                if !ch.is_whitespace() {
                    break;
                }
                end += ch.len_utf8();
            }
        } else if source[index..].starts_with("//") {
            kind = "comment";
            end = source[index..]
                .find('\n')
                .map_or(source.len(), |n| index + n);
        } else if source[index..].starts_with("/*") {
            kind = "comment";
            end = source[index + 2..]
                .find("*/")
                .map_or(source.len(), |n| index + 2 + n + 2);
        } else if "\"'`".contains(ch) {
            kind = if ch == '`' { "template" } else { "string" };
            let mut escaped = false;
            while end < source.len() {
                let c = source[end..].chars().next().unwrap();
                if !escaped && c == '\n' && ch != '`' {
                    break;
                }
                end += c.len_utf8();
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == ch {
                    break;
                }
            }
        } else if ch.is_ascii_digit()
            || ch == '.' && source[end..].starts_with(|c: char| c.is_ascii_digit())
        {
            if let Some(m) = PATTERNS["number"]
                .find_at(source, index)
                .filter(|m| m.start() == index)
            {
                kind = "number";
                end = m.end();
            }
        } else if ch.is_alphabetic() || "_$".contains(ch) || !ch.is_ascii() {
            if let Some(m) = PATTERNS["identifier"]
                .find_at(source, index)
                .filter(|m| m.start() == index)
            {
                kind = "identifier";
                end = m.end();
            }
        } else if ch == '/'
            && (previous.is_empty()
                || "([{,;=:!&|?+-*%^~<>".contains(previous)
                || [
                    "await",
                    "case",
                    "delete",
                    "do",
                    "else",
                    "in",
                    "instanceof",
                    "new",
                    "of",
                    "return",
                    "typeof",
                    "void",
                    "yield",
                ]
                .contains(&previous))
        {
            let mut escaped = false;
            let mut class = false;
            let mut cursor = end;
            while cursor < source.len() {
                let c = source[cursor..].chars().next().unwrap();
                cursor += c.len_utf8();
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '\n' {
                    break;
                } else if c == '[' {
                    class = true;
                } else if c == ']' {
                    class = false;
                } else if c == '/' && !class {
                    while cursor < source.len() {
                        let c = source[cursor..].chars().next().unwrap();
                        if !c.is_alphabetic() {
                            break;
                        }
                        cursor += c.len_utf8();
                    }
                    kind = "regexp";
                    end = cursor;
                    break;
                }
            }
        }
        if !["comment", "whitespace"].contains(&kind) {
            previous = if ["string", "number", "template", "regexp"].contains(&kind) {
                kind
            } else {
                &source[start..end]
            };
        }
        tokens.push(Token { kind, start, end });
        index = end;
    }
    tokens
}
fn round(value: f64, precision: i32) -> f64 {
    let scale = 10_f64.powi(precision);
    (value * scale).round_ties_even() / scale
}
fn metrics(source: &str) -> Value {
    let tokens = scan(source);
    let lines = source.split('\n').collect::<Vec<_>>();
    let nonempty = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    let whitespace = tokens
        .iter()
        .filter(|t| t.kind == "whitespace")
        .map(|t| source[t.start..t.end].chars().count())
        .sum::<usize>();
    let ids = tokens
        .iter()
        .filter(|t| t.kind == "identifier")
        .collect::<Vec<_>>();
    let chars = source.chars().count();
    let mut result = json!({"bytes":source.len(),"characters":chars,"lines":lines.len(),"non_empty_lines":nonempty.len(),"max_line_length":lines.iter().map(|l|l.chars().count()).max().unwrap_or(0),"mean_line_length":round(nonempty.iter().map(|l|l.chars().count()).sum::<usize>() as f64/nonempty.len().max(1) as f64,2),"whitespace_ratio":round(whitespace as f64/chars.max(1) as f64,4),"identifiers":ids.len(),"short_identifier_ratio":round(ids.iter().filter(|t|source[t.start..t.end].chars().count()<=2).count() as f64/ids.len().max(1) as f64,4)});
    for key in [
        "hex_escapes",
        "unicode_escapes",
        "obfuscated_identifiers",
        "base64_blobs",
        "percent_blobs",
        "dynamic_code_calls",
        "blob_decoders",
    ] {
        result[key] = json!(PATTERNS[key].find_iter(source).count());
    }
    result["packer_signature"] = json!(PATTERNS["packer_signature"].is_match(source));
    result
}
fn classify(m: &Value) -> Value {
    let n = |key: &str| m[key].as_f64().unwrap_or(0.0);
    let mut evidence = Vec::new();
    let mut add = |id: &str, weight: i32, detail: &str, value: Value| {
        evidence.push(json!({"id":id,"weight":weight,"detail":detail,"value":value}));
        weight
    };
    let mut packed = 0;
    let mut obfuscated = 0;
    let mut minified = 0;
    if m["packer_signature"] == true {
        packed += add(
            "packer-signature",
            60,
            "Matches the classic evaluate-a-decoder-function packer shape.",
            json!(true),
        );
    }
    if n("dynamic_code_calls") > 0.0 && n("base64_blobs") + n("percent_blobs") > 0.0 {
        packed += add(
            "packed-blob",
            45,
            "Dynamic code construction next to a large encoded blob.",
            json!({"dynamic_code_calls":m["dynamic_code_calls"],"blobs":n("base64_blobs") as u64+n("percent_blobs") as u64}),
        );
    }
    for (key, threshold, weight, id, detail) in [
        (
            "obfuscated_identifiers",
            10.0,
            40,
            "hex-identifiers",
            "Hexadecimal _0x-prefixed identifiers dominate the script.",
        ),
        (
            "hex_escapes",
            20.0,
            35,
            "hex-escapes",
            "String literals are written as hexadecimal escape runs.",
        ),
        (
            "unicode_escapes",
            20.0,
            35,
            "unicode-escapes",
            "String literals are written as unicode escape runs.",
        ),
    ] {
        if n(key) >= threshold {
            obfuscated += add(id, weight, detail, m[key].clone());
        }
    }
    if n("blob_decoders") > 0.0 && n("hex_escapes") + n("obfuscated_identifiers") > 0.0 {
        obfuscated += add(
            "encoded-string-table",
            20,
            "Blob decoders run over escape-encoded strings or hex identifiers.",
            m["blob_decoders"].clone(),
        );
    }
    if n("non_empty_lines") > 0.0 && n("mean_line_length") >= 120.0 {
        minified += add(
            "long-lines",
            35,
            "Non-empty lines are far longer than hand-written source.",
            m["mean_line_length"].clone(),
        );
    }
    if n("whitespace_ratio") <= 0.12 {
        minified += add(
            "low-whitespace",
            25,
            "Whitespace is too sparse for hand-written source.",
            m["whitespace_ratio"].clone(),
        );
    }
    if n("short_identifier_ratio") >= 0.5 && n("identifiers") >= 50.0 {
        minified += add(
            "short-identifiers-widespread",
            15,
            "Identifier minification is widespread, not local to one scope.",
            m["short_identifier_ratio"].clone(),
        );
    }
    let label = if packed >= 45 && packed >= obfuscated {
        "packed"
    } else if obfuscated >= 35 {
        "obfuscated"
    } else if minified >= 35 {
        "minified"
    } else {
        "readable"
    };
    let scores = [
        ("packed", packed),
        ("obfuscated", obfuscated),
        ("minified", minified),
    ];
    if label == "readable" {
        evidence.push(json!({"id":"readable-baseline","weight":0,"detail":"No packing, obfuscation, or minification evidence passed threshold.","value":{"mean_line_length":m["mean_line_length"],"whitespace_ratio":m["whitespace_ratio"]}}));
    }
    let competing = scores
        .iter()
        .filter(|(k, v)| *k != label && *v > 0)
        .map(|(_, v)| *v)
        .max()
        .unwrap_or(0);
    let confidence = if label == "readable" {
        50
    } else {
        (40 + scores.iter().find(|(k, _)| *k == label).unwrap().1 - competing / 2).min(95)
    };
    let mut alternatives = scores
        .into_iter()
        .filter(|(k, v)| *k != label && *v > 0)
        .collect::<Vec<_>>();
    alternatives.sort_by_key(|(_, v)| -v);
    json!({"label":label,"confidence":confidence.clamp(0,100),"scores":{"packed":packed,"obfuscated":obfuscated,"minified":minified},"evidence":evidence,"alternatives":alternatives.into_iter().map(|(label,score)|json!({"label":label,"score":score})).collect::<Vec<_>>()})
}
fn unescape(body: &str) -> String {
    let chars = body.chars().collect::<Vec<_>>();
    let mut index = 0;
    let mut result = String::new();
    while index < chars.len() {
        let c = chars[index];
        if c != '\\' || index + 1 >= chars.len() {
            result.push(c);
            index += 1;
            continue;
        }
        let marker = chars[index + 1];
        let (start, end, next) = if marker == 'x' && index + 4 <= chars.len() {
            (index + 2, index + 4, index + 4)
        } else if marker == 'u' && chars.get(index + 2) == Some(&'{') {
            if let Some(end) = chars[index + 3..].iter().position(|c| *c == '}') {
                (index + 3, index + 3 + end, index + 4 + end)
            } else {
                (0, 0, 0)
            }
        } else if marker == 'u' && index + 6 <= chars.len() {
            (index + 2, index + 6, index + 6)
        } else {
            (0, 0, 0)
        };
        if end > start && end - start <= 6 {
            let digits = chars[start..end].iter().collect::<String>();
            if let Ok(n) = u32::from_str_radix(&digits, 16) {
                result.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                index = next;
                continue;
            }
        }
        result.push(match marker {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'v' => '\u{b}',
            '0' => '\0',
            c => c,
        });
        index += 2;
    }
    result
}
fn chars_limit(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}
fn decode_literal(raw: &str) -> (String, &'static str) {
    let body = &raw[1..raw.len() - 1];
    let decoded = unescape(body);
    let mut encoding = if body.contains("\\x") || body.contains("\\u") {
        "escape-sequence"
    } else {
        "literal"
    };
    let mut text = decoded.clone();
    if encoding == "literal" && decoded.chars().count() >= 8 {
        for (name, bytes) in [
            ("base64", STANDARD.decode(decoded.trim()).ok()),
            ("hex", hex::decode(decoded.trim()).ok()),
        ] {
            if let Some(bytes) = bytes.filter(|b| !b.is_empty()) {
                let candidate = String::from_utf8_lossy(&bytes);
                let count = candidate.chars().count();
                let printable = candidate
                    .chars()
                    .filter(|c| !c.is_control() || (name == "base64" && "\n\t".contains(*c)))
                    .count();
                if count > 0 && printable as f64 / count as f64 >= 0.85 {
                    text = candidate.into_owned();
                    encoding = name;
                    break;
                }
            }
        }
    }
    (chars_limit(&text, 4096), encoding)
}
fn hint(source: &str, boundary: usize) -> Value {
    let window = source[boundary..].chars().take(2000).collect::<String>();
    let definition = PATTERNS["function"].captures(&window);
    json!({"kind":if definition.is_some() {"function-definition-near-table"} else {"none"},"name":definition.as_ref().map(|d|d[1].to_owned()),"offset":definition.as_ref().map(|d|source[..boundary].chars().count()+window[..d.get(0).unwrap().start()].chars().count()),"dynamic_code_nearby":PATTERNS["dynamic_code_calls"].is_match(&window),"confidence":if definition.is_some() {"low"} else {"none"},"note":"A nearby definition is a hint, not proof, that it decodes this table."})
}
fn tables(source: &str) -> Vec<Value> {
    let mut tables = Vec::new();
    let mut used = 0;
    for m in PATTERNS["code_array"].find_iter(source) {
        if tables.len() >= 64 || used >= 2048 {
            break;
        }
        let numbers = PATTERNS["integer"]
            .find_iter(m.as_str())
            .map(|n| (n.as_str().parse::<u32>().unwrap(), m.start() + n.start()))
            .collect::<Vec<_>>();
        if numbers.iter().any(|(n, _)| char::from_u32(*n).is_none()) {
            continue;
        }
        let decoded = numbers
            .iter()
            .map(|(n, _)| char::from_u32(*n).unwrap())
            .collect::<String>();
        if decoded
            .chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .count() as f64
            / (numbers.len() as f64)
            < 0.85
        {
            continue;
        }
        if used + numbers.len() > 2048 {
            break;
        }
        used += numbers.len();
        tables.push(json!({"kind":"code-point-array","offset":source[..m.start()].chars().count(),"length":m.as_str().chars().count(),"entry_count":numbers.len(),"encodings":["code-point"],"entries":numbers.iter().enumerate().map(|(i,(n,offset))|json!({"index":i,"offset":source[..*offset].chars().count(),"raw":n.to_string(),"encoding":"code-point","value":char::from_u32(*n).unwrap().to_string()})).collect::<Vec<_>>(),"decoded_preview":chars_limit(&decoded,512),"decoder_hint":hint(source,m.end())}));
    }
    for m in PATTERNS["string_array"].find_iter(source) {
        if tables.len() >= 64 || used >= 2048 {
            break;
        }
        let mut entries = Vec::new();
        let mut encodings = BTreeSet::new();
        for (i, literal) in PATTERNS["string"].find_iter(m.as_str()).enumerate() {
            if used >= 2048 {
                break;
            }
            let (value, encoding) = decode_literal(literal.as_str());
            used += 1;
            encodings.insert(encoding);
            entries.push(json!({"index":i,"offset":source[..m.start()+literal.start()].chars().count(),"raw":chars_limit(literal.as_str(),4096),"encoding":encoding,"value":value}));
        }
        if entries.len() < 8 {
            continue;
        }
        tables.push(json!({"kind":"string-array","offset":source[..m.start()].chars().count(),"length":m.as_str().chars().count(),"entry_count":entries.len(),"encodings":encodings,"entries":entries,"decoder_hint":hint(source,m.end())}));
    }
    tables.sort_by_key(|v| v["offset"].as_u64());
    tables
}
