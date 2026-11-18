use crate::{
    durable,
    error::{Error, Result},
    evidence,
};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    sync::LazyLock,
};
use wasmparser::{ElementItems, ElementKind, Operator, Parser, Payload, TypeRef};
#[path = "vm_capture_mode.rs"]
pub(crate) mod capture_mode;
#[path = "vm_dispatch_shape.rs"]
pub(crate) mod dispatch_shape;
#[path = "vm_document.rs"]
pub mod document;
#[path = "vm_input.rs"]
mod input;
pub(crate) use reb_js_lexer as js_lexer;
#[cfg(test)]
#[path = "vm_review_inputs.rs"]
pub(crate) mod review_inputs;
#[path = "vm_wasm_control.rs"]
pub(crate) mod wasm_control;
#[path = "vm_wasm_dispatch.rs"]
mod wasm_dispatch;
#[path = "vm_wasm_tables.rs"]
pub(crate) mod wasm_tables;
pub use document::Analysis;
pub(crate) use input::Runtime;

const PROFILE: &str = "anti-bot-vm-detection-v1";
static CONFIG: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/vm-profile.json")).expect("VM profile")
});
static JS_RULES: LazyLock<Vec<(&str, &str, Vec<Regex>)>> = LazyLock::new(|| {
    [
        (
            "js.instruction-pointer",
            "A program-counter-like binding is advanced or assigned.",
            vec![r"\b(?:pc|ip|instructionPointer|offset|cursor)\b\s*(?:\+\+|--|[+\-]?=)"],
        ),
        (
            "js.indexed-bytecode-read",
            "A byte-oriented candidate guest program is read by index.",
            vec![
                r"(?i)\b(?:program|bytecode|code|instructions|opcodes|bytes)\s*\[[^\]]+\]",
                r"\b(?:Uint8Array|DataView)\b",
            ],
        ),
        (
            "js.state-effects",
            "Stack, register, accumulator, or memory-like state is mutated.",
            vec![
                r"\.(?:push|pop|shift|unshift)\s*\(",
                r"(?i)\b(?:stack|registers?|accumulator|memory)\b\s*(?:\[|[+\-^|&]?=)",
            ],
        ),
        (
            "js.handler-selection",
            "Opcode cases or an indexed handler collection selects behavior.",
            vec![
                r#"(?i)\bcase\s+(?:0x[0-9a-f]+|\d+|['"][^'"]+['"])?\s*:"#,
                r"(?i)\b(?:handlers?|opcodes?)\s*\[[^\]]+\]",
            ],
        ),
        (
            "js.bounded-exit",
            "A dispatch candidate contains an explicit exit or unknown-opcode frontier.",
            vec![r"\b(?:return|break|throw)\b"],
        ),
    ]
    .into_iter()
    .map(|(id, detail, patterns)| {
        (
            id,
            detail,
            patterns
                .into_iter()
                .map(|p| Regex::new(p).expect("VM rule"))
                .collect(),
        )
    })
    .collect()
});
static ANTI: LazyLock<Vec<(&str, u64, Regex)>> = LazyLock::new(|| {
    [
    ("antibot.canvas-webgl",25,r"(?i)\b(?:canvas|getImageData|toDataURL|webgl|readPixels|getParameter)\b"),
    ("antibot.navigator-device",25,r"(?i)\b(?:navigator|screen|hardwareConcurrency|deviceMemory|platform|timezone|language)\b"),
    ("antibot.automation",20,r"(?i)\b(?:webdriver|automation|headless|permissions\.query)\b"),
    ("antibot.encoding-crypto",15,r"(?i)\b(?:crypto|subtle|digest|base64|btoa|encode|hash)\b"),
    ("antibot.request",15,r"(?i)\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b"),
].into_iter().map(|(id,weight,p)|(id,weight,Regex::new(p).expect("Anti-bot rule"))).collect()
});
pub(crate) fn current_producer() -> Value {
    json!({"id":"origin-trace-vm-detector","version":"1.11.0"})
}

// The catalog and generated documents share this exact profile projection.
// Keep bibliography revisions outside it so citations never rewrite analysis identity.
pub(crate) fn current_profile() -> Value {
    let mut limits = serde_json::Map::new();
    for (key, value) in CONFIG.as_object().unwrap() {
        if let Some(name) = key.strip_prefix("MAX_")
            && name != "JS_FUNCTION_SIGNATURE_CHARACTERS"
        {
            limits.insert(format!("max_{}", name.to_ascii_lowercase()), value.clone());
        }
    }
    json!({"profile_id":PROFILE,"javascript_scoring_version":3,"javascript_likely_vm_requires_handlers":true,"candidate_threshold":20,"likely_vm_threshold":60,"likely_vm_required_families":3,"rule_weights":CONFIG["RULE_WEIGHTS"],"runtime_evidence_version":2,"runtime_rule_weights":runtime_weights(),"limits":limits})
}

pub(crate) fn current_rule_definitions() -> Vec<Value> {
    let mut rules = Vec::new();
    for (id, weight) in CONFIG["RULE_WEIGHTS"].as_object().unwrap() {
        let detail = JS_RULES.iter().find(|(rule, _, _)| *rule == id)
            .map(|(_, detail, _)| *detail).unwrap_or_else(|| match id.as_str() {
                "js.dispatch-loop" => "A loop and a switch, indexed call or called alias of an indexed read, or a threaded cycle of a table literal's functions dispatching it again, occur in one approximate function region.",
                "wasm.dispatch-loop" => "Decoded br_table or call_indirect occurs inside a loop.",
                "wasm.instruction-pointer" => "A decoded variable is both read and written, with arithmetic in the function.",
                "wasm.linear-memory" => "A decoded instruction accesses linear memory.",
                "wasm.handler-table" => "An indirect call or module table/element section is present.",
                "wasm.bytecode-region" => "A data section is a possible bytecode region, not identified guest instructions.",
                "wasm.bounded-exit" => "A decoded return or trap is present.",
                _ => unreachable!("Every structural rule needs a catalog definition"),
            });
        rules.push(json!({"rule_id":id,"family":CONFIG["RULE_FAMILIES"][id],"weight":weight,
            "scope":if id.starts_with("js.") {"javascript-structure"} else {"wasm-structure"},"summary":detail}));
    }
    for (id, weight, _) in ANTI.iter() {
        rules.push(json!({"rule_id":id,"family":"relevance","weight":weight,"scope":"javascript-lexical-relevance",
            "summary":"An unmasked source-text pattern matches this relevance category; comments and literals can match."}));
    }
    for (id, weight) in runtime_weights().as_object().unwrap() {
        rules.push(json!({"rule_id":id,"family":"relevance","weight":weight,"scope":"retained-runtime-relevance",
            "summary":"A retained browser-surface event is attributed to this artifact or correlated by capture context."}));
    }
    rules.sort_by(|a, b| a["rule_id"].as_str().cmp(&b["rule_id"].as_str()));
    rules
}

fn observation(id: &str, start: usize, end: usize, detail: &str) -> Value {
    json!({"rule_id":id,"family":CONFIG["RULE_FAMILIES"][id],"weight":CONFIG["RULE_WEIGHTS"][id],"coordinate":{"byte_offset":start,"byte_size":end.saturating_sub(start).max(1)},"detail":detail})
}
fn rank(observations: &[Value]) -> (u64, usize) {
    (
        observations
            .iter()
            .map(|o| o["weight"].as_u64().unwrap())
            .sum(),
        observations
            .iter()
            .map(|o| o["family"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
    )
}
/// Blank comments, quoted and template text and regular-expression bodies,
/// keeping every byte offset, line terminators outside them, template
/// substitution code and its braces, and each literal's two slashes. A kept
/// slash still names the regex-or-division guess for consumers that refuse it.
/// The input must be complete source text: masking a slice or masked text
/// re-guesses its slashes without the context that decided them.
pub(crate) fn mask(source: &str) -> String {
    use js_lexer::{Kind, Lexer};
    let mut bytes = source.as_bytes().to_vec();
    for token in Lexer::new(source) {
        match token.kind {
            Kind::Comment | Kind::String | Kind::TemplateText => {
                bytes[token.start..token.end].fill(b' ');
            }
            Kind::Regex { body_end, .. } => {
                bytes[token.start + 1..body_end].fill(b' ');
                bytes[body_end + 1..token.end].fill(b' ');
            }
            _ => (),
        }
    }
    // Every blanked range starts and ends at an ASCII delimiter.
    String::from_utf8(bytes).expect("UTF-8 literal masking")
}
fn js(source: &str) -> Result<(Vec<Value>, Vec<Value>)> {
    static SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?:\bfunction\b[^{}]{0,1024}|\([^(){}]{0,1024}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*\{",
        )
        .unwrap()
    });
    static LOOP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:while|for)\s*\(").unwrap());
    static DISPATCH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bswitch\s*\(|\b[A-Za-z_$][\w$]*\s*\[(?:[^\[\]]+|\[[^\[\]]*\])+\]\s*\(")
            .unwrap()
    });
    // `h = t[selector]` whose temporary the same region calls.
    static ALIASED_READ: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$.]*\s*\[(?:[^\[\]]+|\[[^\[\]]*\])+\]\s*(?:[;,)\n]|$)")
            .unwrap()
    });
    static CALLED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b([A-Za-z_$][\w$]*)\s*(?:\(|\.\s*(?:call|apply)\s*\()").unwrap()
    });
    let dispatch = |region: &str| {
        let direct = DISPATCH.find(region).map(|m| (m.start(), m.end()));
        let called = CALLED
            .captures_iter(region)
            .map(|captures| captures.get(1).unwrap().as_str())
            .collect::<BTreeSet<_>>();
        let aliased = ALIASED_READ
            .captures_iter(region)
            .find(|captures| called.contains(&captures[1]))
            .map(|captures| {
                let m = captures.get(0).unwrap();
                (m.start(), m.end())
            });
        direct.into_iter().chain(aliased).min()
    };
    let masked = mask(source);
    let mut openings = BTreeSet::new();
    let mut omissions = Vec::new();
    for m in SIGNATURE.find_iter(&masked) {
        if openings.len() >= 4096 {
            omissions
                .push(json!({"reason":"javascript-function-region-limit","observed_records":4096}));
            break;
        }
        openings.insert(m.end() - 1);
    }
    let mut stack = Vec::new();
    let mut regions = vec![(0, source.len())];
    for (i, c) in masked.bytes().enumerate() {
        if c == b'{' {
            stack.push(i);
        } else if c == b'}'
            && let Some(start) = stack.pop()
            && openings.remove(&start)
        {
            regions.push((start + 1, i));
        }
    }
    if !openings.is_empty() {
        omissions.push(json!({
            "reason": "javascript-unterminated-function",
            "observed_records": openings.len()
        }));
    }
    regions.sort_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)));
    let mut children = BTreeMap::<(usize, usize), Vec<(usize, usize)>>::new();
    let mut parents = Vec::<(usize, usize)>::new();
    for region in &regions {
        while parents.last().is_some_and(|p| region.0 >= p.1) {
            parents.pop();
        }
        if let Some(parent) = parents.last().filter(|p| region.1 <= p.1) {
            children.entry(*parent).or_default().push(*region);
        }
        parents.push(*region);
    }
    let mut order = regions.clone();
    order.sort_by_key(|r| {
        if *r == (0, source.len()) {
            0
        } else {
            r.1 - r.0 + 1
        }
    });
    let mut work = 0;
    let mut best = Vec::new();
    let mut best_rank = (0, 0, usize::MAX);
    for (start, end) in order {
        if work + end - start > 64 * 1024 * 1024 {
            omissions.push(json!({"reason":"javascript-region-work-limit","observed_bytes":work,"total_bytes":work+end-start}));
            break;
        }
        work += end - start;
        // Keep byte coordinates while excluding masked comments and quoted
        // text. Original source remains available for bytecode extraction.
        let mut bytes = masked.as_bytes()[start..end].to_vec();
        for (a, b) in children.get(&(start, end)).into_iter().flatten() {
            bytes[a - start..b - start].fill(b' ');
        }
        let region = String::from_utf8(bytes).expect("masked nested source");
        let mut observations = Vec::new();
        let nested = children.get(&(start, end)).map_or(&[][..], Vec::as_slice);
        if let Some(a) = LOOP.find(&region)
            && let Some(b) = dispatch(&region)
        {
            observations.push(observation(
                "js.dispatch-loop",
                a.start().min(b.0),
                a.end().max(b.1),
                "A loop and a switch, an indexed callable, or a called alias of an indexed read occur in the same function region.",
            ));
        } else if let Some((a, b)) = threaded_cycle(&masked, &region, start, nested) {
            observations.push(observation(
                "js.dispatch-loop",
                a,
                b,
                "A table literal's own functions dispatch the table again, directly or through a function of the region: a threaded cycle that repeats without a syntactic loop.",
            ));
        }
        for (id, detail, patterns) in JS_RULES.iter() {
            let mut first = None::<(usize, usize)>;
            let mut count = 0;
            let mut truncated = false;
            for pattern in patterns {
                for m in pattern.find_iter(&region) {
                    if count >= 32 {
                        truncated = true;
                        break;
                    }
                    count += 1;
                    if first.is_none_or(|f| m.start() < f.0) {
                        first = Some((m.start(), m.end()));
                    }
                }
                if truncated {
                    break;
                }
            }
            if let Some((a, b)) = first {
                let mut o = observation(id, a, b, detail);
                o["match_count"] = json!(count);
                o["matches_truncated"] = json!(truncated);
                observations.push(o);
            }
        }
        for o in &mut observations {
            o["coordinate"]["byte_offset"] =
                json!(o["coordinate"]["byte_offset"].as_u64().unwrap() + start as u64);
            o["function_region"] = json!({"byte_offset":start,"byte_size":end-start});
        }
        let (score, families) = rank(&observations);
        if score > best_rank.0
            || score == best_rank.0
                && (families > best_rank.1 || families == best_rank.1 && start < best_rank.2)
        {
            best = observations;
            best_rank = (score, families, start);
        }
    }
    Ok((best, omissions))
}
/// A table literal of a region whose own function elements dispatch that
/// table again (`ops = [function(s){ return ops[code[pc++]](s); }]`),
/// directly or through a named function of the region they call (a shared
/// `next()`), threads each handler to the next: a dispatch cycle without a
/// syntactic loop. Returns the literal's span in region coordinates. Each
/// child body is scanned once, so the work is linear in the region.
fn threaded_cycle(
    masked: &str,
    region: &str,
    start: usize,
    children: &[(usize, usize)],
) -> Option<(usize, usize)> {
    static TABLE_LITERAL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[\[{]").unwrap());
    static INDEXED_CALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\[(?:[^\[\]]+|\[[^\[\]]*\])+\]\s*\(").unwrap()
    });
    static CALLED_NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\(").unwrap());
    // The name a child function is declared or bound to, just before its body.
    static NAMED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^()]*\)|\b([A-Za-z_$][\w$]*)\s*=\s*(?:function\b[^(){}]*\([^()]*\)|\([^()]*\)\s*=>))\s*$").unwrap()
    });
    if !TABLE_LITERAL.is_match(region) {
        return None;
    }
    let bytes = region.as_bytes();
    let bodies = children
        .iter()
        .map(|&(a, b)| {
            let text = &masked[a..b];
            let dispatched = INDEXED_CALL
                .captures_iter(text)
                .map(|captures| captures.get(1).unwrap().as_str())
                .collect::<BTreeSet<_>>();
            let called = CALLED_NAME
                .captures_iter(text)
                .map(|captures| captures.get(1).unwrap().as_str())
                .collect::<BTreeSet<_>>();
            let header = &region[..(a - start).saturating_sub(1)];
            let window = header.len().saturating_sub(1100);
            let name = (0..=window)
                .rev()
                .find(|at| header.is_char_boundary(*at))
                .and_then(|at| NAMED.captures(&header[at..]))
                .and_then(|captures| captures.get(1).or_else(|| captures.get(2)))
                .map(|name| name.as_str());
            (a - start, b - start, name, dispatched, called)
        })
        .collect::<Vec<_>>();
    let helpers = bodies
        .iter()
        .filter_map(|(_, _, name, dispatched, _)| Some((name.as_ref()?, dispatched)))
        .filter(|(_, dispatched)| !dispatched.is_empty())
        .collect::<BTreeMap<_, _>>();
    for captures in TABLE_LITERAL.captures_iter(region).take(32) {
        let table = captures.get(1).unwrap();
        if region[..table.start()].trim_end().ends_with('.') {
            continue;
        }
        let opening = captures.get(0).unwrap().end() - 1;
        let (open, close) = if bytes[opening] == b'[' {
            (b'[', b']')
        } else {
            (b'{', b'}')
        };
        let mut depth = 0usize;
        let Some(closing) = (opening..bytes.len()).find(|&at| {
            if bytes[at] == open {
                depth += 1;
            } else if bytes[at] == close {
                depth -= 1;
            }
            depth == 0
        }) else {
            continue;
        };
        let table = table.as_str();
        let threads = bodies.iter().any(|(a, b, _, dispatched, called)| {
            opening < *a
                && *b < closing
                && (dispatched.contains(table)
                    || called.iter().any(|name| {
                        helpers
                            .get(name)
                            .is_some_and(|dispatched| dispatched.contains(table))
                    }))
        });
        if threads {
            return Some((captures.get(0).unwrap().start(), closing + 1));
        }
    }
    None
}

/// Classify an artifact's dispatch sites under one fresh meter.
fn classify_artifact(
    runtime: &str,
    bytes: &[u8],
    meter: &dispatch_shape::Meter,
) -> Option<dispatch_shape::Classified> {
    match runtime {
        "javascript" => Some(dispatch_shape::javascript::classify(std::str::from_utf8(bytes).ok()?, meter)),
        "webassembly" => Some(dispatch_shape::wasm(bytes, meter).unwrap_or(
            dispatch_shape::Classified {
                javascript: None,
                sites: Vec::new(),
                omissions: vec![json!({"reason":"classification-unavailable","detail":"The module sections did not decode for dispatch classification."})],
            },
        )),
        _ => None,
    }
}

/// The classification document of one artifact under a given meter.
#[cfg(test)]
pub(crate) fn classification_under(
    runtime: &str,
    bytes: &[u8],
    meter: &dispatch_shape::Meter,
) -> Value {
    let classified = classify_artifact(runtime, bytes, meter).expect("classifiable artifact");
    dispatch_shape::document(&json!("1"), classified.sites, classified.omissions)
}

/// Classification of one JavaScript source and the meter that bounded it.
#[cfg(test)]
pub(crate) fn javascript_classification_work(source: &str) -> (Value, dispatch_shape::Meter) {
    let meter = dispatch_shape::Meter::new();
    let document = classification_under("javascript", source.as_bytes(), &meter);
    (document, meter)
}

/// Roles of every classified dispatch site of an artifact, recomputed under
/// a fresh meter. Production passes the roles the analysis computed instead.
#[cfg(test)]
pub(crate) fn dispatch_roles(runtime: &str, bytes: &[u8]) -> Option<dispatch_shape::Roles> {
    let meter = dispatch_shape::Meter::new();
    Some(dispatch_shape::Roles::new(
        &classify_artifact(runtime, bytes, &meter)?,
        &meter,
    ))
}

/// The structural dispatch classification of one JavaScript source, as
/// `analyze` records it.
#[cfg(test)]
pub(crate) fn javascript_classification(source: &str) -> Value {
    javascript_classification_work(source).0
}
struct Instruction {
    opcode: u8,
    start: usize,
    end: usize,
    variable: Option<(bool, u32)>,
    loop_depth: usize,
    arm_count: Option<u32>,
    // Distinct Wasm label indexes for br_table, including the default. Null for
    // call_indirect. This clusters repeated arms; it is not a guest opcode count.
    unique_targets: Option<u32>,
    table_index: Option<u32>,
}
fn wasm(bytes: &[u8]) -> Result<(Vec<Value>, Value)> {
    let bad = |e: wasmparser::BinaryReaderError| Error::bad(e.to_string());
    let mut sections = 0;
    let mut code_sections = 0;
    let mut data_ranges = Vec::new();
    let mut table_ranges = Vec::new();
    let mut imported = 0;
    let mut defined = 0;
    let mut functions = 0;
    let mut instructions_count = 0;
    let mut best = Vec::new();
    let mut best_rank = (0, 0);
    let mut best_dispatch = None;
    let mut inventory = wasm_dispatch::Inventory::default();
    // Active element-segment funcref initializers, keyed by table index. A missing
    // key means the fanout is unknown. Passive and declarative segments are omitted.
    let mut element_fanout: BTreeMap<u32, u32> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(bad)?;
        if let Some((id, range)) = payload.as_section() {
            sections += 1;
            if sections > 128 || range.len() > 2 * 1024 * 1024 {
                return Err(Error::bad(
                    "WebAssembly section count or byte limit exceeded",
                ));
            }
            if id != 0 && !seen.insert(id) {
                return Err(Error::bad(
                    "WebAssembly contains a duplicate structural section",
                ));
            }
        }
        match payload {
            Payload::Version { num, encoding, .. } => {
                if num != 1 || encoding != wasmparser::Encoding::Module {
                    return Err(Error::bad("Unsupported WebAssembly module"));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    if matches!(import.map_err(bad)?.ty, TypeRef::Func(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                defined = reader.count();
                if defined > 100000 {
                    return Err(Error::bad("WebAssembly function count exceeded"));
                }
                for entry in reader {
                    let _ = entry.map_err(bad)?;
                }
            }
            Payload::TableSection(reader) => table_ranges.push(reader.range()),
            Payload::ElementSection(reader) => {
                table_ranges.push(reader.range());
                for element in reader {
                    let element = element.map_err(bad)?;
                    let ElementKind::Active { table_index, .. } = element.kind else {
                        continue;
                    };
                    // MVP active segments omit the table index and mean table 0.
                    let slot = element_fanout.entry(table_index.unwrap_or(0)).or_insert(0);
                    match element.items {
                        ElementItems::Functions(functions) => {
                            for function in functions {
                                let _ = function.map_err(bad)?;
                                *slot = slot.saturating_add(1);
                            }
                        }
                        ElementItems::Expressions(_, expressions) => {
                            for expression in expressions {
                                let mut operators = expression.map_err(bad)?.get_operators_reader();
                                let mut funcref = false;
                                while !operators.eof() {
                                    if matches!(
                                        operators.read().map_err(bad)?,
                                        Operator::RefFunc { .. }
                                    ) {
                                        funcref = true;
                                    }
                                }
                                if funcref {
                                    *slot = slot.saturating_add(1);
                                }
                            }
                        }
                    }
                }
            }
            Payload::DataSection(reader) => data_ranges.push(reader.range()),
            Payload::CodeSectionStart { count, .. } => {
                code_sections += 1;
                if count != defined {
                    return Err(Error::bad("WebAssembly function and code counts disagree"));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                let mut reader = body.get_operators_reader().map_err(bad)?;
                let mut decoded = Vec::new();
                let mut control = Vec::new();
                let mut ended = false;
                while !reader.eof() {
                    if instructions_count >= 1000000 {
                        return Err(Error::bad("WebAssembly instruction limit exceeded"));
                    }
                    instructions_count += 1;
                    let start = reader.original_position();
                    let op = reader.read().map_err(bad)?;
                    let end = reader.original_position();
                    let opcode = bytes[start];
                    let variable = match &op {
                        Operator::LocalGet { local_index }
                        | Operator::LocalSet { local_index }
                        | Operator::LocalTee { local_index } => Some((false, *local_index)),
                        Operator::GlobalGet { global_index }
                        | Operator::GlobalSet { global_index } => Some((true, *global_index)),
                        _ => None,
                    };
                    let loop_depth = control
                        .iter()
                        .filter(|block| **block == wasm_control::BlockKind::Loop)
                        .count();
                    let (arm_count, unique_targets, table_index) = match &op {
                        Operator::BrTable { targets } => {
                            let mut labels = BTreeSet::new();
                            labels.insert(targets.default());
                            for target in targets.targets() {
                                labels.insert(target.map_err(bad)?);
                            }
                            (
                                Some(targets.len()),
                                Some(u32::try_from(labels.len()).unwrap_or(u32::MAX)),
                                None,
                            )
                        }
                        Operator::CallIndirect { table_index, .. } => {
                            (None, None, Some(*table_index))
                        }
                        _ => (None, None, None),
                    };
                    decoded.push(Instruction {
                        opcode,
                        start,
                        end,
                        variable,
                        loop_depth,
                        arm_count,
                        unique_targets,
                        table_index,
                    });
                    match wasm_control::control(&op) {
                        wasm_control::Control::Open(block) => control.push(block),
                        wasm_control::Control::Arm(block) if control.last() != Some(&block) => {
                            return Err(Error::bad(if block == wasm_control::BlockKind::If {
                                "WebAssembly else without matching if"
                            } else {
                                "WebAssembly catch without matching try"
                            }));
                        }
                        wasm_control::Control::Close { delegate } => match control.pop() {
                            Some(block) if !delegate || block == wasm_control::BlockKind::Try => (),
                            Some(_) | None if delegate => {
                                return Err(Error::bad(
                                    "WebAssembly delegate without matching try",
                                ));
                            }
                            _ => {
                                ended = true;
                                if !reader.eof() {
                                    return Err(Error::bad(
                                        "WebAssembly function body has trailing instructions",
                                    ));
                                }
                            }
                        },
                        _ => (),
                    }
                }
                if !ended {
                    return Err(Error::bad("WebAssembly function body has an invalid end"));
                }
                let mut obs = Vec::new();
                if let Some(dispatch) = decoded
                    .iter()
                    .find(|i| [0x0e, 0x11].contains(&i.opcode) && i.loop_depth > 0)
                    && let Some(loop_op) = decoded
                        .iter()
                        .find(|i| i.opcode == 3 && i.start < dispatch.start)
                {
                    obs.push(observation(
                        "wasm.dispatch-loop",
                        loop_op.start,
                        dispatch.end,
                        "Decoded br_table or call_indirect dispatch occurs inside a loop.",
                    ));
                }
                let reads = decoded
                    .iter()
                    .filter(|i| [0x20, 0x23].contains(&i.opcode))
                    .filter_map(|i| i.variable)
                    .collect::<BTreeSet<_>>();
                let writes = decoded
                    .iter()
                    .filter(|i| [0x21, 0x22, 0x24].contains(&i.opcode))
                    .filter_map(|i| i.variable)
                    .collect::<BTreeSet<_>>();
                if let (Some(variable), Some(arithmetic)) = (
                    reads.intersection(&writes).next(),
                    decoded
                        .iter()
                        .find(|i| [0x6a, 0x6b, 0x7c, 0x7d].contains(&i.opcode)),
                ) {
                    let first = decoded
                        .iter()
                        .find(|i| [0x20, 0x23].contains(&i.opcode) && i.variable == Some(*variable))
                        .unwrap();
                    obs.push(observation(
                        "wasm.instruction-pointer",
                        first.start,
                        arithmetic.end,
                        "A decoded local or global is both read and written, with arithmetic elsewhere in this function. This is an IP-like pattern, not a data-flow or dispatch-binding proof.",
                    ));
                }
                for (id, detail, opcodes) in [
                    (
                        "wasm.linear-memory",
                        "A decoded load or store accesses linear memory.",
                        (0x28..0x3f).collect::<Vec<_>>(),
                    ),
                    (
                        "wasm.handler-table",
                        "A decoded call_indirect selects a function-table entry.",
                        vec![0x11],
                    ),
                    (
                        "wasm.bounded-exit",
                        "A decoded return or trap bounds a candidate path.",
                        vec![0, 0x0f],
                    ),
                ] {
                    if let Some(i) = decoded.iter().find(|i| opcodes.contains(&i.opcode)) {
                        obs.push(observation(id, i.start, i.end, detail));
                    }
                }
                for o in &mut obs {
                    o["coordinate"]["function_index"] = json!(imported + functions);
                    o["coordinate"]["function_body_offset"] = json!(range.start);
                    o["coordinate"]["function_body_size"] = json!(range.len());
                }
                let score = rank(&obs);
                let dispatch = inventory.function(
                    imported + functions,
                    &range,
                    &decoded,
                    score.0,
                    obs.iter()
                        .any(|o| o["rule_id"] == "wasm.instruction-pointer"),
                    &element_fanout,
                );
                if let Some((site_rank, start, end)) = dispatch {
                    if best_dispatch.is_none_or(|(previous, _)| site_rank > previous) {
                        if let Some(observation) = obs
                            .iter_mut()
                            .find(|o| o["rule_id"] == "wasm.dispatch-loop")
                        {
                            observation["coordinate"]["byte_offset"] = json!(start);
                            observation["coordinate"]["byte_size"] = json!(end - start);
                        }
                        best_dispatch = Some((site_rank, start));
                        best = obs;
                    }
                } else if best_dispatch.is_none() && score > best_rank {
                    best_rank = score;
                    best = obs;
                }
                functions += 1;
            }
            _ => (),
        }
    }
    if !table_ranges.is_empty() && !best.iter().any(|o| o["rule_id"] == "wasm.handler-table") {
        let start = table_ranges[0].start;
        best.push(observation(
            "wasm.handler-table",
            start,
            start + 1,
            "A table or element section is present without decoded indirect dispatch.",
        ));
    }
    if let Some(range) = data_ranges.first() {
        best.push(observation(
            "wasm.bytecode-region",
            range.start,
            range.end.min(range.start + 16),
            "A data section can supply candidate guest bytes.",
        ));
    }
    Ok((
        best,
        json!({"section_count":sections,"code_section_count":code_sections,"data_section_count":data_ranges.len(),"decoded_function_count":functions,"imported_function_count":imported,"decoded_instruction_count":instructions_count,"dispatch_inventory":inventory.value(best_dispatch.map(|(_, offset)| offset))}),
    ))
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let raw = serde_json::to_string(value)?;
    let mut encoded = String::new();
    for ch in raw.chars() {
        if ch.is_ascii() {
            encoded.push(ch);
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) {
                use std::fmt::Write;
                let _ = write!(encoded, "\\u{unit:04x}");
            }
        }
    }
    Ok(encoded.into_bytes())
}
pub(crate) fn digest(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical(value)?)))
}
fn finding(hash: &str, rules: &[String]) -> String {
    let mut rules = rules.to_vec();
    rules.sort();
    hex::encode(Sha256::digest(format!(
        "{PROFILE}:{hash}:{}",
        rules.join(",")
    )))[..24]
        .into()
}
fn failure(artifact: &Value, code: &str, message: &str) -> Value {
    json!({"artifact_id":artifact["artifact_id"],"artifact_sha256":artifact["sha256"],"runtime":if artifact["kind"]=="javascript" {"javascript"} else {"webassembly"},"status":"failed","error":{"code":code,"message":message},"coverage":{"complete":false,"omissions":[{"reason":code}]}})
}
type EventReference = (String, u32, String);
fn event_reference(event: &Value) -> Option<EventReference> {
    if !["session_id", "sequence_number"]
        .iter()
        .all(|key| evidence::canonical(&event[key], 64, true))
    {
        return None;
    }
    let process = event["process_id"]
        .as_u64()
        .filter(|id| *id > 0 && *id <= u64::from(u32::MAX))?;
    Some((
        event["session_id"].as_str()?.into(),
        process as u32,
        event["sequence_number"].as_str()?.into(),
    ))
}
fn event_value(event: &Value) -> Value {
    json!({"session_id":event["session_id"],"process_id":event["process_id"],"sequence_number":event["sequence_number"]})
}
fn event_node(prefix: &str, event: &Value) -> String {
    format!(
        "{prefix}:{}:{}:{}",
        event["session_id"].as_str().unwrap(),
        event["process_id"].as_u64().unwrap(),
        event["sequence_number"].as_str().unwrap()
    )
}
fn runtime_rule(event: &Value) -> Option<&'static str> {
    match (event["category"].as_str()?, event["type"].as_str()?) {
        ("canvas" | "webgl", "api_call" | "property_read") => Some("antibot.runtime-canvas-webgl"),
        ("navigator", "api_call" | "property_read") => Some("antibot.runtime-navigator-device"),
        ("web_audio", "api_call") => Some("antibot.runtime-web-audio"),
        _ => None,
    }
}
fn runtime_weights() -> Value {
    json!({"antibot.runtime-canvas-webgl":25,"antibot.runtime-navigator-device":25,"antibot.runtime-web-audio":25})
}
// Pattern rank can mark JavaScript likely-vm before static handler recovery.
// Keep the workspace, but do not leave an empty handler table at that tier.
// Structural dispatch classification never changes a tier: handlers the
// classification withheld still count as recovered here.
fn retain_handlerless_javascript_as_candidate(result: &mut Value, workspace: &Value) {
    let empty_handlers = workspace["handlers"]
        .as_array()
        .is_some_and(|handlers| handlers.is_empty());
    let withheld = workspace["coverage"]["omissions"]
        .as_array()
        .is_some_and(|omissions| {
            omissions
                .iter()
                .any(|omission| omission["reason"] == "handler-withheld")
        });
    if result["runtime"] != "javascript"
        || result["tier"] != "likely-vm"
        || !empty_handlers
        || withheld
    {
        return;
    }
    result["tier"] = json!("candidate");
    let already_recorded = result["coverage"]["omissions"]
        .as_array()
        .is_some_and(|omissions| {
            omissions
                .iter()
                .any(|omission| omission["reason"] == "handler-unavailable")
        });
    if already_recorded {
        return;
    }
    result["coverage"]["omissions"]
        .as_array_mut()
        .expect("analysis coverage omissions")
        .push(json!({
            "reason": "handler-unavailable",
            "detail": "The dispatch pattern did not yield a static handler table, so this artifact stays a candidate."
        }));
    result["status"] = json!("partial");
    result["coverage"]["complete"] = json!(false);
}
#[cfg(test)]
fn analyze(artifact: &Value, bytes: &[u8], events: &[Value]) -> Value {
    analyze_with_roles(artifact, bytes, events).0
}

/// Workspace extraction spends the same artifact budget. Its exhaustion
/// must remain visible even when extraction cannot return a workspace.
/// Names on a classification document that the artifact's work budget ran
/// out after it was listed.
fn work_limited(classification: &mut Value) {
    if let Some(omissions) = classification["omissions"].as_array_mut()
        && !omissions
            .iter()
            .any(|o| o["reason"] == "classification-work-limit")
    {
        omissions.push(json!({"reason":"classification-work-limit","detail":"The shared artifact work or memory budget prevented completion of 1 downstream claim-gate or table-layout pass. Unsupported claims were withheld."}));
    }
}

pub(crate) fn finish_classification(
    result: &mut Value,
    workspace: Option<&mut Value>,
    meter: &dispatch_shape::Meter,
) {
    if !meter.exhausted() {
        return;
    }
    work_limited(&mut result["frontend"]["dispatch_classification"]);
    if let Some(workspace) = workspace {
        workspace["dispatch_classification"] =
            result["frontend"]["dispatch_classification"].clone();
        workspace["coverage"]["omissions"].as_array_mut().expect("workspace omissions").push(json!({"reason":"classification-work-limit","detail":"The shared artifact work or memory budget prevented completion of the claim gate or table layout."}));
        workspace["coverage"]["complete"] = json!(false);
    }
}

/// The analysis result and the roles of every classified dispatch site, which
/// the opcode-claim gate reads without classifying the artifact again.
#[cfg(test)]
pub(crate) fn analyze_with_roles(
    artifact: &Value,
    bytes: &[u8],
    events: &[Value],
) -> (Value, Option<dispatch_shape::Roles>) {
    analyze_with_meter(artifact, bytes, events, &dispatch_shape::Meter::new())
}

#[cfg(test)]
pub(crate) fn analyze_with_meter(
    artifact: &Value,
    bytes: &[u8],
    events: &[Value],
    meter: &dispatch_shape::Meter,
) -> (Value, Option<dispatch_shape::Roles>) {
    analyze_in(artifact, bytes, &Runtime::of(events), meter)
}

/// One artifact's analysis, correlated with the records of its frame.
#[cfg(test)]
fn analyze_in(
    artifact: &Value,
    bytes: &[u8],
    context: &Runtime,
    meter: &dispatch_shape::Meter,
) -> (Value, Option<dispatch_shape::Roles>) {
    match analyze_content(artifact, bytes, meter) {
        Ok((content, roles)) => (artifact_result(artifact, &content, context), roles),
        Err(message) => (failure(artifact, "malformed-artifact", &message), None),
    }
}

/// What an artifact's bytes alone decide: structure, score, tier, static
/// relevance, classification and bytecode snapshot. Identical bytes decide
/// identically, so a session pass analyzes each content once and
/// `artifact_result` adds what names the artifact and correlates its frame.
#[derive(Clone)]
struct Content {
    runtime: &'static str,
    tier: &'static str,
    score: u64,
    finding_id: String,
    observations: Vec<Value>,
    anti: Vec<Value>,
    frontend: Value,
    omissions: Vec<Value>,
    bytecode_snapshot: Option<Value>,
    byte_count: usize,
}
impl Content {
    fn has_workspace(&self) -> bool {
        crate::vm_opcode::has_workspace(self.runtime, self.tier, &self.frontend)
    }
}

/// Distinct contents whose analysis the session pass keeps for reuse. A
/// session loads far fewer contents than artifacts; past this many, the
/// oldest is analyzed again if it reappears.
const CONTENT_CACHE: usize = 1024;

/// Results as they are produced: spooled whole, with the counts the summary
/// reports and the findings a mixed finding joins.
struct Results {
    spool: document::Spool,
    analyzed: u64,
    candidates: u64,
    likely_vm: u64,
    failed: u64,
    worker_failures: BTreeMap<String, u64>,
    findings: Vec<Value>,
}

impl Results {
    fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            spool: document::Spool::new(root)?,
            analyzed: 0,
            candidates: 0,
            likely_vm: 0,
            failed: 0,
            worker_failures: BTreeMap::new(),
            findings: Vec::new(),
        })
    }

    fn push(&mut self, result: Value) -> Result<()> {
        self.analyzed += 1;
        self.failed += u64::from(result["status"] == "failed");
        for omission in result["frontend"]["dispatch_classification"]["omissions"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if omission["reason"] == "analysis-worker-failed" {
                *self
                    .worker_failures
                    .entry(omission["detail"].as_str().unwrap_or("protocol").to_owned())
                    .or_default() += omission["omitted_records"].as_u64().unwrap_or(1);
            }
        }
        self.spool.push(&result)?;
        match result["tier"].as_str() {
            Some("candidate") => self.candidates += 1,
            Some("likely-vm") => self.likely_vm += 1,
            _ => return Ok(()),
        }
        self.findings.push(result);
        Ok(())
    }
}

/// One content as the session pass keeps it for the next artifact with the
/// same bytes: its analysis or failure, and its native JavaScript source key.
struct Analyzed {
    source: Option<([u8; 32], u32)>,
    outcome: std::result::Result<Content, (&'static str, String)>,
}
impl Analyzed {
    fn result(&self, artifact: &Value, context: &Runtime) -> Value {
        match &self.outcome {
            Ok(content) => artifact_result(artifact, content, context),
            Err((code, message)) => failure(artifact, code, message),
        }
    }
}

/// The content analysis of an artifact's bytes, or why they do not parse.
fn analyze_content(
    artifact: &Value,
    bytes: &[u8],
    meter: &dispatch_shape::Meter,
) -> std::result::Result<(Content, Option<dispatch_shape::Roles>), String> {
    let runtime = if artifact["kind"] == "javascript" {
        "javascript"
    } else {
        "webassembly"
    };
    let source = if runtime == "javascript" {
        std::str::from_utf8(bytes).map_err(|_| "Artifact is not UTF-8 JavaScript".to_owned())?
    } else {
        ""
    };
    let (observations, mut frontend, omissions) = if runtime == "javascript" {
        let (obs, omissions) = js(source).map_err(|e| e.message)?;
        (obs, json!({"replacement_character_count":0}), omissions)
    } else {
        let (obs, frontend) = wasm(bytes).map_err(|e| e.message)?;
        let omitted = frontend["dispatch_inventory"]["omitted_site_count"]
            .as_u64()
            .unwrap_or(0);
        let omissions = if omitted > 0 {
            vec![json!({"reason":"dispatch-inventory-limit","omitted_records":omitted})]
        } else {
            Vec::new()
        };
        (obs, frontend, omissions)
    };
    // Classification is interpretation over the same bytes, metered on its
    // own and never an input to the observations, score or tier above. Its
    // listed sites name the artifact, which `artifact_result` fills in.
    let classified = classify_artifact(runtime, bytes, meter);
    let roles = classified
        .as_ref()
        .map(|classified| dispatch_shape::Roles::new(classified, meter));
    if let Some(classified) = classified {
        frontend["dispatch_classification"] =
            dispatch_shape::document(&json!("0"), classified.sites, classified.omissions);
    }
    let rules = observations
        .iter()
        .map(|o| o["rule_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let (score, family_count) = rank(&observations);
    let has_dispatch = rules.contains(&format!(
        "{}.dispatch-loop",
        if runtime == "javascript" {
            "js"
        } else {
            "wasm"
        }
    ));
    let tier = if has_dispatch && score >= 60 && family_count >= 3 {
        "likely-vm"
    } else if score >= 20 {
        "candidate"
    } else {
        "none"
    };
    let mut anti = Vec::new();
    for (id, weight, pattern) in ANTI.iter() {
        if let Some(m) = pattern.find(source) {
            anti.push(json!({"rule_id":id,"weight":weight,"coordinate":{"byte_offset":m.start(),"byte_size":m.len()},"detail":"Static anti-bot relevance signal. It does not establish VM structure."}));
        }
    }
    let content = Content {
        runtime,
        tier,
        score,
        finding_id: finding(artifact["sha256"].as_str().unwrap(), &rules),
        observations,
        anti,
        frontend,
        omissions,
        bytecode_snapshot: (runtime == "javascript" && tier != "none")
            .then(|| crate::vm_bytecode::snapshot(source, "0")),
        byte_count: bytes.len(),
    };
    Ok((content, roles))
}

/// An artifact's result: its content analysis, named for the artifact and
/// correlated with the records of its frame.
fn artifact_result(artifact: &Value, content: &Content, context: &Runtime) -> Value {
    let mut frontend = content.frontend.clone();
    for site in frontend["dispatch_classification"]["sites"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        site["artifact_id"] = artifact["artifact_id"].clone();
    }
    let mut anti = content.anti.clone();
    let mut omissions = content.omissions.clone();
    let id = &content.finding_id;
    let artifact_node = format!("artifact:{}", artifact["artifact_id"].as_str().unwrap());
    let finding_node = format!("finding:{id}");
    let mut nodes = vec![
        json!({"id":artifact_node,"kind":"artifact","label":artifact["url"]}),
        json!({"id":finding_node,"kind":"vm-candidate","label":id}),
    ];
    let mut edges = vec![
        json!({"from":artifact_node,"to":finding_node,"state":"inferred","reason":"Deterministic static analysis produced this candidate."}),
    ];
    // Frame correlation is a count and a get_events filter: every artifact
    // of a frame shares its records, so none of them is copied per artifact.
    // A zero frame ID means attribution is unavailable (for example a
    // worker), not a shared frame; only records naming the artifact count.
    let frame = input::frame_of(artifact);
    let available = artifact["frame_id"] != "0";
    let frame_context = frame
        .as_ref()
        .filter(|_| available)
        .and_then(|frame| context.frame(frame));
    let own = frame
        .as_ref()
        .zip(artifact["artifact_id"].as_str().filter(|id| *id != "0"))
        .and_then(|(frame, id)| context.attributed(frame, id));
    let empty = BTreeMap::new();
    let own_rules = own.unwrap_or(&empty);
    let mut representatives = BTreeMap::<&str, (&Value, bool)>::new();
    for (rule, stats) in own_rules {
        if let Some(first) = &stats.first {
            representatives.insert(rule, (first, true));
        }
    }
    for (rule, stats) in frame_context
        .map(|frame| &frame.rules)
        .into_iter()
        .flatten()
    {
        if let Some(first) = &stats.first {
            representatives.entry(rule).or_insert((first, false));
        }
    }
    let own_total = own_rules.values().map(|rule| rule.count).sum::<u64>();
    let unavailable = if available {
        0
    } else {
        frame
            .as_ref()
            .and_then(|frame| context.frame(frame))
            .map_or(0, |frame| {
                (frame.requests + frame.rules.values().map(|rule| rule.count).sum::<u64>())
                    .saturating_sub(own_total)
            })
    };
    let weights = runtime_weights();
    for (rule, (event, observed)) in &representatives {
        // Runtime evidence has an event coordinate, never an invented source
        // byte range. It changes relevance only, not structural VM scoring.
        anti.push(json!({"rule_id":rule,"weight":weights[*rule],"event":event_value(event),"event_sequence":event["sequence_number"],"state":if *observed {"observed"} else {"correlated"},"detail":if *observed {"A captured browser-signal event explicitly names this artifact. API use alone does not establish fingerprinting or anti-bot behavior."} else {"A captured browser-signal event shares this artifact's session, navigation metadata, and nonzero frame. Script attribution and causality are unknown; API use alone does not establish fingerprinting or anti-bot behavior."}}));
    }
    // Each scoring representative has a graph node, so every relevance
    // explanation is in the graph; the rest of the frame is counted.
    for (event, observed) in representatives.values().copied() {
        let node = event_node("event", event);
        nodes.push(json!({"id":node,"kind":"browser-signal","label":format!("{} {}",event["category"].as_str().unwrap(),event["type"].as_str().unwrap()),"event":event_value(event),"event_sequence":event["sequence_number"]}));
        edges.push(json!({"from":node,"to":finding_node,"state":if observed {"observed"} else {"correlated"},"reason":if observed {"Captured nonzero artifact attribution; no value flow is claimed."} else {"Matching session, navigation metadata, and nonzero frame; script attribution and causality remain unknown."}}));
    }
    let mut signals = BTreeMap::<&str, (u64, u64)>::new();
    for (rule, stats) in own_rules {
        signals.entry(rule).or_default().0 = stats.count;
    }
    for (rule, stats) in frame_context
        .map(|frame| &frame.rules)
        .into_iter()
        .flatten()
    {
        let entry = signals.entry(rule).or_default();
        entry.1 = stats.count.saturating_sub(entry.0);
    }
    let runtime_context = json!({
        "session_id": artifact["session_id"],
        "navigation_id": artifact["navigation_id"],
        "frame_id": artifact["frame_id"],
        "frame_attribution": if available {"available"} else {"unavailable"},
        "request_records": frame_context.map_or(0, |frame| frame.requests),
        "signal_records": signals.iter().map(|(rule, (observed, correlated))| json!({"rule_id": rule, "observed": observed, "correlated": correlated})).collect::<Vec<_>>(),
        // get_events parameters that list the frame's records, or the
        // artifact's own records when the frame is unknown.
        "events_filter": if available {
            json!({"session_id": artifact["session_id"], "navigation_id": artifact["navigation_id"], "frame_id": artifact["frame_id"]})
        } else {
            json!({"session_id": artifact["session_id"], "artifact_id": artifact["artifact_id"]})
        },
    });
    if unavailable > 0 {
        omissions.push(
            json!({"reason":"runtime-frame-attribution-unavailable","omitted_records":unavailable}),
        );
    }
    let observations = &content.observations;
    let mut result = json!({"artifact_id":artifact["artifact_id"],"artifact_sha256":artifact["sha256"],"runtime":content.runtime,"status":if omissions.is_empty() {"complete"} else {"partial"},"finding_id":id,"tier":content.tier,"vm_score":content.score,"vm_threshold":60,"required_family_count":3,"evidence_families":observations.iter().map(|o|o["family"].as_str().unwrap()).collect::<BTreeSet<_>>(),"observations":observations,"anti_bot_score":anti.iter().map(|o|o["weight"].as_u64().unwrap()).sum::<u64>().min(100),"anti_bot_observations":anti,"runtime_context":runtime_context,"graph":{"nodes":nodes,"edges":edges},"coverage":{"complete":omissions.is_empty(),"observed_bytes":content.byte_count,"total_bytes":content.byte_count,"omissions":omissions,"residual_unknowns":["Static evidence does not confirm guest dispatch at runtime.","Frame context is correlation, not exact value provenance."]},"frontend":frontend});
    if let Some(snapshot) = &content.bytecode_snapshot {
        let mut snapshot = snapshot.clone();
        snapshot["artifact_id"] = artifact["artifact_id"].clone();
        result["bytecode_snapshot"] = snapshot;
    }
    result
}

pub(crate) struct Documents {
    pub analysis: Analysis,
    pub opcode_workspace: Result<Value>,
    pub host_links: Result<Value>,
}

pub(crate) fn store_documents(root: &Path, event_store: &Path) -> Result<Documents> {
    let mut documents = build_documents(root, event_store)?;
    publish(root, &mut documents, &mut durable::write_private_from)?;
    Ok(documents)
}

fn build_documents(root: &Path, event_store: &Path) -> Result<Documents> {
    let capture_provenance = capture_mode::Provenance::read(root)?;
    let manifest_path = root.join("manifest.jsonl");
    let manifest = input::manifest(&manifest_path, &capture_provenance)?;
    let event_input = input::events(event_store, &capture_provenance, &manifest.creators)?;
    let mut omissions = manifest.omissions.clone();
    omissions.extend(event_input.omissions);
    let capture_mode = if omissions.is_empty() {
        capture_mode::aggregate(manifest.modes.iter().chain(&event_input.modes).copied())
    } else {
        "unknown"
    };
    let snapshot_artifacts = manifest.snapshot_artifacts;
    let link_index = crate::vm_request_links::Index::new(event_input.links.iter());
    let mut dispatch_budget_losses = Vec::new();
    let mut native_js_gaps = Vec::new();
    for gap in &event_input.gaps {
        // A vm gap that names an interpreter artifact is also a dispatch-budget
        // loss. The opcode workspace sums that weight so a capped trace stays
        // incomplete. Other gaps stay capture-gap markers only.
        if let Some(loss) = crate::vm_opcode::dispatch_budget_loss(gap) {
            dispatch_budget_losses.push(loss);
        }
        if let Some(gap) = crate::vm_opcode::native_js::gap(gap) {
            native_js_gaps.push(gap);
        }
    }
    if !event_input.gaps.is_empty() {
        // This counts markers, not dropped events: queue reports and sequence
        // gaps can overlap and must never be added into a fabricated loss total.
        omissions.add_count("capture-gap", event_input.gaps.len() as u64, None);
    }
    let omissions = omissions.values();
    let events = event_input
        .records
        .into_iter()
        .map(|(_, event)| event)
        .collect::<Vec<_>>();
    let runtime_context = event_input.runtime;
    // Script text is keyed only when native JavaScript records exist to join.
    let has_native_js = events
        .iter()
        .any(|event| event["type"] == "js_dispatch_observation");
    let native_js_sources = std::cell::RefCell::new(BTreeSet::new());
    let profile = current_profile();
    let mut results = Results::new(root)?;
    for failure in manifest.failures {
        results.push(failure)?;
    }
    let mut opcode_workspaces = Vec::new();
    // Kept past the pass: the artifacts a workspace or a mixed finding names.
    let mut artifacts = Vec::new();
    // A session loads the same scripts in navigation after navigation, so
    // its artifacts share far fewer contents than they have records. The
    // oldest content leaves first, so memory stays bounded when they do not.
    let mut contents = HashMap::<[String; 4], Analyzed>::new();
    let mut content_order = std::collections::VecDeque::new();
    input::analyzed_artifacts(&manifest_path, manifest.length, |artifact| {
        if !["javascript", "wasm"].contains(&artifact["kind"].as_str().unwrap_or("")) {
            return Ok(());
        }
        // Bytes are read, verified and analyzed once per content. A content
        // with an opcode workspace is analyzed for each artifact, as the
        // workspace joins that artifact's own samples under its own budget.
        let key = [
            &artifact["kind"],
            &artifact["sha256"],
            &artifact["content_path"],
            &artifact["byte_size"],
        ]
        .map(Value::to_string);
        let mut fresh = None;
        if !contents.contains_key(&key) {
            let analyzed = match evidence::content(root, &artifact, 16 * 1024 * 1024) {
                Err(e) => Some(Analyzed {
                    source: None,
                    outcome: Err((
                        if e.status == 400 {
                            "artifact-byte-limit"
                        } else {
                            "artifact-integrity"
                        },
                        e.message,
                    )),
                }),
                Ok(bytes) => {
                    let source = (has_native_js && artifact["kind"] == "javascript")
                        .then(|| crate::vm_opcode::native_js::source_key(&bytes))
                        .flatten()
                        .map(|key| (key.sha256, key.length));
                    let meter = dispatch_shape::Meter::new();
                    match analyze_content(&artifact, &bytes, &meter) {
                        Err(message) => Some(Analyzed {
                            source,
                            outcome: Err(("malformed-artifact", message)),
                        }),
                        Ok((content, roles)) if content.has_workspace() => {
                            fresh = Some((bytes, content, roles, source));
                            None
                        }
                        Ok((mut content, roles)) => {
                            // Without a workspace the classification work is
                            // all done, so its budget is the content's alone.
                            if roles.is_some_and(|roles| roles.meter.exhausted()) {
                                work_limited(&mut content.frontend["dispatch_classification"]);
                            }
                            Some(Analyzed {
                                source,
                                outcome: Ok(content),
                            })
                        }
                    }
                }
            };
            if let Some(analyzed) = analyzed {
                if contents.len() == CONTENT_CACHE
                    && let Some(oldest) = content_order.pop_front()
                {
                    contents.remove(&oldest);
                }
                content_order.push_back(key.clone());
                contents.insert(key.clone(), analyzed);
            }
        }
        let (mut result, source, workspace_input) = match fresh {
            Some((bytes, content, roles, source)) => (
                artifact_result(&artifact, &content, &runtime_context),
                source,
                Some((bytes, roles)),
            ),
            None => {
                let analyzed = &contents[&key];
                (
                    analyzed.result(&artifact, &runtime_context),
                    analyzed.source,
                    None,
                )
            }
        };
        if let Some((sha256, length)) = source {
            native_js_sources.borrow_mut().insert((
                artifact["session_id"].as_str().unwrap_or("").to_owned(),
                artifact["frame_id"].as_str().unwrap_or("").to_owned(),
                sha256,
                length,
            ));
        }
        if result["status"] != "failed" {
            // Resolved before normalization so conflicting identities remain
            // tombstones; an ID that also names an invalid record links nothing.
            let id = artifact["artifact_id"].as_str().unwrap();
            result["exact_request_links"] = json!(if manifest.invalid_ids.contains(id) {
                Vec::new()
            } else {
                link_index.links(&artifact)
            });
        }
        if result["status"] != "failed" && !omissions.is_empty() {
            result["status"] = json!("partial");
            result["coverage"]["complete"] = json!(false);
            result["coverage"]["omissions"]
                .as_array_mut()
                .unwrap()
                .extend(omissions.iter().cloned());
        }
        let mut keep = artifact["kind"] == "wasm"
            || ["candidate", "likely-vm"].contains(&result["tier"].as_str().unwrap_or(""));
        if let Some((bytes, roles)) = workspace_input {
            let mut workspace = crate::vm_opcode::workspace(
                root,
                &artifact,
                &bytes,
                crate::vm_opcode::Analysis {
                    result: &result,
                    roles: roles.as_ref(),
                },
                &snapshot_artifacts,
                &events,
                crate::vm_opcode::Losses {
                    budget: &dispatch_budget_losses,
                    native_js: &native_js_gaps,
                },
            );
            if let Some(roles) = &roles {
                finish_classification(&mut result, workspace.as_mut(), &roles.meter);
            }
            if let Some(mut workspace) = workspace {
                workspace["capture_mode"] = json!(capture_provenance.mode(&artifact["session_id"]));
                retain_handlerless_javascript_as_candidate(&mut result, &workspace);
                opcode_workspaces.push(workspace);
                keep = true;
            }
        }
        if keep {
            artifacts.push(artifact);
        }
        results.push(result)
    })?;
    let native_js_sources = native_js_sources.into_inner();
    let mut omissions = omissions;
    // An operational worker failure is retryable, never derived evidence.
    // Return before writing any document; App only caches successful calls.
    let worker_failures = &results.worker_failures;
    if !worker_failures.is_empty() {
        return Err(crate::error::Error::new(
            503,
            format!(
                "analysis-worker-failed: {}. Analysis was not saved; retry the request.",
                worker_failures
                    .iter()
                    .map(|(detail, count)| format!("{detail} ({count} omitted artifacts)"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_reason(crate::error::Reason::at(
            crate::error::Code::DependencyUnavailable,
            crate::error::Phase::Worker,
        )));
    }
    // A native JavaScript record names its script by text. One no analyzed
    // artifact of its session and frame has supplies no claim anywhere.
    let unmatched = events
        .iter()
        .filter(|event| event["type"] == "js_dispatch_observation")
        .filter_map(crate::vm_opcode::native_js::event_key)
        .filter(|key| !native_js_sources.contains(key))
        .count();
    if unmatched > 0 {
        omissions.push(json!({"reason":"native-js-observation-unmatched","observed_records":unmatched,
            "detail":"Native JavaScript dispatch records name script text that no analyzed JavaScript artifact of the same session and frame has. They supply no observed claim."}));
    }
    let mut mixed = Vec::new();
    for wasm in results.findings.iter().filter(|r| {
        r["runtime"] == "webassembly"
            && ["candidate", "likely-vm"].contains(&r["tier"].as_str().unwrap_or(""))
    }) {
        let parent = artifacts
            .iter()
            .find(|a| a["artifact_id"] == wasm["artifact_id"])
            .map(|a| a["parent_artifact_id"].clone())
            .unwrap_or(Value::Null);
        if let Some(js) = results.findings.iter().find(|r| {
            r["artifact_id"] == parent
                && r["runtime"] == "javascript"
                && ["candidate", "likely-vm"].contains(&r["tier"].as_str().unwrap_or(""))
        }) {
            let rules = js["observations"]
                .as_array()
                .unwrap()
                .iter()
                .chain(wasm["observations"].as_array().unwrap())
                .map(|o| o["rule_id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            mixed.push(json!({"finding_id":finding(&format!("{}:{}",js["artifact_sha256"].as_str().unwrap(),wasm["artifact_sha256"].as_str().unwrap()),&rules),"runtime":"mixed","tier":if js["tier"]=="likely-vm" || wasm["tier"]=="likely-vm" {"likely-vm"} else {"candidate"},"artifact_ids":[parent,wasm["artifact_id"]],"vm_score":js["vm_score"].as_u64().unwrap()+wasm["vm_score"].as_u64().unwrap(),"anti_bot_score":js["anti_bot_score"],"evidence_families":js["evidence_families"].as_array().unwrap().iter().chain(wasm["evidence_families"].as_array().unwrap()).map(|v|v.as_str().unwrap()).collect::<BTreeSet<_>>(),"boundary":{"state":"observed","reason":"The WASM artifact manifest names the JavaScript artifact as its creator."}}));
        }
    }
    let document = json!({"contract_version":1,"document_kind":"vm-analysis","producer":current_producer(),"profile_digest":digest(&profile)?,"profile":profile,"inputs":{"artifact_manifest_digest":manifest.digest,"event_store_digest":event_input.digest,"capture_provenance_digest":capture_provenance.digest},"capture_mode":capture_mode,"input_coverage":{"complete":omissions.is_empty(),"omissions":omissions},"summary":{"analyzed_artifacts":results.analyzed,"candidate_count":results.candidates,"likely_vm_count":results.likely_vm,"failed_count":results.failed,"mixed_count":mixed.len()},"mixed_findings":mixed});
    let document = results.spool.finish(document)?;
    let opcode_workspace = crate::vm_opcode::document(document.head(), opcode_workspaces);
    let host_links = opcode_workspace
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|workspace| {
            crate::vm_host_links::document(workspace, &artifacts, &events, &runtime_context)
        });
    Ok(Documents {
        analysis: document,
        opcode_workspace,
        host_links,
    })
}

/// Analysis, then the workspace naming its digest, then host links naming
/// the workspace digest.
const CHAIN: [&str; 3] = [
    "analysis/vm-analysis-v1.json",
    "analysis/vm-opcode-workspace-v2.json",
    "analysis/vm-host-links-v1.json",
];

impl Documents {
    /// The chain document at `index` and everything derived from it are
    /// unavailable. The analysis itself stays served from memory.
    fn fail_from(&mut self, index: usize, error: Error) {
        if index == 1 {
            self.opcode_workspace = Err(error.clone());
        }
        self.host_links = Err(error);
    }
}

/// Removes a dependant before its source changes. A directory in its place is
/// no document a reader could join; the later write reports it.
fn remove_dependant(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
        Ok(metadata) if metadata.is_dir() => Ok(false),
        Ok(_) => std::fs::remove_file(path).map(|()| true),
    }
}

/// One cooperative writer at a time, the backend or the CLI, publishes the
/// chain. Dependants are removed before their source is replaced and written
/// after it, so a crash or failed write leaves a prefix of the chain whose
/// digest links all hold, never a document naming a replaced source. A
/// dependant that cannot be written or removed is reported as unavailable,
/// with everything derived from it; the analysis is still served.
fn publish(
    root: &Path,
    documents: &mut Documents,
    write: &mut dyn FnMut(&Path, &mut dyn std::io::Read) -> Result<()>,
) -> Result<()> {
    let paths = CHAIN.map(|name| root.join(name));
    #[cfg(unix)]
    let _lease = chain_lease(&paths[0])?;
    let mut removed = false;
    for index in [2, 1] {
        match remove_dependant(&paths[index]) {
            Ok(gone) => removed |= gone,
            Err(error) => {
                // Replacing its source would leave this stale document naming
                // a replaced one, so the previous chain stays as it was.
                documents.fail_from(
                    index,
                    Error::new(
                        500,
                        format!(
                            "The previous {} could not be removed, so the VM analysis documents were not replaced: {error}",
                            CHAIN[index]
                        ),
                    ),
                );
                return Ok(());
            }
        }
    }
    if removed && let Some(directory) = paths[0].parent() {
        std::fs::File::open(directory)?.sync_all()?;
    }
    write(&paths[0], &mut documents.analysis.reader())?;
    for index in [1, 2] {
        let document = if index == 1 {
            &documents.opcode_workspace
        } else {
            &documents.host_links
        };
        // An unavailable document has no written dependant either.
        let Ok(value) = document else { break };
        if let Err(error) =
            canonical(value).and_then(|bytes| write(&paths[index], &mut bytes.as_slice()))
        {
            documents.fail_from(index, error);
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn chain_lease(path: &Path) -> Result<crate::workspace_lease::Lease> {
    // Publication itself takes milliseconds. Wait briefly for another
    // writer rather than refusing a read that has already recomputed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match crate::workspace_lease::Lease::acquire(path) {
            Err(error) if error.status == 409 => {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::error::Error::conflict(
                        "VM analysis documents are being published by another process; retry",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

#[cfg(all(test, unix))]
mod chain_tests {
    use super::*;

    fn inputs(root: &Path, events: &[&str]) -> std::path::PathBuf {
        std::fs::write(root.join("manifest.jsonl"), "").unwrap();
        let store = root.join("events.jsonl");
        std::fs::write(&store, events.concat()).unwrap();
        store
    }
    fn read(root: &Path, index: usize) -> Option<Value> {
        durable::read_private(&root.join(CHAIN[index]), 1 << 26)
            .unwrap()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }
    /// Every present dependant names the present document it was derived from.
    fn linked(root: &Path) -> [bool; 3] {
        let [analysis, workspace, links] = [0, 1, 2].map(|index| read(root, index));
        if let Some(workspace) = &workspace {
            assert_eq!(
                workspace["analysis_digest"],
                analysis.as_ref().unwrap()["document_digest"]
            );
        }
        if let Some(links) = &links {
            assert_eq!(
                links["workspace_document_digest"],
                workspace.as_ref().unwrap()["document_digest"]
            );
        }
        [analysis.is_some(), workspace.is_some(), links.is_some()]
    }
    #[test]
    fn failed_chain_write_never_leaves_a_document_naming_a_replaced_source() {
        for (failing, failing_name) in CHAIN.iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            let store = inputs(root.path(), &[]);
            let first = store_documents(root.path(), &store).unwrap();
            assert_eq!(linked(root.path()), [true; 3]);
            inputs(root.path(), &["{\"x\":1}\n"]);
            let mut next = build_documents(root.path(), &store).unwrap();
            assert_ne!(next.analysis.digest(), first.analysis.digest());
            let result = publish(root.path(), &mut next, &mut |path, source| {
                if path.ends_with(failing_name) {
                    Err(crate::error::Error::new(500, "Synthetic write failure"))
                } else {
                    durable::write_private_from(path, source)
                }
            });
            assert_eq!(result.is_err(), failing == 0);
            let present = linked(root.path());
            assert_eq!(present, [true, failing > 1, false], "{failing}");
            let analysis = read(root.path(), 0).unwrap();
            assert_eq!(
                analysis["document_digest"],
                if failing == 0 { &first } else { &next }.analysis.digest()
            );
            // A failed analysis write fails the whole call instead.
            assert_eq!(next.opcode_workspace.is_ok(), failing != 1);
            assert_eq!(next.host_links.is_ok(), failing == 0);
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unremovable_dependant_keeps_the_previous_chain() {
        use std::os::unix::ffi::OsStrExt;
        for stuck in [1, 2] {
            let root = tempfile::tempdir().unwrap();
            let store = inputs(root.path(), &[]);
            let first = store_documents(root.path(), &store).unwrap();
            let path = root.path().join(CHAIN[stuck]);
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chflags(path.as_ptr(), libc::UF_IMMUTABLE as _) },
                0
            );
            inputs(root.path(), &["{\"x\":1}\n"]);
            let next = store_documents(root.path(), &store);
            assert_eq!(unsafe { libc::chflags(path.as_ptr(), 0) }, 0);
            let next = next.unwrap();
            assert_eq!(linked(root.path()), [true, true, stuck == 2], "{stuck}");
            assert_eq!(
                read(root.path(), 0).unwrap()["document_digest"],
                first.analysis.digest()
            );
            assert_ne!(next.analysis.digest(), first.analysis.digest());
            assert_eq!(next.opcode_workspace.is_ok(), stuck == 2);
            assert!(next.host_links.is_err());
        }
    }
    #[test]
    fn chain_publication_waits_for_another_writer() {
        let root = tempfile::tempdir().unwrap();
        let store = inputs(root.path(), &[]);
        let held = crate::workspace_lease::Lease::acquire(&root.path().join(CHAIN[0])).unwrap();
        let path = root.path().to_owned();
        let writer = std::thread::spawn(move || store_documents(&path, &store).map(|_| ()));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!writer.is_finished());
        assert_eq!(linked(root.path()), [false; 3]);
        drop(held);
        writer.join().unwrap().unwrap();
        assert_eq!(linked(root.path()), [true; 3]);
    }
}

/// Publishes the documents and returns the analysis, held by reference.
pub fn store_analysis(root: &Path, event_store: &Path) -> Result<Analysis> {
    let documents = store_documents(root, event_store)?;
    documents.opcode_workspace?;
    documents.host_links?;
    Ok(documents.analysis)
}

pub fn store(root: &Path, event_store: &Path) -> Result<Value> {
    store_analysis(root, event_store)?.document()
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn handler_recovery_requirement_has_distinct_profile_and_accepts_older_profiles() {
        let current = current_profile();
        assert_eq!(current_producer()["version"], "1.11.0");
        assert_eq!(current["javascript_likely_vm_requires_handlers"], true);
        let mut historical = current.clone();
        historical
            .as_object_mut()
            .unwrap()
            .remove("javascript_likely_vm_requires_handlers");
        // The pinned digest is the version 2 profile that preceded both,
        // which still had the record and graph limits producer 1.11.0 removed.
        historical["javascript_scoring_version"] = json!(2);
        let limits = historical["limits"].as_object_mut().unwrap();
        limits.insert("max_artifact_records".into(), json!(10000));
        limits.insert("max_event_records".into(), json!(100000));
        limits.insert("max_graph_edges".into(), json!(1024));
        assert_eq!(
            digest(&historical).unwrap(),
            "61900fb0d5f5e7b8db28d67086c4e2648aca6a604c1fd2ef509941e95c974824"
        );
        assert_ne!(digest(&current).unwrap(), digest(&historical).unwrap());
        let schema: Value =
            serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
                .unwrap();
        let validator = jsonschema::validator_for(&schema["$defs"]["profile"]).unwrap();
        validator.validate(&current).unwrap();
        validator.validate(&historical).unwrap();
        historical
            .as_object_mut()
            .unwrap()
            .remove("javascript_scoring_version");
        validator.validate(&historical).unwrap();
    }
}

#[cfg(test)]
mod dispatch_shape_tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/dispatch-shapes")
    }

    fn sources() -> Vec<PathBuf> {
        let mut sources = std::fs::read_dir(fixtures())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "wat"))
            .collect::<Vec<_>>();
        sources.sort();
        assert!(sources.len() >= 5, "dispatch shape WAT sources are missing");
        sources
    }

    fn classify(name: &str) -> Value {
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        let kind = if name.ends_with(".js") {
            "javascript"
        } else {
            "wasm"
        };
        let artifact = json!({
            "artifact_id": "7", "sha256": hex::encode(Sha256::digest(&bytes)), "kind": kind,
            "session_id": "1", "navigation_id": "1", "frame_id": "1", "url": name,
        });
        analyze(&artifact, &bytes, &[])
    }

    /// The checked-in binaries are exactly what the pinned assembler builds
    /// from the checked-in sources. Run `make dispatch-shape-fixtures` after
    /// editing a `.wat`.
    #[test]
    fn dispatch_shape_wasm_fixtures_match_their_wat_sources() {
        for source in sources() {
            let built = wat::parse_file(&source).unwrap();
            wasmparser::Validator::new().validate_all(&built).unwrap();
            let binary = source.with_extension("wasm");
            let checked_in = std::fs::read(&binary).unwrap_or_else(|_| {
                panic!(
                    "{} is missing; run make dispatch-shape-fixtures",
                    binary.display()
                )
            });
            assert!(
                built == checked_in,
                "{} drifted from its source; run make dispatch-shape-fixtures",
                binary.display()
            );
        }
    }

    #[test]
    #[ignore = "writes fixtures; run through make dispatch-shape-fixtures"]
    fn write_dispatch_shape_fixtures() {
        for source in sources() {
            let built = wat::parse_file(&source).unwrap();
            std::fs::write(source.with_extension("wasm"), built).unwrap();
        }
    }

    #[test]
    fn dispatch_shape_fixtures_classify_as_expected() {
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(fixtures().join("expected.json")).unwrap(),
        )
        .unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-dispatch-classification-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let analysis_schema: Value =
            serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
                .unwrap();
        let result_validator = jsonschema::validator_for(
            &json!({"$ref":"#/$defs/result","$defs":analysis_schema["$defs"]}),
        )
        .unwrap();
        let mut mismatches = Vec::new();
        for fixture in expected["fixtures"].as_array().unwrap() {
            let name = fixture["artifact"].as_str().unwrap();
            let result = classify(name);
            result_validator.validate(&result).unwrap();
            let classification = &result["frontend"]["dispatch_classification"];
            validator.validate(classification).unwrap();
            let sites = classification["sites"].as_array().unwrap();
            let wanted = fixture["sites"].as_array().unwrap();
            // Every fixture mismatch is reported, not only the first.
            let mut failed =
                sites.len() != wanted.len() || classification["site_count"] != wanted.len();
            for (site, want) in sites.iter().zip(wanted) {
                for (key, value) in want.as_object().unwrap() {
                    let actual = match key.as_str() {
                        "function_index" | "line" => &site["location"][key],
                        "through_helper" => &site["selector"][key],
                        _ => &site[key],
                    };
                    failed |= actual != value;
                }
                assert_eq!(site["confidence"], "structural");
                assert_eq!(site["artifact_id"], "7");
                assert!(!site["selector"]["expression"].as_str().unwrap().is_empty());
            }
            if failed {
                let summary = sites
                    .iter()
                    .map(|site| {
                        format!(
                            "{} {} {}/{}/{} {}",
                            site["location"]["function_index"],
                            site["instruction"],
                            site["dispatch_kind"],
                            site["selector_source"],
                            site["repeats"],
                            site["role"]
                        )
                    })
                    .collect::<Vec<_>>();
                mismatches.push(format!("{name}: {summary:?}"));
            }
            // Classification never raises the structural tier.
            let observations = result["observations"].as_array().unwrap();
            let rules = observations
                .iter()
                .map(|o| o["rule_id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                result["finding_id"],
                finding(result["artifact_sha256"].as_str().unwrap(), &rules)
            );
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    /// The native JavaScript dispatch probe anchors a switch at its keyword
    /// and an indexed call at the `[` of its callee's computed member, found
    /// from the AST. Optional chains and shapes without one node have none.
    #[test]
    fn javascript_sites_record_the_native_probe_anchor() {
        let source = "\u{feff}// \u{3a9}\u{1d535}\nfunction run(c,t,s){var p=0;while(p<c.length){switch(c[p++]){case 0:(t) /* [ */ [c[p++]](s);t[c[p++]].call(null,s);t[c[p++]]?.(s);t?.[c[p++]](s);const h=t[c[p++]];h(s);break;}}}";
        let classification = javascript_classification(source);
        let sites = classification["sites"].as_array().unwrap();
        let anchors = sites
            .iter()
            .map(|site| {
                (
                    site["instruction"].as_str().unwrap(),
                    site["location"]["byte_offset"].as_u64().unwrap() as usize,
                    site["location"]["anchor_offset"]
                        .as_u64()
                        .map(|v| v as usize),
                )
            })
            .collect::<Vec<_>>();
        let find = |needle: &str| source.find(needle).unwrap();
        let expected = [
            ("switch", find("switch"), Some(find("switch"))),
            ("indexed call", find("(t)"), Some(find("[c[p++]](s);t["))),
            (
                "indexed call",
                find("t[c[p++]].call"),
                Some(find("t[c[p++]].call") + 1),
            ),
            ("indexed call", find("t[c[p++]]?.("), None),
            ("indexed call", find("t?.["), None),
            ("aliased call", find("h(s)"), None),
        ];
        for want in expected {
            assert!(anchors.contains(&want), "{want:?} not in {anchors:?}");
        }
        // Anchors are artifact bytes: the mark and multibyte comment precede them.
        assert!(anchors.iter().all(|(_, offset, _)| *offset > 10));
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-dispatch-classification-v1.schema.json"
        ))
        .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&classification)
            .unwrap();
    }

    /// Every embedded copy of the classification contract matches the
    /// standalone versioned schema after reference rewriting.
    #[test]
    fn dispatch_classification_contract_copies_match_the_standalone_schema() {
        let standalone: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-dispatch-classification-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            standalone["properties"]["omissions"]["items"]["properties"]["reason"]["enum"],
            json!(dispatch_shape::OMISSION_REASONS)
        );
        let copy = |prefix: &str| {
            let mut body = standalone.clone();
            for key in ["$schema", "$id", "title", "$defs"] {
                body.as_object_mut().unwrap().remove(key);
            }
            let text = serde_json::to_string(&body).unwrap().replace(
                "\"#/$defs/site\"",
                &format!("\"{prefix}/dispatchClassificationSite\""),
            );
            serde_json::from_str::<Value>(&text).unwrap()
        };
        let analysis: Value =
            serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
                .unwrap();
        let workspace: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        let openapi: Value =
            serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap();
        for (defs, prefix) in [
            (&analysis["$defs"], "#/$defs".to_owned()),
            (&workspace["$defs"], "#/$defs".to_owned()),
            (
                &openapi["components"]["schemas"]["VmAnalysis"]["$defs"],
                "#/components/schemas/VmAnalysis/$defs".to_owned(),
            ),
            (
                &openapi["components"]["schemas"]["VmOpcodeWorkspace"]["$defs"],
                "#/components/schemas/VmOpcodeWorkspace/$defs".to_owned(),
            ),
        ] {
            assert_eq!(defs["dispatchClassification"], copy(&prefix), "{prefix}");
            assert_eq!(
                defs["dispatchClassificationSite"], standalone["$defs"]["site"],
                "{prefix}"
            );
        }
    }

    /// A loop that reloads a state field and writes constants back is a
    /// state machine. Only a slot stored back as `slot + n` is an advancing
    /// program position.
    #[test]
    fn field_state_machine_loops_are_not_interpreter_candidates() {
        let bytes = wat::parse_str(
            r#"(module
              (memory 1)
              (func (export "drive") (param $obj i32) (result i32)
                (local $state i32)
                (block $exit
                  (loop $again
                    (local.set $state (i32.load offset=4 (local.get $obj)))
                    (block $two (block $one (block $zero
                      (br_table $zero $one $two $exit (local.get $state)))
                      (i32.store offset=4 (local.get $obj) (i32.const 2)) (br $again))
                      (i32.store offset=4 (local.get $obj) (i32.const 0)) (br $again))
                    (i32.store offset=4 (local.get $obj) (i32.const 3))
                    (br $again)))
                (local.get $state)))"#,
        )
        .unwrap();
        let sites = dispatch_shape::wasm(&bytes, &dispatch_shape::Meter::new()).unwrap();
        let document = dispatch_shape::document(&json!("9"), sites.sites, sites.omissions);
        let site = &document["sites"][0];
        assert_eq!(site["selector_source"], "frame_slot");
        assert_eq!(site["repeats"], "unknown");
        assert_eq!(site["role"], "other");
    }

    #[test]
    fn javascript_saved_positions_must_advance_to_repeat() {
        let classify = |source: &str| {
            let document = javascript_classification(source);
            let site = document["sites"][0].clone();
            (
                site["selector_source"].as_str().unwrap().to_owned(),
                site["repeats"].as_str().unwrap().to_owned(),
                site["role"].as_str().unwrap().to_owned(),
            )
        };
        let machine = "function drive(m){while(true){switch(m.state){case 0: m.state = 1; break; case 1: m.state = 2; break; case 2: return;}}}";
        assert_eq!(
            classify(machine),
            ("frame_slot".into(), "unknown".into(), "other".into())
        );
        let saved = "function run(f, code){while(true){switch(code[f.pc++]){case 0: break; case 1: return; case 2: f.pc = 0;}}}";
        assert_eq!(
            classify(saved),
            (
                "frame_slot".into(),
                "loop".into(),
                "interpreter-candidate".into()
            )
        );
    }

    /// Review regression: without validator arity a call's effect is
    /// unknown, so its argument never becomes the selector.
    #[test]
    fn untyped_call_results_do_not_become_call_arguments() {
        let bytes = wat::parse_str(
            r#"(module
              (func $f (param i32) (result i32) (local.get 0))
              (func (export "g") (param $x i32) (result i32)
                (drop (i64.add (i32.const 1) (i32.const 2)))
                (block $b (block $a
                  (br_table $a $b (call $f (local.get $x)))))
                (i32.const 0)))"#,
        )
        .unwrap();
        assert!(wasmparser::Validator::new().validate_all(&bytes).is_err());
        let sites = dispatch_shape::wasm(&bytes, &dispatch_shape::Meter::new()).unwrap();
        let document = dispatch_shape::document(&json!("9"), sites.sites, sites.omissions);
        let site = &document["sites"][0];
        assert_eq!(site["selector_source"], "unknown", "{site}");
        assert_eq!(site["role"], "other");
    }

    /// Review regression: a cyclic local trace must not cache a provisional
    /// unknown, so a site's classification is independent of query order.
    #[test]
    fn cyclic_local_traces_do_not_depend_on_query_order() {
        let function = |first: &str, second: &str| {
            format!(
                r#"(func (param $code i32) (param $len i32)
                  (local $pc i32) (local $a i32) (local $b i32)
                  (block $exit
                    (loop $again
                      (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
                      (local.set $a (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
                      (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
                      (local.set $b (local.get $a))
                      (block $y (block $x (br_table $x $y (local.get ${first}))))
                      (block $w (block $v (br_table $v $w (local.get ${second}))))
                      (local.set $a (local.get $b))
                      (br $again))))"#
            )
        };
        let bytes = wat::parse_str(format!(
            "(module (memory 1) {} {})",
            function("a", "b"),
            function("b", "a")
        ))
        .unwrap();
        let sites = dispatch_shape::wasm(&bytes, &dispatch_shape::Meter::new()).unwrap();
        let document = dispatch_shape::document(&json!("9"), sites.sites, sites.omissions);
        let by_local = |function: u64, expression: &str| {
            document["sites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|site| {
                    site["location"]["function_index"] == function
                        && site["selector"]["expression"]
                            .as_str()
                            .unwrap()
                            .starts_with(expression)
                })
                .map(|site| (site["selector_source"].clone(), site["repeats"].clone()))
                .unwrap()
        };
        assert_eq!(by_local(0, "local4"), by_local(1, "local4"));
        assert_eq!(by_local(0, "local3"), by_local(1, "local3"));
        assert_eq!(by_local(0, "local4").0, "cursor_index");
    }

    /// Review regression: every dispatch_kind the schema allows is counted.
    #[test]
    fn kind_counts_cover_every_dispatch_kind() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-dispatch-classification-v1.schema.json"
        ))
        .unwrap();
        let kinds = schema["$defs"]["site"]["properties"]["dispatch_kind"]["enum"]
            .as_array()
            .unwrap()
            .clone();
        let counted = schema["properties"]["kind_counts"]["required"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(kinds, counted);
        let document = dispatch_shape::document(&json!("9"), Vec::new(), Vec::new());
        for kind in &kinds {
            assert_eq!(document["kind_counts"][kind.as_str().unwrap()], 0);
        }
    }

    fn classify_module(bytes: &[u8]) -> Value {
        let classified = dispatch_shape::wasm(bytes, &dispatch_shape::Meter::new()).unwrap();
        dispatch_shape::document(&json!("9"), classified.sites, classified.omissions)
    }

    /// Fetch helpers and threaded handler cycles in Wasm: a helper whose
    /// result is a load at a global or frame-slot position it advances, and
    /// a tail-call cycle whose next index is such a fetch, are interpreter
    /// candidates. A per-call local cursor or a dispatch outside any loop or
    /// cycle is not.
    #[test]
    fn wasm_fetch_helpers_and_threaded_cycles_classify_structurally() {
        for (name, text, instruction, role, helper) in review_inputs::WASM_STATIC_SHAPES {
            let classification = classify_module(&wat::parse_str(text).unwrap());
            let site = classification["sites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|site| site["instruction"] == *instruction)
                .unwrap_or_else(|| panic!("{name}: {classification}"));
            assert_eq!(
                (&site["role"], &site["selector"]["through_helper"]),
                (&json!(role), &json!(helper)),
                "{name}: {site}"
            );
        }
    }

    /// JavaScript threaded dispatch: a self call tied to a table whose
    /// handlers return a cursor fetch, and handlers that dispatch their own
    /// table again, directly or through a shared helper, are threaded
    /// interpreter candidates. A chain of constant indexes and a router
    /// forwarding its argument are not, nor is a self call whose variable a
    /// loop head also writes; a reassigned table is structurally
    /// threaded but its binding proof fails, so it claims nothing.
    #[test]
    fn javascript_threaded_chains_and_cycles_classify_structurally() {
        for (name, role, source_kind) in [
            (
                "threaded-returned-handler",
                "interpreter-candidate",
                "cursor_index",
            ),
            (
                "threaded-tail-call",
                "interpreter-candidate",
                "cursor_index",
            ),
            (
                "threaded-shared-next",
                "interpreter-candidate",
                "cursor_index",
            ),
            ("threaded-callback-chain", "other", "handler_address"),
            ("threaded-router", "other", "call_argument"),
            ("threaded-loop-head-write", "other", "handler_address"),
            (
                "threaded-reassigned-table",
                "interpreter-candidate",
                "cursor_index",
            ),
        ] {
            let (_, source, _) = review_inputs::STATIC_SHAPES
                .iter()
                .find(|(shape, _, _)| *shape == name)
                .unwrap();
            let classification = javascript_classification(source);
            let site = classification["sites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|site| site["dispatch_kind"] == "threaded")
                .unwrap_or_else(|| panic!("{name}: {classification}"));
            assert_eq!(
                (&site["role"], &site["selector_source"]),
                (&json!(role), &json!(source_kind)),
                "{name}: {site}"
            );
        }
    }

    /// Review regression: a trace cap never yields a confident different
    /// source. Constant writes before the loop must not crowd out the loop's
    /// fetch, and a large function must not run out of symbolic nodes.
    #[test]
    fn trace_caps_never_yield_a_confident_wrong_source() {
        for (name, bytes) in review_inputs::wasm() {
            let document = classify_module(&bytes);
            let site = &document["sites"][0];
            assert_eq!(
                (
                    site["selector_source"].as_str().unwrap(),
                    site["repeats"].as_str().unwrap(),
                    site["role"].as_str().unwrap()
                ),
                ("cursor_index", "loop", "interpreter-candidate"),
                "{name}: {site}"
            );
        }
    }

    /// Review regression: a selector with more reaching writes than one
    /// query may trace is an honest unknown with a counted omission.
    #[test]
    fn exhausted_trace_budget_is_an_honest_counted_unknown() {
        let writes = (0..5000)
            .map(|i| {
                format!("(local.set $op (i32.load8_u (i32.add (local.get $code) (i32.const {i}))))")
            })
            .collect::<String>();
        let bytes = wat::parse_str(format!(
            r#"(module (memory 1)
              (func (param $code i32) (local $op i32)
                {writes}
                (block $b (block $a (br_table $a $b (local.get $op))))))"#
        ))
        .unwrap();
        let document = classify_module(&bytes);
        assert_eq!(document["sites"][0]["selector_source"], "unknown");
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |omission| omission["reason"] == "classification-trace-limit"
                        && omission["omitted_records"] == 1
                ),
            "{}",
            document["omissions"]
        );
    }

    /// Review regression: a memoized trace must cost the same depth and
    /// steps as computing it, so a site's result does not depend on whether
    /// another site traced part of its chain first.
    #[test]
    fn trace_results_do_not_depend_on_site_order() {
        let chain = (1..=10)
            .map(|i| format!("(local.set $a{i} (local.get $a{}))", i - 1))
            .collect::<String>();
        let locals = (0..=10)
            .map(|i| format!("(local $a{i} i32)"))
            .collect::<String>();
        let function = |first: usize, second: usize| {
            format!(
                r#"(func (param $code i32) (param $len i32) (local $pc i32) {locals}
                  (block $exit (loop $again
                    (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
                    (local.set $a0 (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
                    (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
                    {chain}
                    (block $y (block $x (br_table $x $y (local.get $a{first}))))
                    (block $w (block $v (br_table $v $w (local.get $a{second}))))
                    (br $again))))"#
            )
        };
        let bytes = wat::parse_str(format!(
            "(module (memory 1) {} {})",
            function(5, 10),
            function(10, 5)
        ))
        .unwrap();
        let document = classify_module(&bytes);
        let result = |function: u64, local: &str| {
            document["sites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|site| {
                    site["location"]["function_index"] == function
                        && site["selector"]["expression"]
                            .as_str()
                            .unwrap()
                            .starts_with(local)
                })
                .map(|site| {
                    (
                        site["selector_source"].clone(),
                        site["repeats"].clone(),
                        site["role"].clone(),
                    )
                })
                .unwrap()
        };
        // local8 is $a5 and local13 is $a10, after code, len and pc.
        assert_eq!(result(0, "local8"), result(1, "local8"));
        assert_eq!(result(0, "local13"), result(1, "local13"));
    }

    #[test]
    fn module_without_dispatch_records_export_per_role() {
        let bytes = wat::parse_str(
            r#"(module
              (func (export "init") (param i32) (result i32) (i32.add (local.get 0) (i32.const 1)))
              (func (export "step") (param i32) (result i32) (i32.mul (local.get 0) (i32.const 3))))"#,
        )
        .unwrap();
        let sites = dispatch_shape::wasm(&bytes, &dispatch_shape::Meter::new()).unwrap();
        let document = dispatch_shape::document(&json!("9"), sites.sites, sites.omissions);
        assert_eq!(document["site_count"], 1);
        let site = &document["sites"][0];
        assert_eq!(site["dispatch_kind"], "export_per_role");
        assert_eq!(site["role"], "other");
        assert_eq!(site["arm_count"], 2);
    }

    #[test]
    fn threaded_and_cff_loops_are_not_interpreter_candidates() {
        let bytes = wat::parse_str(
            r#"(module
              (type $step (func (param i32) (result i32)))
              (table 4 funcref)
              (func $next (type $step) (local.get 0))
              (elem (i32.const 0) func $next)
              (func (export "threaded") (param $h i32) (result i32)
                (local $handler i32)
                (local.set $handler (local.get $h))
                (block $exit
                  (loop $again
                    (br_if $exit (i32.eqz (local.get $handler)))
                    (local.set $handler (call_indirect (type $step) (local.get $handler) (local.get $handler)))
                    (br $again)))
                (local.get $handler))
              (func (export "flattened") (result i32)
                (local $state i32) (local $acc i32)
                (local.set $state (i32.const 0))
                (block $exit
                  (loop $again
                    (block $two (block $one (block $zero
                      (br_table $zero $one $two $exit (local.get $state)))
                      (local.set $state (i32.const 2)) (br $again))
                      (local.set $state (i32.const 3)) (br $again))
                    (local.set $acc (i32.const 7))
                    (local.set $state (i32.const 1))
                    (br $again)))
                (local.get $acc)))"#,
        )
        .unwrap();
        let sites = dispatch_shape::wasm(&bytes, &dispatch_shape::Meter::new()).unwrap();
        let document = dispatch_shape::document(&json!("9"), sites.sites, sites.omissions);
        let listed = document["sites"].as_array().unwrap();
        let threaded = listed
            .iter()
            .find(|site| site["instruction"] == "call_indirect")
            .unwrap();
        assert_eq!(threaded["dispatch_kind"], "threaded");
        assert_eq!(threaded["selector_source"], "handler_address");
        assert_eq!(threaded["repeats"], "loop");
        assert_eq!(threaded["role"], "other");
        let flattened = listed
            .iter()
            .find(|site| site["instruction"] == "br_table")
            .unwrap();
        assert_eq!(flattened["selector_source"], "constant");
        assert_eq!(flattened["repeats"], "loop");
        assert_eq!(flattened["role"], "other");
        assert_eq!(document["role_counts"]["interpreter-candidate"], 0);
    }
}
