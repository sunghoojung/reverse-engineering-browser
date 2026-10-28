use crate::{
    durable,
    error::{Error, Result},
    evidence,
};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};
use wasmparser::{ElementItems, ElementKind, Operator, Parser, Payload, TypeRef};
#[path = "vm_capture_mode.rs"]
pub(crate) mod capture_mode;
#[path = "vm_dispatch_shape.rs"]
pub(crate) mod dispatch_shape;
#[cfg(test)]
#[path = "vm_review_inputs.rs"]
pub(crate) mod review_inputs;
#[path = "vm_wasm_dispatch.rs"]
mod wasm_dispatch;
#[path = "vm_wasm_tables.rs"]
pub(crate) mod wasm_tables;

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
    json!({"id":"origin-trace-vm-detector","version":"1.6.0"})
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
    json!({"profile_id":PROFILE,"javascript_scoring_version":2,"javascript_likely_vm_requires_handlers":true,"candidate_threshold":20,"likely_vm_threshold":60,"likely_vm_required_families":3,"rule_weights":CONFIG["RULE_WEIGHTS"],"runtime_evidence_version":2,"runtime_rule_weights":runtime_weights(),"limits":limits})
}

pub(crate) fn current_rule_definitions() -> Vec<Value> {
    let mut rules = Vec::new();
    for (id, weight) in CONFIG["RULE_WEIGHTS"].as_object().unwrap() {
        let detail = JS_RULES.iter().find(|(rule, _, _)| *rule == id)
            .map(|(_, detail, _)| *detail).unwrap_or_else(|| match id.as_str() {
                "js.dispatch-loop" => "A loop and switch or indexed call occur in one approximate function region.",
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
pub(crate) fn mask(source: &str) -> String {
    let mut bytes = source.as_bytes().to_vec();
    let mut index = 0;
    let mut quote = 0;
    let mut line = false;
    let mut block = false;
    let mut escaped = false;
    while index < bytes.len() {
        let c = source.as_bytes()[index];
        let next = source.as_bytes().get(index + 1).copied().unwrap_or(0);
        if line {
            if c == b'\n' {
                line = false;
            } else {
                bytes[index] = b' ';
            }
        } else if block {
            bytes[index] = b' ';
            if c == b'*' && next == b'/' {
                bytes[index + 1] = b' ';
                index += 1;
                block = false;
            }
        } else if quote != 0 {
            bytes[index] = b' ';
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == quote {
                quote = 0;
            }
        } else if c == b'/' && b"/*".contains(&next) {
            bytes[index] = b' ';
            bytes[index + 1] = b' ';
            index += 1;
            line = next == b'/';
            block = next == b'*';
        } else if b"\"'`".contains(&c) {
            bytes[index] = b' ';
            quote = c;
        }
        index += 1;
    }
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
        if let (Some(a), Some(b)) = (LOOP.find(&region), DISPATCH.find(&region)) {
            observations.push(observation(
                "js.dispatch-loop",
                a.start().min(b.start()),
                a.end().max(b.end()),
                "A loop and switch or indexed callable dispatch occur in the same function region.",
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
/// Structural dispatch classification of one JavaScript source, run as its
/// own metered pass after the unchanged scoring pass. It recomputes the same
/// function regions, then classifies them strongest pattern rank first so
/// large noise regions cannot starve a real interpreter of the meter.
fn classify_javascript(source: &str, meter: &dispatch_shape::Meter) -> dispatch_shape::Classified {
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
    let mut omissions = Vec::new();
    meter.charge(3 * source.len() as u64);
    let masked = mask(source);
    let mut openings = BTreeMap::new();
    for m in SIGNATURE.find_iter(&masked) {
        if openings.len() >= 4096 {
            break;
        }
        openings.insert(m.end() - 1, m.start());
    }
    let mut stack = Vec::new();
    let mut regions = vec![(0, source.len())];
    let mut parameters = BTreeMap::<usize, Vec<String>>::new();
    for (i, c) in masked.bytes().enumerate() {
        if c == b'{' {
            stack.push(i);
        } else if c == b'}'
            && let Some(start) = stack.pop()
            && let Some(signature) = openings.remove(&start)
        {
            regions.push((start + 1, i));
            parameters.insert(
                start + 1,
                dispatch_shape::javascript::parameters(&masked[signature..=start]),
            );
        }
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
    let region_text = |start: usize, end: usize| {
        let mut bytes = masked.as_bytes()[start..end].to_vec();
        for (a, b) in children.get(&(start, end)).into_iter().flatten() {
            bytes[a - start..b - start].fill(b' ');
        }
        String::from_utf8(bytes).expect("masked nested source")
    };
    // The same structural rank the scoring pass gives each region, so the
    // strongest dispatch evidence is classified first.
    let mut ranked = Vec::new();
    let mut work = 0usize;
    for (start, end) in regions {
        if work + end - start > 64 * 1024 * 1024 {
            omissions.push(json!({"reason":"classification-region-limit","detail":"Function regions past the JavaScript region work bound were not searched for dispatch sites."}));
            break;
        }
        work += end - start;
        if !meter.charge((1 + JS_RULES.len() as u64) * (end - start) as u64) {
            meter.count_unexamined(1);
            continue;
        }
        let region = region_text(start, end);
        let mut observations = Vec::new();
        if let (Some(a), Some(b)) = (LOOP.find(&region), DISPATCH.find(&region)) {
            observations.push(observation("js.dispatch-loop", a.start(), b.end(), ""));
        }
        for (id, _, patterns) in JS_RULES.iter() {
            if patterns.iter().any(|pattern| pattern.is_match(&region)) {
                observations.push(observation(id, 0, 1, ""));
            }
        }
        ranked.push((rank(&observations), start, end));
    }
    ranked.sort_by_key(|((score, families), start, _)| {
        (
            std::cmp::Reverse(*score),
            std::cmp::Reverse(*families),
            *start,
        )
    });
    let lines = dispatch_shape::javascript::Lines::new(source);
    let mut sites = Vec::new();
    for (_, start, end) in ranked {
        if meter.exhausted() {
            meter.count_unexamined(1);
            continue;
        }
        let region = region_text(start, end);
        if !meter.retain(region.len() as u64) {
            meter.release(region.len() as u64);
            meter.count_unexamined(1);
            continue;
        }
        dispatch_shape::javascript::classify_region(
            source,
            &lines,
            &region,
            start,
            parameters.get(&start).map_or(&[], Vec::as_slice),
            &mut sites,
            meter,
        );
        meter.release(region.len() as u64);
    }
    omissions.extend(meter.omissions("function regions"));
    dispatch_shape::Classified { sites, omissions }
}

/// Classify an artifact's dispatch sites under one fresh meter.
fn classify_artifact(
    runtime: &str,
    bytes: &[u8],
    meter: &dispatch_shape::Meter,
) -> Option<dispatch_shape::Classified> {
    match runtime {
        "javascript" => Some(classify_javascript(std::str::from_utf8(bytes).ok()?, meter)),
        "webassembly" => Some(dispatch_shape::wasm(bytes, meter).unwrap_or(
            dispatch_shape::Classified {
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

/// Classification of one Wasm module and the meter that bounded it.
#[cfg(test)]
pub(crate) fn wasm_classification_work(bytes: &[u8]) -> (Value, dispatch_shape::Meter) {
    let meter = dispatch_shape::Meter::new();
    let document = classification_under("webassembly", bytes, &meter);
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
                    let loop_depth = control.iter().filter(|c| **c == 3).count();
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
                    match op {
                        Operator::Block { .. } => control.push(2),
                        Operator::Loop { .. } => control.push(3),
                        Operator::If { .. } => control.push(4),
                        Operator::Else => {
                            if control.last() != Some(&4) {
                                return Err(Error::bad("WebAssembly else without matching if"));
                            }
                        }
                        Operator::End if control.pop().is_none() => {
                            ended = true;
                            if !reader.eof() {
                                return Err(Error::bad(
                                    "WebAssembly function body has trailing instructions",
                                ));
                            }
                        }
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
fn graph_entry(
    nodes: &mut Vec<Value>,
    edges: &mut Vec<Value>,
    seen: &mut BTreeSet<String>,
    node: Value,
    edge: Value,
) -> bool {
    let id = node["id"].as_str().unwrap();
    if seen.contains(id) {
        return true;
    }
    if edges.len() >= CONFIG["MAX_GRAPH_EDGES"].as_u64().unwrap() as usize {
        return false;
    }
    seen.insert(id.into());
    nodes.push(node);
    edges.push(edge);
    true
}
#[cfg(test)]
fn analyze(artifact: &Value, bytes: &[u8], events: &[Value]) -> Value {
    analyze_with_roles(artifact, bytes, events).0
}

/// The analysis result and the roles of every classified dispatch site, which
/// the opcode-claim gate reads without classifying the artifact again.
fn analyze_with_roles(
    artifact: &Value,
    bytes: &[u8],
    events: &[Value],
) -> (Value, Option<dispatch_shape::Roles>) {
    let runtime = if artifact["kind"] == "javascript" {
        "javascript"
    } else {
        "webassembly"
    };
    let source = if runtime == "javascript" {
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return (
                    failure(
                        artifact,
                        "malformed-artifact",
                        "Artifact is not UTF-8 JavaScript",
                    ),
                    None,
                );
            }
        }
    } else {
        ""
    };
    let (observations, mut frontend, mut omissions) = if runtime == "javascript" {
        match js(source) {
            Ok((obs, omissions)) => (obs, json!({"replacement_character_count":0}), omissions),
            Err(e) => return (failure(artifact, "malformed-artifact", &e.message), None),
        }
    } else {
        match wasm(bytes) {
            Ok((obs, frontend)) => {
                let omitted = frontend["dispatch_inventory"]["omitted_site_count"]
                    .as_u64()
                    .unwrap_or(0);
                let omissions = if omitted > 0 {
                    vec![json!({"reason":"dispatch-inventory-limit","omitted_records":omitted})]
                } else {
                    Vec::new()
                };
                (obs, frontend, omissions)
            }
            Err(e) => return (failure(artifact, "malformed-artifact", &e.message), None),
        }
    };
    // Classification is interpretation over the same bytes, metered on its
    // own and never an input to the observations, score or tier above.
    let meter = dispatch_shape::Meter::new();
    let classified = classify_artifact(runtime, bytes, &meter);
    let roles = classified
        .as_ref()
        .map(|classified| dispatch_shape::Roles::new(classified, &meter));
    if let Some(classified) = classified {
        frontend["dispatch_classification"] = dispatch_shape::document(
            &artifact["artifact_id"],
            classified.sites,
            classified.omissions,
        );
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
    let id = finding(artifact["sha256"].as_str().unwrap(), &rules);
    let artifact_node = format!("artifact:{}", artifact["artifact_id"].as_str().unwrap());
    let finding_node = format!("finding:{id}");
    let mut nodes = vec![
        json!({"id":artifact_node,"kind":"artifact","label":artifact["url"]}),
        json!({"id":finding_node,"kind":"vm-candidate","label":id}),
    ];
    let mut edges = vec![
        json!({"from":artifact_node,"to":finding_node,"state":"inferred","reason":"Deterministic static analysis produced this candidate."}),
    ];
    let mut requests = Vec::<String>::new();
    let mut runtime_events = Vec::new();
    let mut request_events = Vec::new();
    let mut representatives = BTreeMap::<&str, (&Value, bool)>::new();
    let mut unavailable = 0usize;
    for event in events.iter().filter(|e| {
        e["session_id"] == artifact["session_id"] && e["navigation_id"] == artifact["navigation_id"]
    }) {
        let rule = runtime_rule(event);
        let request = event["category"] == "network"
            && ["request_started", "request_initiated"]
                .contains(&event["type"].as_str().unwrap_or(""))
            && event["request_id"].as_str().is_some_and(|id| id != "0");
        if rule.is_none() && !request {
            continue;
        }
        let observed =
            artifact["artifact_id"] != "0" && event["artifact_id"] == artifact["artifact_id"];
        // Zero frame IDs mean unavailable attribution (for example a worker),
        // not a shared frame. Explicit captured artifact attribution can still
        // identify a signal when both frame IDs are unavailable.
        if event["frame_id"] != artifact["frame_id"] {
            continue;
        }
        if artifact["frame_id"] == "0" && (!observed || rule.is_none()) {
            unavailable += 1;
            continue;
        }
        if let Some(rule) = rule {
            runtime_events.push((event, observed));
            let representative = representatives.entry(rule).or_insert((event, observed));
            if observed && !representative.1 {
                *representative = (event, true);
            }
        }
        if request {
            request_events.push(event);
        }
    }
    let weights = runtime_weights();
    for (rule, (event, observed)) in &representatives {
        // Runtime evidence has an event coordinate, never an invented source
        // byte range. It changes relevance only, not structural VM scoring.
        anti.push(json!({"rule_id":rule,"weight":weights[*rule],"event":event_value(event),"event_sequence":event["sequence_number"],"state":if *observed {"observed"} else {"correlated"},"detail":if *observed {"A captured browser-signal event explicitly names this artifact. API use alone does not establish fingerprinting or anti-bot behavior."} else {"A captured browser-signal event shares this artifact's session, navigation metadata, and nonzero frame. Script attribution and causality are unknown; API use alone does not establish fingerprinting or anti-bot behavior."}}));
    }
    let mut graph_ids = BTreeSet::new();
    let mut graph_omitted = 0usize;
    // Scoring representatives stay first, so every retained relevance
    // explanation has a graph node even when later context exceeds the cap.
    // Request edges follow, before individual signal events. A browser-signal
    // flood must not consume the cap and drop every correlated request.
    for (event, observed) in representatives.values().copied() {
        let node = event_node("event", event);
        if !graph_entry(
            &mut nodes,
            &mut edges,
            &mut graph_ids,
            json!({"id":node,"kind":"browser-signal","label":format!("{} {}",event["category"].as_str().unwrap(),event["type"].as_str().unwrap()),"event":event_value(event),"event_sequence":event["sequence_number"]}),
            json!({"from":node,"to":finding_node,"state":if observed {"observed"} else {"correlated"},"reason":if observed {"Captured nonzero artifact attribution; no value flow is claimed."} else {"Matching session, navigation metadata, and nonzero frame; script attribution and causality remain unknown."}}),
        ) {
            graph_omitted += 1;
        }
    }
    for event in request_events {
        let request = event["request_id"].as_str().unwrap();
        let node = event_node("request", event);
        if graph_entry(
            &mut nodes,
            &mut edges,
            &mut graph_ids,
            json!({"id":node,"kind":"request","label":format!("request {request}"),"request_id":request,"event":event_value(event),"event_sequence":event["sequence_number"]}),
            json!({"from":finding_node,"to":node,"state":"correlated","reason":"Matching session, navigation metadata, and nonzero frame. Exact value provenance and causal ordering are not claimed."}),
        ) {
            if !requests.iter().any(|r| r == request) {
                requests.push(request.into());
            }
        } else {
            graph_omitted += 1;
        }
    }
    for (event, observed) in runtime_events {
        let node = event_node("event", event);
        if !graph_entry(
            &mut nodes,
            &mut edges,
            &mut graph_ids,
            json!({"id":node,"kind":"browser-signal","label":format!("{} {}",event["category"].as_str().unwrap(),event["type"].as_str().unwrap()),"event":event_value(event),"event_sequence":event["sequence_number"]}),
            json!({"from":node,"to":finding_node,"state":if observed {"observed"} else {"correlated"},"reason":if observed {"Captured nonzero artifact attribution; no value flow is claimed."} else {"Matching session, navigation metadata, and nonzero frame; script attribution and causality remain unknown."}}),
        ) {
            graph_omitted += 1;
        }
    }
    if unavailable > 0 {
        omissions.push(
            json!({"reason":"runtime-frame-attribution-unavailable","omitted_records":unavailable}),
        );
    }
    if graph_omitted > 0 {
        omissions
            .push(json!({"reason":"runtime-graph-edge-limit","omitted_records":graph_omitted}));
    }
    let mut result = json!({"artifact_id":artifact["artifact_id"],"artifact_sha256":artifact["sha256"],"runtime":runtime,"status":if omissions.is_empty() {"complete"} else {"partial"},"finding_id":id,"tier":tier,"vm_score":score,"vm_threshold":60,"required_family_count":3,"evidence_families":observations.iter().map(|o|o["family"].as_str().unwrap()).collect::<BTreeSet<_>>(),"observations":observations,"anti_bot_score":anti.iter().map(|o|o["weight"].as_u64().unwrap()).sum::<u64>().min(100),"anti_bot_observations":anti,"related_request_ids":requests,"graph":{"nodes":nodes,"edges":edges},"coverage":{"complete":omissions.is_empty(),"observed_bytes":bytes.len(),"total_bytes":bytes.len(),"omissions":omissions,"residual_unknowns":["Static evidence does not confirm guest dispatch at runtime.","Request edges are correlation, not exact value provenance."]},"frontend":frontend});
    if runtime == "javascript" && tier != "none" {
        result["bytecode_snapshot"] =
            crate::vm_bytecode::snapshot(source, artifact["artifact_id"].as_str().unwrap());
    }
    (result, roles)
}
// Read a bounded prefix, report omissions, and hash exactly the consumed input.
type JsonlInput = (Vec<(usize, Value)>, Vec<Value>, String);
fn input(path: &Path, line_limit: u64, record_limit: usize, source: &str) -> Result<JsonlInput> {
    use std::io::{BufRead, Read};
    let file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((vec![], vec![], hex::encode(Sha256::digest([]))));
        }
        Err(e) => return Err(e.into()),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    let mut omissions = Vec::new();
    let mut hash = Sha256::new();
    let mut line = 0;
    let started = std::time::Instant::now();
    while records.len() < record_limit {
        if started.elapsed() > std::time::Duration::from_secs(10) {
            omissions.push(json!({"reason":format!("{source}-read-deadline")}));
            break;
        }
        let mut bytes = Vec::new();
        let size = reader
            .by_ref()
            .take(line_limit + 1)
            .read_until(b'\n', &mut bytes)?;
        if size == 0 {
            break;
        }
        line += 1;
        hash.update(&bytes);
        if size as u64 > line_limit {
            omissions.push(json!({"reason":format!("{source}-line-byte-limit"),"line":line}));
            break;
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice(&bytes) {
            Ok(v) => records.push((line, v)),
            Err(_) => omissions.push(json!({"reason":format!("malformed-{source}"),"line":line})),
        }
        if omissions.len() >= 1024 {
            omissions.push(json!({"reason":format!("{source}-omission-limit")}));
            break;
        }
    }
    if records.len() >= record_limit && reader.read(&mut [0u8])? != 0 {
        omissions.push(
            json!({"reason":format!("{source}-record-limit"),"observed_records":records.len()}),
        );
    }
    Ok((records, omissions, hex::encode(hash.finalize())))
}
pub(crate) struct Documents {
    pub analysis: Value,
    pub opcode_workspace: Result<Value>,
    pub host_links: Result<Value>,
}

pub(crate) fn store_documents(root: &Path, event_store: &Path) -> Result<Documents> {
    let (manifest, mut omissions, manifest_digest) = input(
        &root.join("manifest.jsonl"),
        65536,
        10000,
        "artifact-manifest",
    )?;
    let (event_records, event_omissions, event_digest) =
        input(event_store, 16384, 100000, "event")?;
    omissions.extend(event_omissions);
    let capture_provenance = capture_mode::Provenance::read(root)?;
    let capture_mode = if omissions.is_empty() {
        capture_provenance.aggregate(
            manifest
                .iter()
                .chain(event_records.iter())
                .map(|(_, record)| record),
        )
    } else {
        "unknown"
    };
    let mut artifacts = Vec::new();
    let mut snapshot_artifacts = Vec::new();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for (line, mut artifact) in manifest {
        let snapshot_candidate = crate::vm_opcode::is_snapshot_candidate(&artifact);
        let error = if snapshot_candidate {
            crate::vm_opcode::validate_snapshot_artifact(&artifact)
        } else {
            evidence::validate_artifact(&mut artifact)
        }
        .err()
        .map(|e| e.message)
        .or_else(|| {
            (!seen.insert(artifact["artifact_id"].as_str().unwrap_or("").to_owned()))
                .then(|| "duplicate artifact ID".into())
        });
        if let Some(reason) = error {
            let omission = json!({"reason":"invalid-artifact-manifest","line":line});
            omissions.push(omission.clone());
            let id = if evidence::canonical(&artifact["artifact_id"], 64, false) {
                artifact["artifact_id"].clone()
            } else {
                json!("0")
            };
            let hash = artifact["sha256"]
                .as_str()
                .filter(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            failures.push(json!({"artifact_id":id,"artifact_sha256":hash,"runtime":match artifact["kind"].as_str() {Some("javascript")=>"javascript",Some("wasm")=>"webassembly",_=>"unknown"},"status":"failed","error":{"code":"invalid-artifact-manifest","message":format!("Artifact manifest line {line}: {reason}")},"coverage":{"complete":false,"omissions":[omission]}}));
        } else if snapshot_candidate || artifact["kind"] == "wasm_guest_adapter" {
            snapshot_artifacts.push(artifact);
        } else {
            artifacts.push(artifact);
        }
    }
    let invalid_ids = failures
        .iter()
        .filter_map(|f| f["artifact_id"].as_str())
        .collect::<BTreeSet<_>>();
    snapshot_artifacts.retain(|a| {
        a["capture_origin"] != "native_wasm_guest"
            || !invalid_ids.contains(a["artifact_id"].as_str().unwrap_or(""))
    });
    // Resolve before normalization so conflicting identities remain tombstones.
    let exact_request_links = {
        let index =
            crate::vm_request_links::Index::new(event_records.iter().map(|(_, event)| event));
        let invalid_ids = failures
            .iter()
            .filter_map(|failure| failure["artifact_id"].as_str())
            .collect::<BTreeSet<_>>();
        artifacts
            .iter()
            .map(|artifact| {
                let id = artifact["artifact_id"].as_str().unwrap().to_owned();
                let duplicate = invalid_ids.contains(id.as_str());
                (
                    id,
                    if duplicate {
                        Vec::new()
                    } else {
                        index.links(artifact)
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let mut events = Vec::<Option<Value>>::new();
    let mut event_ids = BTreeMap::<EventReference, Option<usize>>::new();
    let mut capture_gaps = 0usize;
    let mut dispatch_budget_losses = Vec::new();
    for (line, event) in event_records {
        let reference = if event["type"] == "vm_dispatch_report" {
            crate::vm_dispatch_input::report_reference(&event)
        } else {
            event_reference(&event)
        };
        if reference.is_none()
            || !matches!(event["protocol_version"].as_u64(), Some(2 | 3))
            || !["navigation_id", "frame_id"]
                .iter()
                .all(|k| evidence::canonical(&event[k], 64, false))
            || !["category", "type"].iter().all(|k| event[k].is_string())
            || ["artifact_id", "request_id"].iter().any(|k| {
                event
                    .get(k)
                    .is_some_and(|v| !evidence::canonical(v, 64, false))
            })
        {
            omissions.push(json!({"reason":"invalid-event-contract","line":line}));
            continue;
        }
        // Transport gap markers intentionally reuse the preceding retained
        // event's sequence. They are coverage evidence, not conflicting events.
        // A vm gap that names an interpreter artifact is also a dispatch-budget
        // loss. The opcode workspace sums that weight so a capped trace stays
        // incomplete. Other gaps stay capture-gap markers only.
        if event["type"] == "gap" {
            capture_gaps += 1;
            if let Some(loss) = crate::vm_opcode::dispatch_budget_loss(&event) {
                dispatch_budget_losses.push(loss);
            }
            continue;
        }
        let reference = reference.unwrap();
        match event_ids.get_mut(&reference) {
            Some(Some(index)) if events[*index].as_ref() != Some(&event) => {
                events[*index] = None;
                *event_ids.get_mut(&reference).unwrap() = None;
                omissions.push(json!({"reason":"conflicting-event-identity","line":line}));
            }
            Some(_) => (),
            None => {
                event_ids.insert(reference, Some(events.len()));
                events.push(Some(event));
            }
        }
    }
    if capture_gaps > 0 {
        // This counts markers, not dropped events: queue reports and sequence
        // gaps can overlap and must never be added into a fabricated loss total.
        omissions.push(json!({"reason":"capture-gap","observed_records":capture_gaps}));
    }
    let events = events.into_iter().flatten().collect::<Vec<_>>();
    let profile = current_profile();
    let mut results = failures;
    let mut opcode_workspaces = Vec::new();
    for artifact in &artifacts {
        if !["javascript", "wasm"].contains(&artifact["kind"].as_str().unwrap_or("")) {
            continue;
        }
        let (mut result, bytes) = match evidence::content(root, artifact, 16 * 1024 * 1024) {
            Ok(bytes) => {
                let (result, roles) = analyze_with_roles(artifact, &bytes, &events);
                (result, Some((bytes, roles)))
            }
            Err(e) => (
                failure(
                    artifact,
                    if e.status == 400 {
                        "artifact-byte-limit"
                    } else {
                        "artifact-integrity"
                    },
                    &e.message,
                ),
                None,
            ),
        };
        if result["status"] != "failed" {
            result["exact_request_links"] = json!(
                exact_request_links
                    .get(artifact["artifact_id"].as_str().unwrap())
                    .cloned()
                    .unwrap_or_default()
            );
        }
        if result["status"] != "failed" && !omissions.is_empty() {
            result["status"] = json!("partial");
            result["coverage"]["complete"] = json!(false);
            result["coverage"]["omissions"]
                .as_array_mut()
                .unwrap()
                .extend(omissions.clone());
        }
        if let Some((bytes, roles)) = bytes
            && let Some(mut workspace) = crate::vm_opcode::workspace(
                root,
                artifact,
                &bytes,
                crate::vm_opcode::Analysis {
                    result: &result,
                    roles: roles.as_ref(),
                },
                &snapshot_artifacts,
                &events,
                &dispatch_budget_losses,
            )
        {
            workspace["capture_mode"] = json!(capture_provenance.mode(&artifact["session_id"]));
            retain_handlerless_javascript_as_candidate(&mut result, &workspace);
            opcode_workspaces.push(workspace);
        }
        results.push(result);
    }
    let mut mixed = Vec::new();
    for wasm in results.iter().filter(|r| {
        r["runtime"] == "webassembly"
            && ["candidate", "likely-vm"].contains(&r["tier"].as_str().unwrap_or(""))
    }) {
        let parent = artifacts
            .iter()
            .find(|a| a["artifact_id"] == wasm["artifact_id"])
            .map(|a| a["parent_artifact_id"].clone())
            .unwrap_or(Value::Null);
        if let Some(js) = results.iter().find(|r| {
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
    let mut document = json!({"contract_version":1,"document_kind":"vm-analysis","producer":current_producer(),"profile_digest":digest(&profile)?,"profile":profile,"inputs":{"artifact_manifest_digest":manifest_digest,"event_store_digest":event_digest,"capture_provenance_digest":capture_provenance.digest},"capture_mode":capture_mode,"input_coverage":{"complete":omissions.is_empty(),"omissions":omissions},"summary":{"analyzed_artifacts":results.len(),"candidate_count":results.iter().filter(|r|r["tier"]=="candidate").count(),"likely_vm_count":results.iter().filter(|r|r["tier"]=="likely-vm").count(),"failed_count":results.iter().filter(|r|r["status"]=="failed").count(),"mixed_count":mixed.len()},"results":results,"mixed_findings":mixed});
    document["document_digest"] = json!(digest(&document)?);
    durable::write_private(
        &root.join("analysis/vm-analysis-v1.json"),
        &canonical(&document)?,
    )?;
    let opcode_workspace = crate::vm_opcode::store(root, &document, opcode_workspaces);
    let host_links = opcode_workspace
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|workspace| crate::vm_host_links::store(root, workspace, &artifacts, &events));
    Ok(Documents {
        analysis: document,
        opcode_workspace,
        host_links,
    })
}

pub fn store(root: &Path, event_store: &Path) -> Result<Value> {
    let documents = store_documents(root, event_store)?;
    documents.opcode_workspace?;
    documents.host_links?;
    Ok(documents.analysis)
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn handler_recovery_requirement_has_distinct_profile_and_accepts_older_profiles() {
        let current = current_profile();
        assert_eq!(current_producer()["version"], "1.6.0");
        assert_eq!(current["javascript_likely_vm_requires_handlers"], true);
        let mut historical = current.clone();
        historical
            .as_object_mut()
            .unwrap()
            .remove("javascript_likely_vm_requires_handlers");
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
                        _ => &site[key],
                    };
                    failed |= actual != value;
                }
                assert_eq!(site["confidence"], "structural");
                assert_eq!(site["artifact_id"], "7");
                assert!(site["selector"]["expression"].as_str().unwrap().len() > 1);
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

    /// Every embedded copy of the classification contract matches the
    /// standalone versioned schema after reference rewriting.
    #[test]
    fn dispatch_classification_contract_copies_match_the_standalone_schema() {
        let standalone: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-dispatch-classification-v1.schema.json"
        ))
        .unwrap();
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

    /// Writes every differential input for the base CLI to snapshot. Run
    /// through `make dispatch-base-expectations`; see the dispatch-review
    /// README.
    #[test]
    #[ignore = "writes inputs; run through make dispatch-base-expectations"]
    fn write_differential_inputs() {
        let directory = PathBuf::from(
            std::env::var("REB_DIFFERENTIAL_INPUTS").expect("REB_DIFFERENTIAL_INPUTS"),
        );
        std::fs::create_dir_all(&directory).unwrap();
        let mut index = Vec::new();
        for (position, (name, bytes, kind)) in
            review_inputs::differential_inputs().iter().enumerate()
        {
            let file = format!(
                "{position:04}.{}",
                if *kind == "wasm" { "wasm" } else { "js" }
            );
            std::fs::write(directory.join(&file), bytes).unwrap();
            index.push(json!({"name": name, "file": file, "kind": kind}));
        }
        std::fs::write(
            directory.join("inputs.json"),
            serde_json::to_string_pretty(&index).unwrap(),
        )
        .unwrap();
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
