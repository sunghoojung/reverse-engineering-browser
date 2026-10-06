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
use wasmparser::{Operator, Parser, Payload, TypeRef};
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
fn mask(source: &str) -> String {
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
        Regex::new(r"\bswitch\s*\(|\b[A-Za-z_$][\w$]*\s*\[[^\]]+\]\s*\(").unwrap()
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
        return Err(Error::bad("unterminated JavaScript function body"));
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
struct Instruction {
    opcode: u8,
    start: usize,
    end: usize,
    variable: Option<(bool, u32)>,
    loop_depth: usize,
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
            Payload::ElementSection(reader) => table_ranges.push(reader.range()),
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
                    decoded.push(Instruction {
                        opcode,
                        start,
                        end,
                        variable,
                        loop_depth,
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
                        "The same decoded local or global is read, advanced, and written.",
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
                if rank(&obs) > best_rank {
                    best_rank = rank(&obs);
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
        json!({"section_count":sections,"code_section_count":code_sections,"data_section_count":data_ranges.len(),"decoded_function_count":functions,"imported_function_count":imported,"decoded_instruction_count":instructions_count}),
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
fn digest(value: &Value) -> Result<String> {
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
fn analyze(artifact: &Value, bytes: &[u8], events: &[Value]) -> Value {
    let runtime = if artifact["kind"] == "javascript" {
        "javascript"
    } else {
        "webassembly"
    };
    let source = if runtime == "javascript" {
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return failure(
                    artifact,
                    "malformed-artifact",
                    "Artifact is not UTF-8 JavaScript",
                );
            }
        }
    } else {
        ""
    };
    let (observations, frontend, mut omissions) = if runtime == "javascript" {
        match js(source) {
            Ok((obs, omissions)) => (obs, json!({"replacement_character_count":0}), omissions),
            Err(e) => return failure(artifact, "malformed-artifact", &e.message),
        }
    } else {
        match wasm(bytes) {
            Ok((obs, frontend)) => (obs, frontend, Vec::new()),
            Err(e) => return failure(artifact, "malformed-artifact", &e.message),
        }
    };
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
    // Keep the scoring representatives first, so every retained relevance
    // explanation has a graph node even when later context exceeds the cap.
    for (event, observed) in representatives.values().copied().chain(runtime_events) {
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
        result["bytecode_snapshot"]=bytecode(source,artifact["artifact_id"].as_str().unwrap()).unwrap_or_else(||json!({"artifact_id":artifact["artifact_id"],"snapshot_hex":null,"unavailable_reason":"No bounded static byte initializer was recognized."}));
    }
    result
}
fn bytecode(source: &str, id: &str) -> Option<Value> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:Uint8Array\.of|new\s+Uint8Array)\s*\((?:\[)?\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+))*)").unwrap()
    });
    let m = PATTERN.captures(source)?;
    let full = m[1]
        .split(',')
        .map(|n| {
            let n = n.trim();
            if n.starts_with("0x") || n.starts_with("0X") {
                u8::from_str_radix(&n[2..], 16)
            } else {
                n.parse::<u8>()
            }
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    let size = full.len().min(256);
    Some(
        json!({"artifact_id":id,"producer":{"kind":"static-initializer","byte_offset":m.get(0)?.start()},"consumer":{"kind":"indexed-read","status":"inferred"},"sha256":hex::encode(Sha256::digest(&full)),"original_byte_count":full.len(),"snapshot_byte_count":size,"snapshot_hex":hex::encode(&full[..size]),"truncated":size<full.len(),"unavailable_reason":null}),
    )
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
pub fn store(root: &Path, event_store: &Path) -> Result<Value> {
    let (manifest, mut omissions, manifest_digest) = input(
        &root.join("manifest.jsonl"),
        65536,
        10000,
        "artifact-manifest",
    )?;
    let (event_records, event_omissions, event_digest) =
        input(event_store, 16384, 100000, "event")?;
    omissions.extend(event_omissions);
    let mut artifacts = Vec::new();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for (line, mut artifact) in manifest {
        let error = evidence::validate_artifact(&mut artifact)
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
        } else {
            artifacts.push(artifact);
        }
    }
    let mut events = Vec::<Option<Value>>::new();
    let mut event_ids = BTreeMap::<EventReference, Option<usize>>::new();
    let mut capture_gaps = 0usize;
    for (line, event) in event_records {
        let reference = event_reference(&event);
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
        if event["type"] == "gap" {
            capture_gaps += 1;
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
    let mut limits = serde_json::Map::new();
    for (key, value) in CONFIG.as_object().unwrap() {
        if let Some(name) = key.strip_prefix("MAX_")
            && name != "JS_FUNCTION_SIGNATURE_CHARACTERS"
        {
            limits.insert(format!("max_{}", name.to_ascii_lowercase()), value.clone());
        }
    }
    let profile = json!({"profile_id":PROFILE,"javascript_scoring_version":2,"candidate_threshold":20,"likely_vm_threshold":60,"likely_vm_required_families":3,"rule_weights":CONFIG["RULE_WEIGHTS"],"runtime_evidence_version":2,"runtime_rule_weights":runtime_weights(),"limits":limits});
    let mut results = failures;
    for artifact in &artifacts {
        if !["javascript", "wasm"].contains(&artifact["kind"].as_str().unwrap_or("")) {
            continue;
        }
        let mut result = match evidence::content(root, artifact, 16 * 1024 * 1024) {
            Ok(bytes) => analyze(artifact, &bytes, &events),
            Err(e) => failure(
                artifact,
                if e.status == 400 {
                    "artifact-byte-limit"
                } else {
                    "artifact-integrity"
                },
                &e.message,
            ),
        };
        if result["status"] != "failed" && !omissions.is_empty() {
            result["status"] = json!("partial");
            result["coverage"]["complete"] = json!(false);
            result["coverage"]["omissions"]
                .as_array_mut()
                .unwrap()
                .extend(omissions.clone());
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
    let mut document = json!({"contract_version":1,"document_kind":"vm-analysis","producer":{"id":"origin-trace-vm-detector","version":"1.1.1"},"profile_digest":digest(&profile)?,"profile":profile,"inputs":{"artifact_manifest_digest":manifest_digest,"event_store_digest":event_digest},"input_coverage":{"complete":omissions.is_empty(),"omissions":omissions},"summary":{"analyzed_artifacts":results.len(),"candidate_count":results.iter().filter(|r|r["tier"]=="candidate").count(),"likely_vm_count":results.iter().filter(|r|r["tier"]=="likely-vm").count(),"failed_count":results.iter().filter(|r|r["status"]=="failed").count(),"mixed_count":mixed.len()},"results":results,"mixed_findings":mixed});
    document["document_digest"] = json!(digest(&document)?);
    durable::write_private(
        &root.join("analysis/vm-analysis-v1.json"),
        &canonical(&document)?,
    )?;
    Ok(document)
}
