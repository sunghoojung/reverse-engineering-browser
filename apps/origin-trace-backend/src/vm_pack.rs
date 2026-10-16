//! Declarative ranking overlays and conservative, offline workspace comparison.
//! Packs never change generic evidence, capture policy, or execution behavior.
use crate::{
    durable,
    error::{Error, Result},
    vm,
};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    sync::LazyLock,
};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PACK_BYTES: usize = 65536;

struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded inert JSON")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
                if value.len() > 8192 {
                    return Err(E::custom("JSON string exceeds bound"));
                }
                Ok(json!(value))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key.len() > 8192 || values.contains_key(&key) {
                        return Err(de::Error::custom("Duplicate or oversized JSON key"));
                    }
                    let StrictJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(JsonVisitor).map(Self)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::bad("VM document exceeds 16 MiB"));
    }
    let (mut depth, mut tokens, mut quoted, mut escaped) = (0usize, 0usize, false, false);
    for byte in bytes {
        if quoted {
            if !escaped && *byte == b'"' {
                quoted = false;
            }
            escaped = !escaped && *byte == b'\\';
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    tokens += 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    tokens += 1;
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                b',' | b':' => tokens += 1,
                _ => (),
            }
            if depth > 32 || tokens > 500000 {
                return Err(Error::bad("VM document structure exceeds bounds"));
            }
        }
    }
    let StrictJson(value) = serde_json::from_slice(bytes).map_err(|_| {
        Error::bad(
            "Invalid VM JSON: duplicate keys, noninteger numbers and malformed text are refused",
        )
    })?;
    if !value.is_object() {
        return Err(Error::bad("VM document must be an object"));
    }
    Ok(value)
}

pub fn read(path: &Path) -> Result<Value> {
    let bytes = durable::read_private(path, MAX_INPUT_BYTES)?
        .ok_or_else(|| Error::bad("VM document does not exist"))?;
    parse(&bytes)
}

static PACK_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!(
            "../../../protocol/vm-analysis-pack-v1.schema.json"
        ))
        .expect("pack schema"),
    )
    .expect("pack validator")
});
static WORKSPACE_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .expect("workspace schema"),
    )
    .expect("workspace validator")
});
static ANALYSIS_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
            .expect("analysis schema"),
    )
    .expect("analysis validator")
});

fn validate_pack(pack: &Value) -> Result<()> {
    // Public Rust callers receive the same integer/depth/string limits as CLI readers.
    parse(&serde_json::to_vec(pack)?)?;
    if vm::canonical(pack)?.len() > MAX_PACK_BYTES || !PACK_SCHEMA.is_valid(pack) {
        return Err(Error::bad("Invalid declarative VM analysis pack"));
    }
    let known = vm::current_rule_definitions()
        .into_iter()
        .filter_map(|rule| {
            rule["rule_id"]
                .as_str()
                .filter(|id| id.starts_with("antibot."))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for rule in pack["rules"].as_array().expect("validated rules") {
        let id = rule["rule_id"].as_str().expect("rule id");
        let label = rule["label"].as_str().expect("label");
        if !known.contains(id)
            || !seen.insert(id)
            || !label
                .chars()
                .all(|c| c.is_alphanumeric() || " ._:/-".contains(c))
        {
            return Err(Error::bad(
                "Pack rules must uniquely name existing relevance evidence with inert labels",
            ));
        }
    }
    let mut sources = BTreeSet::new();
    for binding in pack["families"].as_array().expect("validated families") {
        if !sources.insert(binding["source_artifact_sha256"].as_str().unwrap()) {
            return Err(Error::bad("Pack source family bindings must be unique"));
        }
    }
    Ok(())
}

fn verify_document(document: &Value, schema: &jsonschema::Validator) -> Result<()> {
    parse(&serde_json::to_vec(document)?)?;
    if !schema.is_valid(document) {
        return Err(Error::bad(
            "VM document does not satisfy its versioned contract",
        ));
    }
    let mut unsigned = document.clone();
    unsigned
        .as_object_mut()
        .expect("validated document")
        .remove("document_digest");
    if document["document_digest"] != vm::digest(&unsigned)? {
        return Err(Error::bad("VM document digest mismatch"));
    }
    Ok(())
}

fn finish(mut report: Value) -> Result<Value> {
    report["document_digest"] = json!(vm::digest(&report)?);
    if vm::canonical(&report)?.len() > MAX_OUTPUT_BYTES {
        return Err(Error::bad(
            "VM report exceeds 32 MiB; no partial report was produced",
        ));
    }
    Ok(report)
}

pub fn apply(pack: &Value, analysis: &Value) -> Result<Value> {
    validate_pack(pack)?;
    verify_document(analysis, &ANALYSIS_SCHEMA)?;
    let rules = pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| (rule["rule_id"].as_str().unwrap(), rule))
        .collect::<BTreeMap<_, _>>();
    let mut rankings = Vec::new();
    for result in analysis["results"].as_array().expect("analysis results") {
        if result["status"] == "failed" {
            continue;
        }
        let mut score = 0u64;
        let mut labels = Vec::new();
        let mut fallback = BTreeSet::new();
        for observation in result["anti_bot_observations"]
            .as_array()
            .expect("relevance observations")
        {
            let id = observation["rule_id"].as_str().unwrap();
            let weight = if let Some(rule) = rules.get(id) {
                labels.push(json!({"rule_id":id,"label":rule["label"]}));
                rule["weight"].as_u64().unwrap()
            } else {
                fallback.insert(id);
                observation["weight"].as_u64().unwrap()
            };
            score = score.saturating_add(weight);
        }
        rankings.push(json!({"artifact_id":result["artifact_id"],"anti_bot_score":score.min(100),"generic_anti_bot_score":result["anti_bot_score"],"labels":labels,"generic_weight_fallbacks":fallback}));
    }
    finish(
        json!({"contract_version":1,"document_kind":"vm-pack-application","pack_digest":vm::digest(pack)?,"analysis_digest":analysis["document_digest"],"generic_analysis":analysis,"rankings":rankings,"omissions":[],"limitations":["Pack rankings do not change generic VM scores, tiers, unknowns, or capture authorization."]}),
    )
}

fn workspace<'a>(document: &'a Value, artifact: &str) -> Result<&'a Value> {
    verify_document(document, &WORKSPACE_SCHEMA)?;
    validate_workspace_counts(document)?;
    let selected = document["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|workspace| workspace["interpreter_artifact_id"] == artifact)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(Error::bad(
            "Select one exact interpreter artifact in each workspace document",
        ));
    }
    let mut opcodes = BTreeSet::new();
    for handler in selected[0]["handlers"].as_array().unwrap() {
        if let Some(opcode) = handler["opcode"].as_u64()
            && !opcodes.insert(opcode)
        {
            return Err(Error::bad("Duplicate opcode rows cannot be compared"));
        }
    }
    Ok(selected[0])
}

fn family<'a>(pack: &'a Value, source: &Value) -> Result<&'a str> {
    pack["families"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| &binding["source_artifact_sha256"] == source)
        .and_then(|binding| binding["program_family"].as_str())
        .ok_or_else(|| Error::bad("Selected source digest has no declared program-family binding"))
}

fn identity(document: &Value, workspace: &Value) -> Value {
    json!({"workspace_digest":document["document_digest"],"source_artifact_sha256":workspace["source_artifact_sha256"],"interpreter_artifact_id":workspace["interpreter_artifact_id"]})
}

fn validate_workspace_counts(document: &Value) -> Result<()> {
    let workspaces = document["workspaces"].as_array().unwrap();
    let mut totals = [workspaces.len() as u64, 0u64, 0, 0, 0];
    for workspace in workspaces {
        let handlers = workspace["handlers"].as_array().unwrap().len() as u64;
        let samples = workspace["sample_count"].as_u64().unwrap();
        let coverage = &workspace["coverage"];
        if coverage["handler_count"] != handlers
            || samples < workspace["samples"].as_array().unwrap().len() as u64
            || coverage["retained_snapshot_bytes"].as_u64().unwrap()
                != coverage["characterized_bytes"].as_u64().unwrap()
                    + coverage["uncharacterized_bytes"].as_u64().unwrap()
        {
            return Err(Error::bad("Inconsistent VM workspace counts"));
        }
        for (total, count) in totals[1..].iter_mut().zip([
            handlers,
            workspace["snapshots"].as_array().unwrap().len() as u64,
            samples,
            workspace["unknowns"].as_array().unwrap().len() as u64,
        ]) {
            *total = total
                .checked_add(count)
                .ok_or_else(|| Error::bad("VM summary count overflow"))?;
        }
    }
    for (key, total) in [
        "workspace_count",
        "handler_count",
        "snapshot_count",
        "sample_count",
        "unknown_count",
    ]
    .iter()
    .zip(totals)
    {
        if document["summary"][key] != total {
            return Err(Error::bad("Inconsistent VM document summary"));
        }
    }
    Ok(())
}

// Schema-valid rows can still contain incompatible coordinate/flow claims.
// Preserve them as unknown rather than letting malformed declarations match.
fn consistent_effect(effect: &Value) -> bool {
    let Some(size) = effect["instruction_size"].as_u64() else {
        return false;
    };
    let mut names = BTreeMap::new();
    let mut occupied = BTreeSet::new();
    for operand in effect["operand_layout"].as_array().unwrap() {
        let Some((start, width)) = operand["byte_offset"]
            .as_u64()
            .zip(operand["byte_size"].as_u64())
        else {
            return false;
        };
        if start + width > size
            || names
                .insert(
                    operand["name"].as_str().unwrap(),
                    operand["kind"].as_str().unwrap(),
                )
                .is_some()
            || (start..start + width).any(|byte| !occupied.insert(byte))
        {
            return false;
        }
    }
    let expected = match effect["operation"].as_str().unwrap() {
        "constant" | "add" | "add_modulo_2_64" | "load" | "store" => "next",
        "branch_zero" | "branch_nonzero" => "branch",
        "jump" => "jump",
        "call" => "call",
        "return" => "return",
        "halt" => "halt",
        _ => return false,
    };
    let flow = &effect["flow"];
    if flow["kind"] != expected {
        return false;
    }
    let target = flow["target_operand"].as_str();
    let offset = flow["target_offset"].as_u64();
    if matches!(expected, "branch" | "jump" | "call") {
        if target.is_some() == offset.is_some()
            || target.is_some_and(|name| names.get(name) != Some(&"target"))
        {
            return false;
        }
    } else if target.is_some() || offset.is_some() {
        return false;
    }
    for cell in effect["reads"]
        .as_array()
        .unwrap()
        .iter()
        .chain(effect["writes"].as_array().unwrap())
    {
        if ["index", "value"].iter().any(|field| {
            cell[field]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().is_err())
        }) {
            return false;
        }
        if let Some(operand) = cell["operand"].as_str()
            && (!cell["index"].is_null() || !names.contains_key(operand))
        {
            return false;
        }
    }
    for field in ["atomic_group", "superoperator"] {
        let span = &effect[field];
        if !span.is_null()
            && span["byte_offset"].as_u64().unwrap() + span["byte_size"].as_u64().unwrap() > 65536
        {
            return false;
        }
    }
    true
}

fn meaning(effect: &Value) -> Value {
    let mut value = effect.clone();
    let fields = value.as_object_mut().unwrap();
    fields.remove("effect_id");
    fields.remove("evidence_class");
    value
}

fn uncertainty(handler: &Value) -> Option<&'static str> {
    let effects = handler["effects"].as_array().expect("handler effects");
    if effects
        .iter()
        .any(|effect| effect["evidence_class"] == "contradicted")
    {
        return Some("contradicted");
    }
    let mut ids = BTreeSet::new();
    if handler["opcode"].is_null()
        || handler["state"] == "unknown"
        || effects.is_empty()
        || effects.iter().any(|effect| {
            effect["evidence_class"] == "unknown"
                || !ids.insert(effect["effect_id"].as_str().unwrap())
                || !consistent_effect(effect)
        })
    {
        return Some("unknown");
    }
    let first = meaning(&effects[0]);
    effects
        .iter()
        .skip(1)
        .any(|effect| meaning(effect) != first)
        .then_some("ambiguous")
}

fn effect_shape(handler: &Value) -> Result<Option<String>> {
    if uncertainty(handler).is_some() {
        return Ok(None);
    }
    // Equivalent declarations with different evidence IDs share one meaning.
    Ok(Some(vm::digest(&meaning(&handler["effects"][0]))?))
}

pub fn compare(
    pack: &Value,
    left: &Value,
    left_artifact: &str,
    right: &Value,
    right_artifact: &str,
) -> Result<Value> {
    validate_pack(pack)?;
    let left_workspace = workspace(left, left_artifact)?;
    let right_workspace = workspace(right, right_artifact)?;
    let family = family(pack, &left_workspace["source_artifact_sha256"])?;
    if family != self::family(pack, &right_workspace["source_artifact_sha256"])? {
        return Err(Error::bad(
            "Selected workspaces have different declared program families",
        ));
    }
    let left_rows = left_workspace["handlers"].as_array().unwrap();
    let right_rows = right_workspace["handlers"].as_array().unwrap();
    let mut shapes = BTreeMap::<String, (Vec<usize>, Vec<usize>)>::new();
    for (side, rows) in [left_rows, right_rows].iter().enumerate() {
        for (index, handler) in rows.iter().enumerate() {
            if let Some(shape) = effect_shape(handler)? {
                let entry = shapes.entry(shape).or_default();
                if side == 0 {
                    entry.0.push(index);
                } else {
                    entry.1.push(index);
                }
            }
        }
    }
    let mut used_left = BTreeSet::new();
    let mut used_right = BTreeSet::new();
    let mut rows = Vec::new();
    for (shape, (left_indices, right_indices)) in shapes {
        if left_indices.len() == 1 && right_indices.len() == 1 {
            let (a, b) = (left_indices[0], right_indices[0]);
            used_left.insert(a);
            used_right.insert(b);
            rows.push(json!({"status":if left_rows[a]["opcode"]==right_rows[b]["opcode"] {"unchanged"} else {"moved"},"match_basis":"unique-exact-effect-shape","effect_shape_digest":shape,"left":left_rows[a],"right":right_rows[b]}));
        } else if left_indices.len() > 1 || right_indices.len() > 1 {
            // Ambiguity is retained in full. Never choose a best-looking row.
            for (side, indices, source, used) in [
                ("left", left_indices, left_rows, &mut used_left),
                ("right", right_indices, right_rows, &mut used_right),
            ] {
                for index in indices {
                    used.insert(index);
                    let mut row = json!({"status":"ambiguous","match_basis":"non-unique-effect-shape","effect_shape_digest":shape,"left":null,"right":null});
                    row[side] = source[index].clone();
                    rows.push(row);
                }
            }
        }
    }
    for (a, handler) in left_rows.iter().enumerate() {
        if used_left.contains(&a) {
            continue;
        }
        let known = uncertainty(handler).is_none();
        let other = known
            .then(|| {
                right_rows.iter().enumerate().find(|(index, row)| {
                    !used_right.contains(index)
                        && uncertainty(row).is_none()
                        && row["opcode"] == handler["opcode"]
                })
            })
            .flatten();
        if let Some((b, other)) = other {
            used_left.insert(a);
            used_right.insert(b);
            rows.push(json!({"status":"changed","match_basis":"same-opcode-different-effects","effect_shape_digest":null,"left":handler,"right":other}));
        }
    }
    for (side, source, used) in [
        ("left", left_rows, &used_left),
        ("right", right_rows, &used_right),
    ] {
        for (_, handler) in source
            .iter()
            .enumerate()
            .filter(|(index, _)| !used.contains(index))
        {
            let mut row = json!({"status":uncertainty(handler).unwrap_or(if side=="left" {"left-only"} else {"right-only"}),"match_basis":"unmatched","effect_shape_digest":null,"left":null,"right":null});
            row[side] = handler.clone();
            rows.push(row);
        }
    }
    rows.sort_by_key(|row| {
        (
            row["left"]["opcode"]
                .as_u64()
                .or_else(|| row["right"]["opcode"].as_u64()),
            row["status"].as_str().unwrap_or("").to_owned(),
        )
    });
    finish(
        json!({"contract_version":1,"document_kind":"vm-instruction-set-comparison","program_family":family,"pack_digest":vm::digest(pack)?,"family_binding":"pack-declaration-not-authentication","left":identity(left,left_workspace),"right":identity(right,right_workspace),"rows":rows,"residual_unknowns":{"left":left_workspace["unknowns"],"right":right_workspace["unknowns"]},"coverage":{"left":left_workspace["coverage"],"right":right_workspace["coverage"]},"omissions":[],"behavioral_equivalence_proven":false,"limitations":["Exact effect shape is a comparison hypothesis, not proven semantic equivalence.","Source digest and family bindings are declarations; absent original artifact bytes are not reverified."]}),
    )
}

pub fn write_report(path: &Path, report: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(Error::bad(
            "VM report exceeds 32 MiB; no output was written",
        ));
    }
    durable::write_private_noclobber(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fixture(name: &str) -> Value {
        read(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../tools/fixtures/vm-analysis-packs/{name}")),
        )
        .unwrap()
    }
    fn seal(document: &mut Value) {
        document.as_object_mut().unwrap().remove("document_digest");
        document["document_digest"] = json!(vm::digest(document).unwrap());
    }
    fn compare_fixture(left: &Value, right: &Value) -> Value {
        compare(&fixture("pack.json"), left, "1", right, "1").unwrap()
    }
    fn analysis(source: &str) -> Value {
        let root = tempfile::tempdir().unwrap();
        let hash = hex::encode(Sha256::digest(source.as_bytes()));
        std::fs::create_dir(root.path().join("blobs")).unwrap();
        std::fs::write(root.path().join(format!("blobs/{hash}.bin")), source).unwrap();
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://owned.test/fixture.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(root.path().join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
        let events = root.path().join("events.jsonl");
        std::fs::write(&events, "").unwrap();
        vm::store(root.path(), &events).unwrap()
    }

    #[test]
    fn vm_pack_default_weights_reproduce_generic_scores_without_erasing_evidence() {
        let pack: Value =
            serde_json::from_str(include_str!("../assets/anti-bot-pack-v1.json")).unwrap();
        let definitions = vm::current_rule_definitions();
        let relevance = definitions
            .iter()
            .filter(|rule| rule["family"] == "relevance")
            .collect::<Vec<_>>();
        assert_eq!(relevance.len(), pack["rules"].as_array().unwrap().len());
        for rule in &relevance {
            assert!(
                pack["rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["rule_id"] == rule["rule_id"]
                        && entry["weight"] == rule["weight"])
            );
        }
        for (source, expected) in [
            ("const answer = 42;", 0),
            ("navigator; canvas;", 50),
            ("navigator; canvas; webdriver; crypto; fetch;", 100),
        ] {
            let generic = analysis(source);
            let report = apply(&pack, &generic).unwrap();
            assert_eq!(report["generic_analysis"], generic);
            assert_eq!(report["rankings"][0]["anti_bot_score"], expected);
            assert_eq!(report["rankings"][0]["generic_anti_bot_score"], expected);
            assert_eq!(report["rankings"][0]["generic_weight_fallbacks"], json!([]));
            assert_eq!(report["omissions"], json!([]));
        }
        // The same additive/capped rule applies to retained runtime evidence too.
        let mut generic = analysis("canvas;");
        let prototype = generic["results"][0]["anti_bot_observations"][0].clone();
        generic["results"][0]["anti_bot_observations"] = json!(
            relevance
                .iter()
                .map(|rule| {
                    let mut observation = prototype.clone();
                    observation["rule_id"] = rule["rule_id"].clone();
                    observation["weight"] = rule["weight"].clone();
                    observation
                })
                .collect::<Vec<_>>()
        );
        generic["results"][0]["anti_bot_score"] = json!(100);
        seal(&mut generic);
        assert_eq!(
            apply(&pack, &generic).unwrap()["rankings"][0]["anti_bot_score"],
            100
        );
        let mut overlay = pack.clone();
        overlay["rules"] = json!([{"rule_id":"antibot.canvas-webgl","weight":3,"label":"관찰"}]);
        let base = analysis("navigator; canvas;");
        let report = apply(&overlay, &base).unwrap();
        assert_eq!(report["rankings"][0]["anti_bot_score"], 28);
        assert_eq!(
            report["rankings"][0]["generic_weight_fallbacks"],
            json!(["antibot.navigator-device"])
        );
        assert_eq!(report["generic_analysis"], base);
        assert_eq!(report["pack_digest"], vm::digest(&overlay).unwrap());
    }

    #[test]
    fn vm_pack_comparison_reports_moved_unchanged_changed_and_retains_unknowns() {
        let left = fixture("build-a.workspace.json");
        let mut right = fixture("build-b.workspace.json");
        right["workspaces"][0]["handlers"][0]["effects"][0]["effect_id"] =
            json!("different_local_id");
        right["workspaces"][0]["handlers"][0]["effects"][0]["evidence_class"] = json!("observed");
        seal(&mut right);
        let report = compare_fixture(&left, &right);
        let rows = report["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 7);
        for (status, opcode) in [("moved", 1), ("unchanged", 2), ("changed", 4)] {
            let row = rows.iter().find(|row| row["status"] == status).unwrap();
            assert_eq!(row["left"]["opcode"], opcode);
            assert_eq!(
                row["left"],
                left["workspaces"][0]["handlers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|h| h["opcode"] == opcode)
                    .unwrap()
                    .clone()
            );
        }
        assert_eq!(
            rows.iter().find(|row| row["status"] == "moved").unwrap()["right"]["opcode"],
            9
        );
        assert_eq!(
            rows.iter().filter(|row| row["status"] == "unknown").count(),
            2
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row["status"] == "contradicted")
                .count(),
            2
        );
        assert_eq!(
            report["residual_unknowns"]["left"],
            left["workspaces"][0]["unknowns"]
        );
        assert_eq!(
            report["coverage"]["right"],
            right["workspaces"][0]["coverage"]
        );
        assert_eq!(report["left"]["workspace_digest"], left["document_digest"]);
        assert_eq!(
            report["left"]["source_artifact_sha256"],
            left["workspaces"][0]["source_artifact_sha256"]
        );
        assert_eq!(report["behavioral_equivalence_proven"], false);
        assert_eq!(
            report["family_binding"],
            "pack-declaration-not-authentication"
        );
        let mut unsigned = report.clone();
        unsigned.as_object_mut().unwrap().remove("document_digest");
        assert_eq!(report["document_digest"], vm::digest(&unsigned).unwrap());
    }

    #[test]
    fn vm_pack_repeated_shapes_and_incomplete_effects_remain_unmatched() {
        let mut left = fixture("build-a.workspace.json");
        let right = fixture("build-b.workspace.json");
        let mut repeated = left["workspaces"][0]["handlers"][0].clone();
        repeated["opcode"] = json!(10);
        left["workspaces"][0]["handlers"]
            .as_array_mut()
            .unwrap()
            .push(repeated);
        left["workspaces"][0]["coverage"]["handler_count"] = json!(6);
        left["summary"]["handler_count"] = json!(6);
        seal(&mut left);
        let report = compare_fixture(&left, &right);
        assert_eq!(
            report["rows"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["status"] == "ambiguous")
                .count(),
            3
        );
        assert!(
            !report["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["status"] == "moved")
        );
        for incomplete in [json!(null), json!(1)] {
            let mut left = fixture("build-a.workspace.json");
            left["workspaces"][0]["handlers"][0]["effects"][0]["instruction_size"] = incomplete;
            left["workspaces"][0]["handlers"][0]["effects"][0]["operand_layout"] =
                json!([{"name":"value","kind":"immediate","byte_offset":null,"byte_size":null}]);
            seal(&mut left);
            assert!(
                compare_fixture(&left, &right)["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["status"] == "unknown" && row["left"]["opcode"] == 1)
            );
        }
    }

    #[test]
    fn vm_pack_refuses_tampered_identity_missing_families_and_wrong_versions() {
        let pack = fixture("pack.json");
        let left = fixture("build-a.workspace.json");
        let right = fixture("build-b.workspace.json");
        let mut tampered = right.clone();
        tampered["workspaces"][0]["handlers"][0]["opcode"] = json!(10);
        assert!(compare(&pack, &left, "1", &tampered, "1").is_err());
        tampered["workspaces"][0]["source_artifact_sha256"] = json!("0".repeat(64));
        seal(&mut tampered);
        assert!(compare(&pack, &left, "1", &tampered, "1").is_err());
        assert!(compare(&pack, &left, "wrong", &right, "1").is_err());
        let mut wrong_family = pack.clone();
        wrong_family["families"][1]["program_family"] = json!("other-family");
        assert!(compare(&wrong_family, &left, "1", &right, "1").is_err());
        let mut old = left.clone();
        old["contract_version"] = json!(1);
        seal(&mut old);
        assert!(compare(&pack, &old, "1", &right, "1").is_err());
        let mut duplicate = left.clone();
        duplicate["workspaces"][0]["handlers"][1]["opcode"] = json!(1);
        seal(&mut duplicate);
        assert!(compare(&pack, &duplicate, "1", &right, "1").is_err());
        let mut generic = analysis("canvas;");
        generic["results"][0]["anti_bot_score"] = json!(99);
        assert!(apply(&pack, &generic).is_err());
    }

    #[test]
    fn vm_pack_is_strict_bounded_data_and_unicode_digest_matches_canonical_form() {
        let pack = fixture("pack.json");
        for (key, value) in [
            ("code", json!("eval('source')")),
            ("url", json!("https://example.test/decoder")),
            ("contract_version", json!(2)),
        ] {
            let mut invalid = pack.clone();
            invalid[key] = value;
            assert!(validate_pack(&invalid).is_err());
        }
        for rule in [
            json!({"rule_id":"antibot.unknown","weight":1,"label":"unknown"}),
            json!({"rule_id":"antibot.canvas-webgl","weight":1,"label":"eval(source)"}),
            json!({"rule_id":"antibot.canvas-webgl","weight":1,"label":"Canvas","function":"decode"}),
        ] {
            let mut invalid = pack.clone();
            invalid["rules"] = json!([rule]);
            assert!(validate_pack(&invalid).is_err());
        }
        let mut float = pack.clone();
        float["rules"] = json!([{"rule_id":"antibot.canvas-webgl","weight":1.0,"label":"Canvas"}]);
        assert!(validate_pack(&float).is_err());
        let mut duplicate_rule = pack.clone();
        let rule = json!({"rule_id":"antibot.canvas-webgl","weight":1,"label":"Canvas"});
        duplicate_rule["rules"] = json!([rule, rule]);
        assert!(validate_pack(&duplicate_rule).is_err());
        let mut duplicate = pack.clone();
        duplicate["families"]
            .as_array_mut()
            .unwrap()
            .push(pack["families"][0].clone());
        assert!(validate_pack(&duplicate).is_err());
        for bytes in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"x":{"a":1,"\u0061":2}}"#,
            br#"{"x":1.0}"#,
            br#"{"x":1e2}"#,
            br#"{}{}"#,
        ] {
            assert!(parse(bytes).is_err());
        }
        assert!(
            parse(format!("{{\"x\":{}0{}}}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err()
        );
        assert!(parse(&vec![b' '; MAX_INPUT_BYTES + 1]).is_err());
        assert!(parse(format!("{{\"x\":\"{}\"}}", "x".repeat(8193)).as_bytes()).is_err());
        let mut left = fixture("build-a.workspace.json");
        left["workspaces"][0]["handlers"][0]["label"] = json!("연구 🧪");
        seal(&mut left);
        let serialized = serde_json::to_vec(&left).unwrap();
        let reparsed = parse(&serialized).unwrap();
        assert_eq!(reparsed, left);
        assert!(
            String::from_utf8(vm::canonical(&left).unwrap())
                .unwrap()
                .contains("\\uc5f0\\uad6c \\ud83e\\uddea")
        );
        compare_fixture(&reparsed, &fixture("build-b.workspace.json"));
    }
    #[test]
    fn vm_pack_conflicting_meanings_and_relationally_invalid_effects_never_match() {
        let original =
            fixture("build-a.workspace.json")["workspaces"][0]["handlers"][0]["effects"][0].clone();
        let mut invalid = Vec::new();
        let mut effect = original.clone();
        effect["operand_layout"] =
            json!([{"name":"a","kind":"immediate","byte_offset":1,"byte_size":1}]);
        invalid.push(effect); // Operand extends past a one-byte instruction.
        for name in ["a", "b"] {
            let mut effect = original.clone();
            effect["instruction_size"] = json!(3);
            effect["operand_layout"] = json!([
                {"name":"a","kind":"immediate","byte_offset":1,"byte_size":1},
                {"name":name,"kind":"immediate","byte_offset":if name=="a" {2} else {1},"byte_size":1}
            ]);
            invalid.push(effect); // Duplicate name or overlapping range.
        }
        let mut effect = original.clone();
        effect["flow"]["kind"] = json!("halt");
        invalid.push(effect); // Constant operation cannot declare halt flow.
        let mut effect = original.clone();
        effect["operation"] = json!("jump");
        effect["flow"] = json!({"kind":"jump","target_operand":"missing","target_offset":null});
        invalid.push(effect);
        let mut effect = original.clone();
        effect["writes"][0]["operand"] = json!("missing");
        invalid.push(effect);
        for field in ["index", "value"] {
            let mut effect = original.clone();
            effect["writes"][0][field] = json!("18446744073709551616");
            invalid.push(effect);
            let mut boundary = original.clone();
            boundary["writes"][0][field] = json!("18446744073709551615");
            assert!(consistent_effect(&boundary));
        }
        for field in ["atomic_group", "superoperator"] {
            let mut effect = original.clone();
            effect[field] = json!({"byte_offset":65535,"byte_size":2});
            invalid.push(effect);
            let mut boundary = original.clone();
            boundary[field] = json!({"byte_offset":65535,"byte_size":1});
            assert!(consistent_effect(&boundary));
        }
        for effect in invalid {
            let mut left = fixture("build-a.workspace.json");
            let mut right = fixture("build-b.workspace.json");
            for document in [&mut left, &mut right] {
                document["workspaces"][0]["handlers"][0]["effects"] = json!([effect]);
                seal(document);
            }
            let report = compare_fixture(&left, &right);
            assert!(
                report["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["status"] == "unknown" && row["left"]["opcode"] == 1)
            );
            assert!(
                !report["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["status"] == "moved")
            );
        }
        for (kind, expected) in [
            ("duplicate-id", "unknown"),
            ("conflict", "ambiguous"),
            ("equivalent", "moved"),
        ] {
            let mut second = original.clone();
            if kind != "duplicate-id" {
                second["effect_id"] = json!("other-evidence");
            }
            if kind == "conflict" {
                second["writes"][0]["value"] = json!("99");
            }
            let mut left = fixture("build-a.workspace.json");
            let mut right = fixture("build-b.workspace.json");
            for document in [&mut left, &mut right] {
                document["workspaces"][0]["handlers"][0]["effects"] = json!([original, second]);
                seal(document);
            }
            let report = compare_fixture(&left, &right);
            let row = report["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["left"]["opcode"] == 1)
                .unwrap();
            assert_eq!(row["status"], expected);
            assert_eq!(row["left"], left["workspaces"][0]["handlers"][0]);
        }
    }

    #[test]
    fn vm_pack_fixture_sources_and_summary_counts_are_checked() {
        let left = fixture("build-a.workspace.json");
        let right = fixture("build-b.workspace.json");
        for (document, source) in [
            (
                &left,
                include_str!("../../../tools/fixtures/vm-analysis-packs/build-a.js"),
            ),
            (
                &right,
                include_str!("../../../tools/fixtures/vm-analysis-packs/build-b.js"),
            ),
        ] {
            assert_eq!(
                document["workspaces"][0]["source_artifact_sha256"],
                hex::encode(Sha256::digest(source.as_bytes()))
            );
        }
        for field in [
            "workspace_count",
            "handler_count",
            "snapshot_count",
            "sample_count",
            "unknown_count",
        ] {
            let mut bad = left.clone();
            bad["summary"][field] = json!(999);
            seal(&mut bad);
            assert!(compare(&fixture("pack.json"), &bad, "1", &right, "1").is_err());
        }
        let report = compare_fixture(&left, &right);
        for (side, document) in [("left", left), ("right", right)] {
            for original in document["workspaces"][0]["handlers"].as_array().unwrap() {
                assert_eq!(
                    report["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|row| &row[side] == original)
                        .count(),
                    1
                );
            }
        }
    }
}
