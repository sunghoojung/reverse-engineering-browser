//! Exact-source-bound declarations for repository-owned fixtures only.
//! Changed state cells are deliberately not used to infer reads or causes.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(test)]
const STACK_SOURCE: &str = include_str!("../../../tools/fixtures/vm-workspace-effects/stack.js");
#[cfg(test)]
const REGISTER_SOURCE: &str =
    include_str!("../../../tools/fixtures/vm-workspace-effects/register.js");
const STACK_EFFECTS: &str = include_str!("../../../tools/fixtures/vm-workspace-effects/stack.json");
const REGISTER_EFFECTS: &str =
    include_str!("../../../tools/fixtures/vm-workspace-effects/register.json");

pub(crate) fn owned_declaration(source: &str) -> Option<Value> {
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    for text in [
        STACK_EFFECTS,
        REGISTER_EFFECTS,
        include_str!("../../../tools/fixtures/vm-workspace-effects/native-stack.json"),
        include_str!("../../../tools/fixtures/vm-workspace-effects/native-register.json"),
    ] {
        let declaration: Value = serde_json::from_str(text).ok()?;
        if declaration["source_sha256"] == digest {
            return Some(declaration);
        }
    }
    None
}

/// Different IDs retain incompatible assertions side by side. Never promote an
/// inferred meaning because the opcode occurred in a dispatch sample.
pub(crate) fn append_effect(handler: &mut Value, effect: &Value) -> bool {
    if !handler["effects"].is_array() {
        handler["effects"] = json!([]);
    }
    let effects = handler["effects"].as_array_mut().expect("effect rows");
    if let Some(previous) = effects
        .iter()
        .find(|row| row["effect_id"] == effect["effect_id"])
    {
        return previous == effect;
    }
    if effects.len() >= 8 {
        return false;
    }
    effects.push(effect.clone());
    true
}

pub(crate) fn attach_owned(source: &str, handlers: &mut [Value]) -> Option<Value> {
    let declaration = owned_declaration(source)?;
    for handler in handlers {
        if let Some(owned) = declaration["handlers"]
            .as_array()?
            .iter()
            .find(|owned| owned["opcode"] == handler["opcode"])
        {
            for effect in owned["effects"].as_array()? {
                append_effect(handler, effect);
            }
        }
    }
    Some(declaration)
}

/// Only one consistent known declaration can guide byte attribution or flow.
/// Preserved contradictory rows remain visible, but never select a winner.
pub(crate) fn unique_effect(handler: &Value) -> Option<&Value> {
    let effects = handler["effects"].as_array()?;
    let mut known = effects.iter().filter(|effect| {
        matches!(
            effect["evidence_class"].as_str(),
            Some("inferred" | "observed")
        ) && effect["operation"] != "unknown"
    });
    let first = known.next()?;
    if effects
        .iter()
        .any(|effect| effect["evidence_class"] == "contradicted")
    {
        return None;
    }
    let meaning = |effect: &Value| {
        let mut value = effect.clone();
        let object = value.as_object_mut().expect("declarative effect");
        object.remove("effect_id");
        object.remove("evidence_class");
        value
    };
    let first_meaning = meaning(first);
    known
        .all(|effect| meaning(effect) == first_meaning)
        .then_some(first)
}

/// Fixed layout attribution is separate from reachability: every byte is
/// interpreted only under this owned fixture's declared all-code encoding.
/// Stop at an unknown opcode/layout; never resynchronize inside operand bytes.
pub(crate) fn attributed_prefix(snapshots: &[Value], handlers: &[Value]) -> Vec<Value> {
    let mut ranges = Vec::new();
    'snapshots: for snapshot in snapshots.iter().take(16) {
        let Some(bytes) = snapshot["preview_hex"]
            .as_str()
            .and_then(|text| hex::decode(text).ok())
        else {
            continue;
        };
        let bytes = &bytes[..bytes.len().min(4096)];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let opcode = u64::from(bytes[offset]);
            let Some(effect) = handlers
                .iter()
                .find(|handler| handler["opcode"].as_u64() == Some(opcode))
                .and_then(unique_effect)
            else {
                break;
            };
            let Some(size) = effect["instruction_size"]
                .as_u64()
                .filter(|size| (1..=65).contains(size))
            else {
                break;
            };
            let end = offset + size as usize;
            if end > bytes.len() {
                break;
            }
            let evidence = effect["evidence_class"].clone();
            ranges.push(
                json!({"artifact_id": snapshot["artifact_id"], "byte_offset": offset,
                "byte_size": 1, "opcode": opcode, "kind": "opcode", "evidence_class": evidence}),
            );
            for operand in effect["operand_layout"].as_array().into_iter().flatten() {
                if let Some((position, width)) = operand["byte_offset"]
                    .as_u64()
                    .zip(operand["byte_size"].as_u64())
                    && position > 0
                    && width > 0
                    && position.checked_add(width).is_some_and(|end| end <= size)
                {
                    ranges.push(json!({"artifact_id": snapshot["artifact_id"], "byte_offset": offset + position as usize,
                        "byte_size": width, "opcode": opcode, "kind": "operand", "evidence_class": evidence}));
                }
            }
            if ranges.len() > crate::vm_byte_coverage::MAX_ATTRIBUTIONS {
                ranges.truncate(crate::vm_byte_coverage::MAX_ATTRIBUTIONS + 1);
                break 'snapshots;
            }
            offset = end;
        }
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn exact_owned_sources_declare_all_manifest_operations_without_values() {
        let manifest: Value =
            serde_json::from_str(include_str!("../../../protocol/owned-vm-programs-v1.json"))
                .unwrap();
        for (source, program) in [STACK_SOURCE, REGISTER_SOURCE].into_iter().zip([1usize, 0]) {
            let declaration = owned_declaration(source).expect("owned declaration");
            let expected = manifest["programs"][program]["instructions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["declared_operation"].as_str().unwrap())
                .collect::<BTreeSet<_>>();
            let actual = declaration["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["effects"][0]["operation"].as_str().unwrap())
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected);
            for row in declaration["handlers"].as_array().unwrap() {
                let effect = &row["effects"][0];
                assert_eq!(effect["evidence_class"], "inferred");
                assert!(
                    effect["reads"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .chain(effect["writes"].as_array().unwrap())
                        .all(|cell| cell["value"].is_null())
                );
                assert!(effect["atomic_group"].is_null());
                assert!(effect["superoperator"].is_null());
            }
            assert!(owned_declaration(&format!("{source}\n")).is_none());
        }
    }

    #[test]
    fn incompatible_inferred_effects_are_retained_and_neither_wins() {
        let declaration = owned_declaration(STACK_SOURCE).unwrap();
        let original = &declaration["handlers"][0]["effects"][0];
        let mut handler = json!({"opcode": 1, "effects": []});
        assert!(append_effect(&mut handler, original));
        assert!(unique_effect(&handler).is_some());
        let mut alternate = original.clone();
        alternate["effect_id"] = json!("alternate-constant");
        alternate["writes"][0]["index"] = json!("3");
        assert!(append_effect(&mut handler, &alternate));
        assert_eq!(handler["effects"].as_array().unwrap().len(), 2);
        assert_eq!(handler["effects"][0]["evidence_class"], "inferred");
        assert_eq!(handler["effects"][1]["evidence_class"], "inferred");
        assert!(unique_effect(&handler).is_none());
    }

    #[test]
    fn byte_attribution_stops_before_unknown_and_truncated_instructions() {
        let declaration = owned_declaration(STACK_SOURCE).unwrap();
        let handlers = declaration["handlers"].as_array().unwrap();
        let ranges = attributed_prefix(
            &[json!({"artifact_id":"1","preview_hex":"010702ff08"})],
            handlers,
        );
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges.last().unwrap()["byte_offset"], 2);
        assert!(
            attributed_prefix(&[json!({"artifact_id":"1","preview_hex":"01"})], handlers)
                .is_empty()
        );
    }
}
