//! Bounded graph walking over declared owned byte layouts, never execution.
use crate::vm_effects;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_INSTRUCTIONS: usize = 4096;
const MAX_FRONTIER: usize = 256;

fn frontier(rows: &mut Vec<Value>, artifact: &Value, offset: Option<u32>, reason: &str) {
    let row = json!({"artifact_id": artifact, "byte_offset": offset, "reason": reason});
    if rows.contains(&row) {
        return;
    }
    if rows.len() < MAX_FRONTIER - 1 {
        rows.push(row);
    } else if !rows.iter().any(|row| row["reason"] == "frontier-limit") {
        rows.push(json!({"artifact_id": null, "byte_offset": null, "reason": "frontier-limit"}));
    }
}

fn target(effect: &Value, bytes: &[u8], offset: usize) -> Option<u32> {
    if let Some(target) = effect["flow"]["target_offset"].as_u64() {
        return target.try_into().ok();
    }
    let name = effect["flow"]["target_operand"].as_str()?;
    let operand = effect["operand_layout"]
        .as_array()?
        .iter()
        .find(|row| row["name"] == name)?;
    let start = offset.checked_add(operand["byte_offset"].as_u64()?.try_into().ok()?)?;
    let width: usize = operand["byte_size"].as_u64()?.try_into().ok()?;
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes.get(start..start.checked_add(width)?)?);
    u32::try_from(u64::from_le_bytes(value)).ok()
}

pub(crate) fn walk(snapshots: &[Value], handlers: &[Value], entry: Option<u32>) -> Value {
    let mut entries = Vec::new();
    let mut instructions = Vec::new();
    let mut edges = Vec::new();
    let mut stops = Vec::new();
    if snapshots.is_empty() {
        frontier(&mut stops, &Value::Null, None, "snapshot-unavailable");
    }
    if snapshots.len() > 16 {
        frontier(
            &mut stops,
            &snapshots[16]["artifact_id"],
            None,
            "snapshot-gap",
        );
    }
    let mut seen_artifacts = BTreeSet::new();
    for snapshot in snapshots.iter().take(16) {
        let artifact = &snapshot["artifact_id"];
        if !seen_artifacts.insert(artifact.as_str()) {
            frontier(&mut stops, artifact, None, "snapshot-gap");
            continue;
        }
        let Some(entry) = entry else {
            frontier(&mut stops, artifact, None, "entry-unavailable");
            continue;
        };
        let Some(bytes) = snapshot["preview_hex"]
            .as_str()
            .and_then(|text| hex::decode(text).ok())
        else {
            frontier(&mut stops, artifact, Some(entry), "snapshot-unavailable");
            continue;
        };
        let oversized = bytes.len() > 4096;
        let bytes = &bytes[..bytes.len().min(4096)];
        if oversized
            || snapshot["truncated"] == true
            || snapshot["byte_count"]
                .as_u64()
                .is_some_and(|count| count > bytes.len() as u64)
        {
            frontier(
                &mut stops,
                artifact,
                Some(bytes.len() as u32),
                "snapshot-gap",
            );
        }
        entries.push(json!({"artifact_id": artifact, "byte_offset": entry}));
        let mut pending = BTreeSet::from([entry]);
        let mut visited = BTreeSet::new();
        let mut occupied = BTreeMap::new();
        while let Some(position) = pending.pop_first() {
            if !visited.insert(position) {
                continue;
            }
            if instructions.len() >= MAX_INSTRUCTIONS {
                frontier(&mut stops, artifact, Some(position), "instruction-limit");
                break;
            }
            let offset = position as usize;
            let Some(opcode) = bytes.get(offset).copied() else {
                let reason = if snapshot["byte_count"]
                    .as_u64()
                    .is_some_and(|count| u64::from(position) < count)
                {
                    "snapshot-gap"
                } else {
                    "past-snapshot"
                };
                frontier(&mut stops, artifact, Some(position), reason);
                continue;
            };
            if occupied.contains_key(&offset) {
                frontier(
                    &mut stops,
                    artifact,
                    Some(position),
                    "overlapping-instruction",
                );
                continue;
            }
            let Some(handler) = handlers
                .iter()
                .find(|handler| handler["opcode"].as_u64() == Some(u64::from(opcode)))
            else {
                frontier(&mut stops, artifact, Some(position), "unknown-opcode");
                continue;
            };
            let Some(effect) = vm_effects::unique_effect(handler) else {
                let reason = if handler["effects"].as_array().is_some_and(|effects| {
                    effects.len() > 1
                        || effects
                            .iter()
                            .any(|effect| effect["evidence_class"] == "contradicted")
                }) {
                    "effect-contradiction"
                } else {
                    "effect-unavailable"
                };
                frontier(&mut stops, artifact, Some(position), reason);
                continue;
            };
            let Some(size) = effect["instruction_size"]
                .as_u64()
                .filter(|size| (1..=65).contains(size))
            else {
                frontier(&mut stops, artifact, Some(position), "unsupported-layout");
                continue;
            };
            let end = offset + size as usize;
            if end > bytes.len() {
                frontier(
                    &mut stops,
                    artifact,
                    Some(position),
                    "truncated-instruction",
                );
                continue;
            }
            if (offset..end).any(|byte| occupied.contains_key(&byte)) {
                frontier(
                    &mut stops,
                    artifact,
                    Some(position),
                    "overlapping-instruction",
                );
                continue;
            }
            for byte in offset..end {
                occupied.insert(byte, position);
            }
            instructions.push(
                json!({"artifact_id": artifact, "byte_offset": position, "byte_size": size,
                "opcode": opcode, "effect_id": effect["effect_id"]}),
            );
            let next = Some(end as u32);
            let destinations = match effect["flow"]["kind"].as_str() {
                Some("next") => vec![("fallthrough", next)],
                Some("branch") => vec![
                    ("branch_taken", target(effect, bytes, offset)),
                    ("branch_not_taken", next),
                ],
                Some("jump") => vec![("jump", target(effect, bytes, offset))],
                Some("call") => vec![
                    ("call", target(effect, bytes, offset)),
                    ("call_continuation", next),
                ],
                Some("halt") => vec![],
                Some("return") => vec![("return", None)],
                _ => vec![("unknown", None)],
            };
            for (kind, destination) in destinations {
                edges.push(json!({"artifact_id": artifact, "from_offset": position, "to_offset": destination, "kind": kind}));
                if let Some(destination) = destination {
                    if !visited.contains(&destination) {
                        pending.insert(destination);
                    }
                } else {
                    frontier(&mut stops, artifact, Some(position), "unknown-target");
                }
            }
        }
    }
    json!({"entry_offsets": entries, "instructions": instructions, "edges": edges,
        "complete": !entries.is_empty() && stops.is_empty(), "frontier": stops})
}

pub(crate) fn attributions(traversal: &Value, handlers: &[Value]) -> Vec<Value> {
    let mut rows = Vec::new();
    for instruction in traversal["instructions"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_INSTRUCTIONS)
    {
        let effect = handlers
            .iter()
            .find(|handler| handler["opcode"] == instruction["opcode"])
            .and_then(vm_effects::unique_effect);
        let Some(effect) = effect else {
            continue;
        };
        let Some(offset) = instruction["byte_offset"]
            .as_u64()
            .filter(|offset| *offset < 4096)
        else {
            continue;
        };
        let Some(size) = instruction["byte_size"]
            .as_u64()
            .filter(|size| (1..=65).contains(size))
        else {
            continue;
        };
        if offset + size > 4096 {
            continue;
        }
        let mut append = |start, size, kind| {
            rows.push(json!({"artifact_id": instruction["artifact_id"],
            "byte_offset": start, "byte_size": size, "opcode": instruction["opcode"], "kind": kind,
            "evidence_class": effect["evidence_class"]}))
        };
        append(offset, 1, "opcode");
        for operand in effect["operand_layout"]
            .as_array()
            .into_iter()
            .flatten()
            .take(8)
        {
            if let Some((start, width)) = operand["byte_offset"]
                .as_u64()
                .zip(operand["byte_size"].as_u64())
                && start > 0
                && matches!(width, 1 | 2 | 4 | 8)
                && start.checked_add(width).is_some_and(|end| end <= size)
            {
                append(offset + start, width, "operand");
            }
        }
        if rows.len() > crate::vm_byte_coverage::MAX_ATTRIBUTIONS {
            rows.truncate(crate::vm_byte_coverage::MAX_ATTRIBUTIONS + 1);
            break;
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handlers(model: &str) -> Vec<Value> {
        let text = match model {
            "stack" => include_str!("../../../tools/fixtures/vm-workspace-effects/stack.json"),
            _ => include_str!("../../../tools/fixtures/vm-workspace-effects/register.json"),
        };
        serde_json::from_str::<Value>(text).unwrap()["handlers"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn snapshot(bytes: &[u8]) -> Value {
        json!({"artifact_id": "10", "preview_hex": hex::encode(bytes), "byte_count": bytes.len()})
    }

    #[test]
    fn both_declared_branch_edges_and_jump_targets_are_walked() {
        for (model, bytes, branch, other, halt) in [
            (
                "stack",
                vec![1, 7, 1, 5, 2, 3, 16, 4, 16, 5, 15, 7, 15, 6, 15, 8],
                9,
                11,
                15,
            ),
            (
                "register",
                vec![
                    1, 0, 7, 1, 1, 5, 2, 0, 0, 1, 3, 16, 0, 4, 2, 16, 5, 2, 24, 7, 2, 24, 6, 24, 8,
                ],
                16,
                19,
                24,
            ),
        ] {
            let handlers = handlers(model);
            let result = walk(&[snapshot(&bytes)], &handlers, Some(0));
            assert_eq!(result["complete"], true);
            let edges = result["edges"].as_array().unwrap();
            assert!(edges.iter().any(|edge| edge["from_offset"] == branch
                && edge["to_offset"] == halt
                && edge["kind"] == "branch_taken"));
            assert!(edges.iter().any(|edge| edge["from_offset"] == branch
                && edge["to_offset"] == other
                && edge["kind"] == "branch_not_taken"));
            let coverage = crate::vm_byte_coverage::coverage(
                &[snapshot(&bytes)],
                handlers.len(),
                &attributions(&result, &handlers),
                &[],
                vec![],
            );
            assert_eq!(coverage["complete"], true);
            assert_eq!(coverage["characterized_bytes"], bytes.len());
        }
    }

    #[test]
    fn cycles_are_visited_once_and_unknown_edges_stop() {
        let handlers = handlers("stack");
        let cycle = walk(&[snapshot(&[6, 0])], &handlers, Some(0));
        assert_eq!(cycle["instructions"].as_array().unwrap().len(), 1);
        assert_eq!(cycle["complete"], true);
        let unknown = walk(&[snapshot(&[1, 7, 255, 8])], &handlers, Some(0));
        assert_eq!(unknown["instructions"].as_array().unwrap().len(), 1);
        assert_eq!(unknown["frontier"][0]["reason"], "unknown-opcode");
        let mut unknown_target = handlers.clone();
        unknown_target[5]["effects"][0]["flow"]["target_operand"] = Value::Null;
        let result = walk(&[snapshot(&[6, 0, 8])], &unknown_target, Some(0));
        assert_eq!(result["instructions"].as_array().unwrap().len(), 1);
        assert_eq!(result["frontier"][0]["reason"], "unknown-target");
    }

    #[test]
    fn calls_returns_and_wide_little_endian_targets_are_explicit() {
        let mut handlers = handlers("stack");
        handlers[5]["effects"][0]["operation"] = json!("call");
        handlers[5]["effects"][0]["flow"]["kind"] = json!("call");
        let result = walk(&[snapshot(&[6, 3, 8, 8])], &handlers, Some(0));
        assert_eq!(result["complete"], true);
        assert_eq!(result["instructions"].as_array().unwrap().len(), 3);
        assert_eq!(result["edges"][0]["kind"], "call");
        assert_eq!(result["edges"][1]["kind"], "call_continuation");
        handlers[7]["effects"][0]["operation"] = json!("return");
        handlers[7]["effects"][0]["flow"]["kind"] = json!("return");
        assert_eq!(
            walk(&[snapshot(&[8])], &handlers, Some(0))["frontier"][0]["reason"],
            "unknown-target"
        );
        let effect = &mut handlers[5]["effects"][0];
        effect["flow"]["kind"] = json!("jump");
        effect["operation"] = json!("jump");
        for (width, value) in [(2, 513u64), (4, u64::from(u32::MAX)), (8, u64::MAX)] {
            effect["instruction_size"] = json!(width + 1);
            effect["operand_layout"][0]["byte_size"] = json!(width);
            let mut bytes = vec![6];
            bytes.extend_from_slice(&value.to_le_bytes()[..width]);
            let result = walk(
                &[snapshot(&bytes)],
                &[json!({"opcode":6,"effects":[effect.clone()]})],
                Some(0),
            );
            assert_eq!(result["complete"], false);
            if let Ok(value) = u32::try_from(value) {
                assert_eq!(result["edges"][0]["to_offset"], value);
                assert_eq!(result["frontier"][0]["reason"], "past-snapshot");
            } else {
                assert!(result["edges"][0]["to_offset"].is_null());
                assert_eq!(result["frontier"][0]["reason"], "unknown-target");
            }
        }
    }

    #[test]
    fn instruction_and_frontier_limits_remain_visible() {
        let handlers = handlers("stack");
        let result = walk(&[snapshot(&vec![2; 4096])], &handlers, Some(0));
        assert_eq!(result["instructions"].as_array().unwrap().len(), 4096);
        assert_eq!(result["complete"], false);
        assert_eq!(result["frontier"][0]["reason"], "instruction-limit");
        let mut stops = Vec::new();
        for offset in 0..300 {
            frontier(&mut stops, &json!("1"), Some(offset), "unknown-opcode");
        }
        assert_eq!(stops.len(), 256);
        assert_eq!(stops[255]["reason"], "frontier-limit");
        let duplicate = snapshot(&[8]);
        assert_eq!(
            walk(&[duplicate.clone(), duplicate], &handlers, Some(0))["complete"],
            false
        );
    }

    #[test]
    fn absent_truncated_gapped_and_overlapping_snapshots_keep_frontiers() {
        let handlers = handlers("stack");
        assert_eq!(
            walk(&[], &handlers, Some(0))["frontier"][0]["reason"],
            "snapshot-unavailable"
        );
        assert_eq!(
            walk(&[snapshot(&[1])], &handlers, Some(0))["frontier"][0]["reason"],
            "truncated-instruction"
        );
        let mut gap = snapshot(&[1, 7]);
        gap["byte_count"] = json!(4);
        let result = walk(&[gap], &handlers, Some(0));
        assert_eq!(result["complete"], false);
        assert_eq!(result["frontier"][0]["reason"], "snapshot-gap");
        let overlap = walk(&[snapshot(&[5, 1, 8])], &handlers, Some(0));
        assert_eq!(overlap["frontier"][0]["reason"], "overlapping-instruction");
    }
    #[test]
    fn snapshot_cap_and_unreachable_truncation_are_not_complete() {
        let handlers = handlers("stack");
        let many = (0..17)
            .map(|id| {
                let mut snapshot = snapshot(&[8]);
                snapshot["artifact_id"] = json!(id.to_string());
                snapshot
            })
            .collect::<Vec<_>>();
        assert_eq!(walk(&many, &handlers, Some(0))["complete"], false);
        let mut truncated = snapshot(&[8]);
        truncated["byte_count"] = json!(10);
        assert_eq!(walk(&[truncated], &handlers, Some(0))["complete"], false);
        let mut malformed = handlers.clone();
        malformed[0]["effects"][0]["operand_layout"][0]["byte_offset"] = json!(u64::MAX);
        let result = walk(&[snapshot(&[1, 7, 8])], &malformed, Some(0));
        assert!(
            attributions(&result, &malformed)
                .iter()
                .all(|row| row["byte_offset"].as_u64().unwrap() < 4096)
        );
    }
}
