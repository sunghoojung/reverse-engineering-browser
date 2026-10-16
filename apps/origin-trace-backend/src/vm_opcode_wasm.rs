//! Bounded, inert dispatch-arm inspection of the detector's selected WASM body.
use super::MAX_HANDLERS;
use serde_json::{Value, json};
use wasmparser::{Operator, Parser, Payload};

pub(super) fn handlers(
    bytes: &[u8],
    result: &Value,
) -> Option<(Vec<Value>, Vec<String>, Vec<Value>)> {
    let coordinate = result["observations"]
        .as_array()?
        .iter()
        .find_map(|observation| {
            (observation["rule_id"] == "wasm.dispatch-loop").then_some(&observation["coordinate"])
        })?;
    let body_offset = coordinate["function_body_offset"].as_u64()? as usize;
    let body_size = coordinate["function_body_size"].as_u64()? as usize;
    let mut handlers = Vec::new();
    let mut omissions = Vec::new();
    let unknowns = vec![
        "WASM dispatch selectors are candidates, not proven guest opcode values or handler bodies."
            .into(),
        "The guest stack/register model, operand widths and state effects remain unknown.".into(),
    ];
    // The detector has already checked the complete bounded module. Inspect only
    // its selected function, never unrelated functions or executable instances.
    for payload in Parser::new(0).parse_all(bytes) {
        let Payload::CodeSectionEntry(body) = payload.ok()? else {
            continue;
        };
        if body.range().start != body_offset || body.range().len() != body_size {
            continue;
        }
        let mut reader = body.get_operators_reader().ok()?;
        let mut control = Vec::new();
        let mut loop_depth = 0usize;
        let mut limit_hit = false;
        while !reader.eof() {
            let start = reader.original_position();
            let op = reader.read().ok()?;
            let size = reader.original_position() - start;
            let mut push = |opcode: Option<u32>, label: String, notes: String| {
                if handlers.len() == MAX_HANDLERS {
                    limit_hit = true;
                    return;
                }
                handlers.push(json!({
                    "opcode": opcode,
                    "state": if opcode.is_some() { "inferred" } else { "unknown" },
                    "source": {"byte_offset": start, "byte_size": size},
                    "label": label,
                    "operand_width": 0,
                    "sample_count": 0,
                    "notes": notes,
                    "effects": [],
                }));
            };
            match op {
                Operator::BrTable { targets } if loop_depth > 0 => {
                    for (index, target) in targets.targets().enumerate() {
                        let target = target.ok()?;
                        push(
                            Some(index as u32),
                            format!("br_table selector {index}"),
                            format!(
                                "Static selector {index} branches to label depth {target}. The source range cites the dispatch instruction; guest opcode binding is unproven."
                            ),
                        );
                        if index >= MAX_HANDLERS {
                            break;
                        }
                    }
                    push(
                        None,
                        "br_table default".into(),
                        format!(
                            "Default dispatch arm to label depth {} has no single static selector or guest opcode binding.",
                            targets.default()
                        ),
                    );
                }
                Operator::CallIndirect { table_index, .. } if loop_depth > 0 => {
                    push(
                        None,
                        "call_indirect target".into(),
                        format!(
                            "The selected entry in function table {table_index} is dynamic. No static handler index or guest opcode binding is inferred."
                        ),
                    );
                }
                Operator::Loop { .. } => {
                    control.push(true);
                    loop_depth += 1;
                }
                Operator::Block { .. } | Operator::If { .. } => control.push(false),
                Operator::End if control.pop() == Some(true) => loop_depth -= 1,
                _ => (),
            }
            if limit_hit {
                omissions.push(json!({"reason":"handler-limit","detail":"Only the first 1024 WASM dispatch-arm candidates are retained."}));
                break;
            }
        }
        return Some((handlers, unknowns, omissions));
    }
    None
}
