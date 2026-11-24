//! Inert dispatch-arm inspection of a captured WASM module.
//!
//! The detector ranks one static candidate function. The workspace also keeps
//! every in-loop `br_table` and `call_indirect` site of that function's
//! neighborhood: direct calls within three hops, either direction, and
//! functions named by element segments of tables those functions use with
//! in-loop `call_indirect`. Three hops is what this workspace calls related,
//! so a module's unrelated jump tables stay out; inside it every site, arm,
//! call and table entry is kept. Nothing here instantiates the module or
//! invents a guest program counter.
use crate::vm::{
    dispatch_shape::{Memory, Meter},
    wasm_control::{self, BlockKind, Control},
    wasm_tables::{Placement, Tables},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use wasmparser::{BinaryReader, Operator, OperatorsReader, Parser, Payload, TypeRef};

/// The neighborhood's call distance from the selected function, in hops.
const MAX_CALL_DEPTH: u8 = 3;

pub(super) struct ModuleDispatch {
    pub sites: u32,
    pub functions: u32,
}

pub(super) struct ExtractedHandlers {
    pub handlers: Vec<Value>,
    pub unknowns: Vec<String>,
    pub omissions: Vec<Value>,
    pub dispatch: ModuleDispatch,
    pub handler_tables: Vec<Value>,
    /// The table layout the element handler tables were built from.
    pub tables: Tables,
}

struct Arm {
    opcode: Option<u32>,
    offset: usize,
    size: usize,
    kind: ArmKind,
    detail: u32,
}

enum ArmKind {
    Selector,
    Default,
    Indirect,
}

struct Site {
    offset: usize,
    size: usize,
}

struct FunctionDispatch {
    index: u32,
    start: usize,
    len: usize,
    /// Direct callees and the element targets of its in-loop tables.
    calls: BTreeSet<u32>,
    tables: BTreeSet<u32>,
    sites: Vec<Site>,
    decoded: bool,
}

#[cfg(test)]
pub(super) fn handlers(bytes: &[u8], result: &Value) -> Option<ExtractedHandlers> {
    handlers_under(bytes, result, &crate::vm::dispatch_shape::Meter::new())
}

pub(super) fn handlers_under(
    bytes: &[u8],
    result: &Value,
    meter: &crate::vm::dispatch_shape::Meter,
) -> Option<ExtractedHandlers> {
    let coordinate = result["observations"]
        .as_array()?
        .iter()
        .find_map(|observation| {
            (observation["rule_id"] == "wasm.dispatch-loop").then_some(&observation["coordinate"])
        })?;
    let selected_site = coordinate["byte_offset"].as_u64()? as usize;
    let body_offset = coordinate["function_body_offset"].as_u64()? as usize;
    let body_size = coordinate["function_body_size"].as_u64()? as usize;
    let mut functions = Vec::new();
    let tables = Tables::parse_under(bytes, meter)?;
    let elements = tables.active_functions();
    let mut imported = 0u32;
    let mut defined = 0u32;
    let mut calls_truncated = false;
    let mut selected_failed = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return None;
        };
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let Ok(import) = import else {
                        return None;
                    };
                    if matches!(import.ty, TypeRef::Func(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported + defined;
                defined += 1;
                let range = body.range();
                let selected = range.start == body_offset && range.len() == body_size;
                let mut function = FunctionDispatch {
                    index,
                    start: range.start,
                    len: range.len(),
                    calls: BTreeSet::new(),
                    tables: BTreeSet::new(),
                    sites: Vec::new(),
                    decoded: false,
                };
                let Ok(mut reader) = body.get_operators_reader() else {
                    if selected {
                        selected_failed = true;
                    }
                    functions.push(function);
                    continue;
                };
                let mut control = Vec::new();
                let mut loop_depth = 0usize;
                let mut broken = false;
                while !reader.eof() {
                    let start = reader.original_position();
                    let Ok(op) = reader.read() else {
                        broken = true;
                        break;
                    };
                    let size = reader.original_position() - start;
                    match wasm_control::control(&op) {
                        Control::Open(block) => {
                            loop_depth += usize::from(block == BlockKind::Loop);
                            control.push(block);
                        }
                        Control::Close { .. } if control.pop() == Some(BlockKind::Loop) => {
                            loop_depth -= 1;
                        }
                        _ => (),
                    }
                    match op {
                        Operator::Call { function_index } => {
                            function.calls.insert(function_index);
                        }
                        Operator::BrTable { .. } | Operator::CallIndirect { .. }
                            if loop_depth > 0 =>
                        {
                            if let Operator::CallIndirect { table_index, .. } = op {
                                function.tables.insert(table_index);
                            }
                            // Only site metadata is retained during traversal. Arms
                            // are decoded one site at a time as they are emitted.
                            function.sites.push(Site {
                                offset: start,
                                size,
                            });
                        }
                        _ => (),
                    }
                }
                if broken {
                    // A partial operator stream is not a dispatch neighborhood.
                    function.sites.clear();
                    function.calls.clear();
                    function.tables.clear();
                    function.decoded = false;
                    if selected {
                        selected_failed = true;
                    }
                } else {
                    function.decoded = true;
                }
                functions.push(function);
            }
            _ => (),
        }
    }
    if selected_failed {
        return None;
    }
    let selected_pos = functions
        .iter()
        .position(|function| function.start == body_offset && function.len == body_size)?;
    if !functions[selected_pos].decoded {
        return None;
    }
    let selected = functions[selected_pos].index;
    // Emit the ranked instruction first, not the first syntactically pretty
    // loop. In particular a large later table must precede an early tiny helper.
    functions[selected_pos]
        .sites
        .sort_by_key(|site| site.offset != selected_site);
    attach_table_edges(&mut functions, elements, &mut calls_truncated, meter);
    let included = neighborhood(&functions, selected);
    let mut handlers = Vec::new();
    let mut omissions = Vec::new();
    let unknowns = vec![
        "WASM dispatch selectors are candidates, not proven guest opcode values or handler bodies."
            .into(),
        "The guest stack/register model, operand widths and state effects remain unknown.".into(),
    ];
    let mut emitted_sites = 0u32;
    let mut emitted_functions = 0u32;
    let mut order = vec![selected];
    order.extend(included.iter().copied().filter(|index| *index != selected));
    let positions = functions
        .iter()
        .enumerate()
        .map(|(position, function)| (function.index, position))
        .collect::<std::collections::HashMap<_, _>>();
    for index in order {
        let Some(function) = positions.get(&index).map(|position| &functions[*position]) else {
            continue;
        };
        if function.sites.is_empty() {
            continue;
        }
        let mut emitted_here = false;
        for site in &function.sites {
            let before = handlers.len();
            let mut reader = OperatorsReader::new(BinaryReader::new(
                &bytes[site.offset..site.offset + site.size],
                site.offset,
            ));
            let op = reader.read().ok()?;
            match op {
                Operator::BrTable { targets } => {
                    for (selector, target) in targets.targets().enumerate() {
                        let arm = Arm {
                            opcode: Some(selector as u32),
                            offset: site.offset,
                            size: site.size,
                            kind: ArmKind::Selector,
                            detail: target.ok()?,
                        };
                        handlers.push(arm_value(&arm, function.index, selected));
                    }
                    let arm = Arm {
                        opcode: None,
                        offset: site.offset,
                        size: site.size,
                        kind: ArmKind::Default,
                        detail: targets.default(),
                    };
                    handlers.push(arm_value(&arm, function.index, selected));
                }
                Operator::CallIndirect { table_index, .. } => {
                    let arm = Arm {
                        opcode: None,
                        offset: site.offset,
                        size: site.size,
                        kind: ArmKind::Indirect,
                        detail: table_index,
                    };
                    handlers.push(arm_value(&arm, function.index, selected));
                }
                _ => return None,
            }
            if handlers.len() > before {
                emitted_sites += 1;
                emitted_here = true;
            }
        }
        if emitted_here {
            emitted_functions += 1;
        }
    }
    let dispatch_functions = functions
        .iter()
        .filter(|function| !function.sites.is_empty())
        .count();
    let omitted = dispatch_functions.saturating_sub(included.len());
    if omitted > 0 {
        let noun = if omitted == 1 {
            "function is"
        } else {
            "functions are"
        };
        omissions.push(json!({
            "reason": "dispatch-neighborhood",
            "detail": format!(
                "{omitted} in-loop dispatch {noun} more than {MAX_CALL_DEPTH} direct-call or call_indirect table hops from the selected interpreter, so outside this workspace."
            ),
        }));
    }
    if calls_truncated {
        omissions.push(json!({
            "reason": "call-edge-limit",
            "detail": "The artifact's work meter ran out while table-element edges were attached. Some statically related dispatch functions may be absent.",
        }));
    }
    let handler_tables = build_handler_tables(
        bytes,
        result
            .get("frontend")
            .and_then(|frontend| frontend.get("dispatch_inventory")),
        &tables,
        meter,
    );
    Some(ExtractedHandlers {
        handlers,
        unknowns,
        omissions,
        dispatch: ModuleDispatch {
            sites: emitted_sites,
            functions: emitted_functions,
        },
        handler_tables,
        tables,
    })
}

/// Every ranked dispatch site, then every active element table, lists each
/// explicit arm or placed slot in a target cluster.
fn build_handler_tables(
    bytes: &[u8],
    inventory: Option<&Value>,
    layout: &Tables,
    meter: &Meter,
) -> Vec<Value> {
    let mut tables = Vec::new();
    if let Some(candidates) = inventory
        .and_then(|value| value.get("candidates"))
        .and_then(|value| value.as_array())
    {
        for site in candidates {
            let row = if site["kind"] == "br_table" {
                br_table_handler_table(site, bytes)
            } else if site["kind"] == "call_indirect" {
                Some(call_indirect_handler_table(site, bytes))
            } else {
                None
            };
            if let Some(row) = row {
                tables.push(row);
            }
        }
    }
    for table_index in layout.active_tables() {
        if let Some(table) = element_handler_table(table_index, layout, meter) {
            tables.push(table);
        }
    }
    tables
}

/// One cluster per distinct target, each listing every selector that reaches
/// it. Producers before 2.21.0 kept the 1024 largest clusters and listed 32
/// selectors of each.
fn clusters_from_pairs(pairs: &[(u32, u32)]) -> (Vec<Value>, u64, u64) {
    let mut grouped: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (selector, target) in pairs {
        grouped.entry(*target).or_default().push(*selector);
    }
    let unique = grouped.len() as u64;
    let clusters = grouped
        .into_iter()
        .map(|(target, selectors)| {
            json!({
                "target": target,
                "selector_count": selectors.len(),
                "selectors": selectors,
            })
        })
        .collect();
    (clusters, unique, 0)
}

fn br_table_handler_table(site: &Value, bytes: &[u8]) -> Option<Value> {
    let offset = usize::try_from(site["byte_offset"].as_u64()?).ok()?;
    let size = usize::try_from(site["byte_size"].as_u64()?).ok()?;
    let end = offset.checked_add(size)?;
    let slice = bytes.get(offset..end)?;
    let mut reader = OperatorsReader::new(BinaryReader::new(slice, offset));
    let Operator::BrTable { targets } = reader.read().ok()? else {
        return None;
    };
    let mut pairs = Vec::new();
    for (selector, target) in targets.targets().enumerate() {
        let selector = u32::try_from(selector).ok()?;
        pairs.push((selector, target.ok()?));
    }
    let default_target = targets.default();
    if Some(pairs.len() as u64) != site["arm_count"].as_u64() {
        return None;
    }
    let (clusters, unique, omitted) = clusters_from_pairs(&pairs);
    Some(json!({
        "kind": "br_table",
        "evidence_class": site["evidence_class"],
        "function_index": site["function_index"],
        "byte_offset": site["byte_offset"],
        "byte_size": site["byte_size"],
        "table_index": null,
        "arm_count": site["arm_count"],
        "entry_count": site["arm_count"],
        "unique_target_count": unique,
        "default_target": default_target,
        "clusters": clusters,
        "omitted_cluster_count": omitted,
    }))
}

fn call_indirect_table_index(site: &Value, bytes: &[u8]) -> Option<u32> {
    let offset = usize::try_from(site["byte_offset"].as_u64()?).ok()?;
    let size = usize::try_from(site["byte_size"].as_u64()?).ok()?;
    let end = offset.checked_add(size)?;
    let slice = bytes.get(offset..end)?;
    let mut reader = OperatorsReader::new(BinaryReader::new(slice, offset));
    match reader.read().ok()? {
        Operator::CallIndirect { table_index, .. } => Some(table_index),
        _ => None,
    }
}

fn call_indirect_handler_table(site: &Value, bytes: &[u8]) -> Value {
    let table_index = call_indirect_table_index(site, bytes);
    json!({
        "kind": "call_indirect",
        "evidence_class": site["evidence_class"],
        "function_index": site["function_index"],
        "byte_offset": site["byte_offset"],
        "byte_size": site["byte_size"],
        "table_index": table_index,
        "arm_count": null,
        "entry_count": null,
        "unique_target_count": null,
        "default_target": null,
        "clusters": [],
        "omitted_cluster_count": 0,
    })
}

/// Clusters key on real table slots: each active segment is placed at its
/// evaluated offset and later segments overwrite earlier slots. A segment
/// whose offset reads an imported global stays `relative` with no slots, and
/// one that ends past the declared table minimum is `out-of-range`. Clusters
/// list only slots whose function is statically known.
fn element_handler_table(table_index: u32, layout: &Tables, meter: &Meter) -> Option<Value> {
    let memory = Memory::new(meter);
    let slots = layout.slots.get(&table_index).map_or(0, Vec::len);
    let unique = layout
        .active_functions()
        .get(&table_index)
        .map_or(0, Vec::len);
    if !meter.charge(slots as u64 * 32 + layout.segments_for(table_index).len() as u64)
        || !memory.keep(slots as u64 * 24 + unique as u64 * 256)
    {
        return None;
    }
    let pairs = layout
        .slots
        .get(&table_index)
        .into_iter()
        .flatten()
        .filter_map(|(slot, entry)| entry.function().map(|function| (*slot, function)))
        .collect::<Vec<_>>();
    let (clusters, unique, omitted) = clusters_from_pairs(&pairs);
    let segments = layout
        .segments_for(table_index)
        .iter()
        .map(|index| &layout.segments[*index])
        .map(|segment| {
            json!({
                "segment_index": segment.index,
                "placement": segment.placement.label(),
                "offset": match segment.placement {
                    Placement::Placed(offset)
                    | Placement::OutOfRange(offset)
                    | Placement::Unreached(offset) => Some(offset),
                    _ => None,
                },
                "global_index": match segment.placement {
                    Placement::Relative(global) => Some(global),
                    _ => None,
                },
                "entry_count": segment.entry_count,
            })
        })
        .collect::<Vec<_>>();
    Some(json!({
        "kind": "element",
        "evidence_class": "call-indirect-table",
        "function_index": null,
        "byte_offset": null,
        "byte_size": null,
        "table_index": table_index,
        "arm_count": null,
        "entry_count": pairs.len(),
        "unique_target_count": unique,
        "default_target": null,
        "clusters": clusters,
        "omitted_cluster_count": omitted,
        "segments": segments,
        "omitted_segment_count": 0,
    }))
}

fn attach_table_edges(
    functions: &mut [FunctionDispatch],
    elements: &BTreeMap<u32, Vec<u32>>,
    calls_truncated: &mut bool,
    meter: &Meter,
) {
    let memory = Memory::new(meter);
    if !meter.charge(functions.len() as u64) || !memory.keep(functions.len() as u64 * 64) {
        *calls_truncated = true;
        return;
    }
    // Element targets can name every function. Index once rather than
    // searching all functions for each target (quadratic on unique entries).
    let known = functions
        .iter()
        .map(|function| function.index)
        .collect::<std::collections::HashSet<_>>();
    let mut targets_of: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (table, targets) in elements {
        if !memory.keep(128 + targets.len() as u64 * 8) {
            *calls_truncated = true;
            return;
        }
        let entry = targets_of.entry(*table).or_default();
        for target in targets {
            if !meter.charge(1) {
                *calls_truncated = true;
                return;
            }
            if known.contains(target) {
                entry.insert(*target);
            }
        }
    }
    for function in functions.iter_mut() {
        for table in &function.tables {
            if let Some(targets) = targets_of.get(table) {
                function.calls.extend(targets);
            }
        }
    }
}

/// Functions with in-loop dispatch within `MAX_CALL_DEPTH` hops of the
/// selected one, following calls and table edges in either direction.
fn neighborhood(functions: &[FunctionDispatch], selected: u32) -> BTreeSet<u32> {
    let mut by_index = BTreeMap::new();
    let mut callers: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for function in functions {
        by_index.insert(function.index, function);
        for callee in &function.calls {
            callers.entry(*callee).or_default().insert(function.index);
        }
    }
    let mut included = BTreeSet::new();
    let mut visited = BTreeSet::from([selected]);
    if by_index
        .get(&selected)
        .is_some_and(|function| !function.sites.is_empty())
    {
        included.insert(selected);
    }
    let mut queue = VecDeque::from([(selected, 0u8)]);
    while let Some((current, depth)) = queue.pop_front() {
        if depth >= MAX_CALL_DEPTH {
            continue;
        }
        let calls = by_index
            .get(&current)
            .into_iter()
            .flat_map(|function| &function.calls);
        let incoming = callers.get(&current).into_iter().flatten();
        for next in calls.chain(incoming).copied().collect::<Vec<_>>() {
            if !by_index.contains_key(&next) || !visited.insert(next) {
                continue;
            }
            if by_index
                .get(&next)
                .is_some_and(|function| !function.sites.is_empty())
            {
                included.insert(next);
            }
            queue.push_back((next, depth + 1));
        }
    }
    included
}

fn arm_value(arm: &Arm, function: u32, selected: u32) -> Value {
    let (label, notes) = match arm.kind {
        ArmKind::Selector if function == selected => (
            format!("br_table selector {}", arm.opcode.unwrap_or(0)),
            format!(
                "Function {function} static selector {} is a Wasm branch to label depth {}. It is not a guest handler address. No guest opcode, PC, register, or stack is inferred; binding is unproven.",
                arm.opcode.unwrap_or(0),
                arm.detail
            ),
        ),
        ArmKind::Selector => (
            format!("br_table f{function} selector {}", arm.opcode.unwrap_or(0)),
            format!(
                "Function {function} static selector {} is a Wasm branch to label depth {}. It is not a guest handler address. No guest opcode, PC, register, or stack is inferred; binding is unproven.",
                arm.opcode.unwrap_or(0),
                arm.detail
            ),
        ),
        ArmKind::Default if function == selected => (
            "br_table default".into(),
            format!(
                "Function {function} default arm is a Wasm branch to label depth {} with no static selector. It is not a guest handler address. Binding is unproven.",
                arm.detail
            ),
        ),
        ArmKind::Default => (
            format!("br_table f{function} default"),
            format!(
                "Function {function} default arm is a Wasm branch to label depth {} with no static selector. It is not a guest handler address. Binding is unproven.",
                arm.detail
            ),
        ),
        ArmKind::Indirect if function == selected => (
            "call_indirect target".into(),
            format!(
                "Function {function} call_indirect uses function table {}. The selected entry is dynamic. No static arm index, guest opcode, PC, register, or stack is inferred; binding is unproven.",
                arm.detail
            ),
        ),
        ArmKind::Indirect => (
            format!("call_indirect f{function}"),
            format!(
                "Function {function} call_indirect uses function table {}. The selected entry is dynamic. No static arm index, guest opcode, PC, register, or stack is inferred; binding is unproven.",
                arm.detail
            ),
        ),
    };
    json!({
        "opcode": arm.opcode,
        "state": if arm.opcode.is_some() { "inferred" } else { "unknown" },
        "source": {"byte_offset": arm.offset, "byte_size": arm.size},
        "label": label,
        "operand_width": 0,
        "sample_count": 0,
        "notes": notes,
        "effects": [],
    })
}
