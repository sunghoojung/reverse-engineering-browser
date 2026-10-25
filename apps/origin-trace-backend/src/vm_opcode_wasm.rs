//! Bounded, inert dispatch-arm inspection of a captured WASM module.
//!
//! The detector ranks one static candidate function. Large modules also keep
//! in-loop `br_table` and `call_indirect` sites in a bounded neighborhood of
//! that function: direct calls within three hops, either direction, and
//! functions named by element segments of tables those functions use with
//! in-loop `call_indirect`. Unrelated jump tables stay out. Nothing here
//! instantiates the module or invents a guest program counter.
use super::MAX_HANDLERS;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use wasmparser::{
    BinaryReader, ElementItems, ElementKind, Operator, OperatorsReader, Parser, Payload, TypeRef,
};

const MAX_RELATED_FUNCTIONS: usize = 32;
const MAX_SITES_PER_FUNCTION: usize = MAX_HANDLERS;
const MAX_CALL_DEPTH: u8 = 3;
const MAX_VISITED_FUNCTIONS: usize = 512;
const MAX_CALLS_PER_FUNCTION: usize = 256;
const MAX_CALL_EDGES: usize = 16384;
const MAX_TABLE_DISPATCH_TARGETS: usize = 256;
const MAX_TABLE_OTHER_TARGETS: usize = 64;

pub(super) struct ModuleDispatch {
    pub sites: u32,
    pub functions: u32,
}

pub(super) struct ExtractedHandlers {
    pub handlers: Vec<Value>,
    pub unknowns: Vec<String>,
    pub omissions: Vec<Value>,
    pub dispatch: ModuleDispatch,
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
    calls: Vec<u32>,
    tables: BTreeSet<u32>,
    sites: Vec<Site>,
    decoded: bool,
    sites_truncated: bool,
}

pub(super) fn handlers(bytes: &[u8], result: &Value) -> Option<ExtractedHandlers> {
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
    let mut elements: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut imported = 0u32;
    let mut defined = 0u32;
    let mut call_edges = 0usize;
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
            Payload::ElementSection(reader) => {
                for element in reader {
                    let Ok(element) = element else {
                        return None;
                    };
                    let ElementKind::Active { table_index, .. } = element.kind else {
                        continue;
                    };
                    // MVP active segments omit the table index and mean table 0.
                    let targets = elements.entry(table_index.unwrap_or(0)).or_default();
                    match element.items {
                        ElementItems::Functions(functions) => {
                            for function in functions {
                                let Ok(function) = function else {
                                    return None;
                                };
                                targets.push(function);
                            }
                        }
                        ElementItems::Expressions(_, expressions) => {
                            for expression in expressions {
                                let Ok(expression) = expression else {
                                    return None;
                                };
                                let mut reader = expression.get_operators_reader();
                                while !reader.eof() {
                                    let Ok(op) = reader.read() else {
                                        return None;
                                    };
                                    if let Operator::RefFunc { function_index } = op {
                                        targets.push(function_index);
                                    }
                                }
                            }
                        }
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
                    calls: Vec::new(),
                    tables: BTreeSet::new(),
                    sites: Vec::new(),
                    decoded: false,
                    sites_truncated: false,
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
                    match op {
                        Operator::Call { function_index } => {
                            if function.calls.len() < MAX_CALLS_PER_FUNCTION
                                && call_edges < MAX_CALL_EDGES
                            {
                                function.calls.push(function_index);
                                call_edges += 1;
                            } else {
                                calls_truncated = true;
                            }
                        }
                        Operator::BrTable { .. } | Operator::CallIndirect { .. }
                            if loop_depth > 0 =>
                        {
                            if let Operator::CallIndirect { table_index, .. } = op {
                                function.tables.insert(table_index);
                            }
                            // Only site metadata is retained during traversal. Arms are
                            // decoded lazily under the final global handler budget below.
                            let site = Site {
                                offset: start,
                                size,
                            };
                            if function.sites.len() < MAX_SITES_PER_FUNCTION {
                                function.sites.push(site);
                            } else {
                                function.sites_truncated = true;
                                if selected && start == selected_site {
                                    *function.sites.last_mut().expect("site cap is nonzero") = site;
                                }
                            }
                        }
                        Operator::Loop { .. } => {
                            control.push(true);
                            loop_depth += 1;
                        }
                        Operator::Block { .. } | Operator::If { .. } => control.push(false),
                        Operator::End if control.pop() == Some(true) => loop_depth -= 1,
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
    attach_table_edges(&mut functions, &elements, &mut calls_truncated);
    let (included, neighborhood_limited) = neighborhood(&functions, selected);
    let mut handlers = Vec::new();
    let mut omissions = Vec::new();
    let unknowns = vec![
        "WASM dispatch selectors are candidates, not proven guest opcode values or handler bodies."
            .into(),
        "The guest stack/register model, operand widths and state effects remain unknown.".into(),
    ];
    if functions
        .iter()
        .any(|function| function.sites_truncated && included.contains(&function.index))
    {
        omissions.push(json!({"reason":"dispatch-site-limit","detail":"At most 1024 dispatch-site metadata records per function are retained; the ranked default is always kept. Arm expansion is separately bounded to 1024 total handlers."}));
    }
    let mut limit_hit = false;
    let mut emitted_sites = 0u32;
    let mut emitted_functions = 0u32;
    let mut order = vec![selected];
    order.extend(included.iter().copied().filter(|index| *index != selected));
    for index in order {
        let Some(function) = functions.iter().find(|function| function.index == index) else {
            continue;
        };
        if function.sites.is_empty() {
            continue;
        }
        let mut emitted_here = false;
        for site in &function.sites {
            if limit_hit {
                break;
            }
            let before = handlers.len();
            let mut reader = OperatorsReader::new(BinaryReader::new(
                &bytes[site.offset..site.offset + site.size],
                site.offset,
            ));
            let op = reader.read().ok()?;
            match op {
                Operator::BrTable { targets } => {
                    for (selector, target) in targets.targets().enumerate() {
                        if handlers.len() == MAX_HANDLERS {
                            limit_hit = true;
                            break;
                        }
                        let arm = Arm {
                            opcode: Some(selector as u32),
                            offset: site.offset,
                            size: site.size,
                            kind: ArmKind::Selector,
                            detail: target.ok()?,
                        };
                        handlers.push(arm_value(&arm, function.index, selected));
                    }
                    if handlers.len() < MAX_HANDLERS {
                        let arm = Arm {
                            opcode: None,
                            offset: site.offset,
                            size: site.size,
                            kind: ArmKind::Default,
                            detail: targets.default(),
                        };
                        handlers.push(arm_value(&arm, function.index, selected));
                    } else {
                        limit_hit = true;
                    }
                }
                Operator::CallIndirect { table_index, .. } => {
                    if handlers.len() < MAX_HANDLERS {
                        let arm = Arm {
                            opcode: None,
                            offset: site.offset,
                            size: site.size,
                            kind: ArmKind::Indirect,
                            detail: table_index,
                        };
                        handlers.push(arm_value(&arm, function.index, selected));
                    } else {
                        limit_hit = true;
                    }
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
        if limit_hit {
            break;
        }
    }
    if limit_hit {
        omissions.push(json!({"reason":"handler-limit","detail":"Only the first 1024 WASM dispatch-arm candidates are retained."}));
    }
    let dispatch_functions = functions
        .iter()
        .filter(|function| !function.sites.is_empty())
        .count();
    let omitted = dispatch_functions.saturating_sub(included.len());
    if omitted > 0 {
        let bound = if neighborhood_limited {
            " The walk hit its function bound."
        } else {
            ""
        };
        let noun = if omitted == 1 {
            "function is"
        } else {
            "functions are"
        };
        let mut detail = format!(
            "{omitted} in-loop dispatch {noun} outside this workspace.{bound} At most {MAX_RELATED_FUNCTIONS} functions are kept: the selected interpreter and its depth-{MAX_CALL_DEPTH} direct-call or call_indirect table neighborhood."
        );
        if detail.len() > 240 {
            detail = format!(
                "{omitted} in-loop dispatch functions are outside the bounded static neighborhood."
            );
            detail.truncate(240);
        }
        omissions.push(json!({
            "reason": "dispatch-neighborhood",
            "detail": detail,
        }));
    }
    if calls_truncated {
        omissions.push(json!({
            "reason": "call-edge-limit",
            "detail": "Direct-call or table-element edges were bounded. Some statically related dispatch functions may be absent.",
        }));
    }
    Some(ExtractedHandlers {
        handlers,
        unknowns,
        omissions,
        dispatch: ModuleDispatch {
            sites: emitted_sites,
            functions: emitted_functions,
        },
    })
}

fn attach_table_edges(
    functions: &mut [FunctionDispatch],
    elements: &BTreeMap<u32, Vec<u32>>,
    calls_truncated: &mut bool,
) {
    let mut preferred: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (table, targets) in elements {
        let mut dispatch = Vec::new();
        let mut other = Vec::new();
        for target in targets {
            let Some(function) = functions.iter().find(|function| function.index == *target) else {
                continue;
            };
            if dispatch.contains(target) || other.contains(target) {
                continue;
            }
            if function.sites.is_empty() {
                if other.len() < MAX_TABLE_OTHER_TARGETS {
                    other.push(*target);
                } else {
                    *calls_truncated = true;
                }
            } else if dispatch.len() < MAX_TABLE_DISPATCH_TARGETS {
                dispatch.push(*target);
            } else {
                *calls_truncated = true;
            }
        }
        dispatch.extend(other);
        preferred.insert(*table, dispatch);
    }
    for function in functions.iter_mut() {
        let tables = function.tables.clone();
        for table in tables {
            let Some(targets) = preferred.get(&table) else {
                continue;
            };
            for target in targets {
                if function.calls.len() >= MAX_CALLS_PER_FUNCTION {
                    *calls_truncated = true;
                    break;
                }
                if !function.calls.contains(target) {
                    function.calls.push(*target);
                }
            }
        }
    }
}

fn neighborhood(functions: &[FunctionDispatch], selected: u32) -> (BTreeSet<u32>, bool) {
    let mut by_index = BTreeMap::new();
    let mut callers: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for function in functions {
        by_index.insert(function.index, function);
        for callee in &function.calls {
            callers.entry(*callee).or_default().push(function.index);
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
    let mut limited = false;
    while let Some((current, depth)) = queue.pop_front() {
        if depth >= MAX_CALL_DEPTH {
            continue;
        }
        let mut neighbors = by_index
            .get(&current)
            .map(|function| function.calls.clone())
            .unwrap_or_default();
        if let Some(incoming) = callers.get(&current) {
            let mut incoming = incoming.clone();
            incoming.sort_unstable();
            incoming.dedup();
            neighbors.extend(incoming);
        }
        for next in neighbors {
            if !by_index.contains_key(&next) || !visited.insert(next) {
                continue;
            }
            if visited.len() > MAX_VISITED_FUNCTIONS {
                limited = true;
                break;
            }
            let has_sites = by_index
                .get(&next)
                .is_some_and(|function| !function.sites.is_empty());
            if has_sites {
                if included.len() < MAX_RELATED_FUNCTIONS {
                    included.insert(next);
                } else {
                    limited = true;
                }
            }
            queue.push_back((next, depth + 1));
        }
    }
    (included, limited)
}

fn arm_value(arm: &Arm, function: u32, selected: u32) -> Value {
    let (label, notes) = match arm.kind {
        ArmKind::Selector if function == selected => (
            format!("br_table selector {}", arm.opcode.unwrap_or(0)),
            format!(
                "Function {function} static selector {} branches to label depth {}. The source range cites this module instruction; guest opcode binding is unproven.",
                arm.opcode.unwrap_or(0),
                arm.detail
            ),
        ),
        ArmKind::Selector => (
            format!("br_table f{function} selector {}", arm.opcode.unwrap_or(0)),
            format!(
                "Function {function} static selector {} branches to label depth {}. The source range cites this module instruction; guest opcode binding is unproven.",
                arm.opcode.unwrap_or(0),
                arm.detail
            ),
        ),
        ArmKind::Default if function == selected => (
            "br_table default".into(),
            format!(
                "Function {function} default dispatch arm to label depth {} has no static selector. Guest opcode binding is unproven.",
                arm.detail
            ),
        ),
        ArmKind::Default => (
            format!("br_table f{function} default"),
            format!(
                "Function {function} default dispatch arm to label depth {} has no static selector. Guest opcode binding is unproven.",
                arm.detail
            ),
        ),
        ArmKind::Indirect if function == selected => (
            "call_indirect target".into(),
            format!(
                "Function {function} call_indirect uses function table {}. The selected entry is dynamic. No static handler index or guest opcode binding is inferred.",
                arm.detail
            ),
        ),
        ArmKind::Indirect => (
            format!("call_indirect f{function}"),
            format!(
                "Function {function} call_indirect uses function table {}. The selected entry is dynamic. No static handler index or guest opcode binding is inferred.",
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
