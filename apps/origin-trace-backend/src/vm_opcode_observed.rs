//! Observed dispatch claims and nested guests, derived only from runtime rows
//! this workspace already retained. Static recovery and its handler rows are
//! never changed: each claim sits beside them, names the exact retained events
//! that support it, and states how it compares with the static claim.
use crate::vm::dispatch_shape::{Role, Roles};
use crate::vm::wasm_tables::{Entry, Placement, Tables};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Distinct observed claims kept per workspace.
const MAX_CLAIMS: usize = 256;
/// Event identities listed on one claim or inner guest; counts cover all rows.
const MAX_LISTED_EVENTS: usize = 8;
const MAX_NESTED: usize = 64;
const MAX_INNER_OPCODES: usize = 64;
/// Longest renderer sequence window checked for a contiguous outer dispatch,
/// and the lookups shared by every window of one workspace. Past either bound
/// the basis stays `nearest-retained`, which claims less.
const MAX_SEQUENCE_WINDOW: u64 = 4096;
const MAX_SEQUENCE_WORK: u64 = 65536;

pub(super) struct Inputs<'a> {
    pub runtime: &'a str,
    pub roles: Option<&'a Roles>,
    pub classification: Option<&'a Value>,
    pub handlers: &'a [Value],
    /// Opcodes recovery found that the opcode-claim gate removed.
    pub withheld: &'a BTreeSet<u32>,
    pub samples: &'a [Value],
    pub physical: &'a [Value],
    pub guest: &'a [Value],
    /// Accepted call_indirect rows and the module's static table layout,
    /// which supplies their static slot claims.
    pub indirect: &'a [Value],
    pub tables: Option<&'a Tables>,
    pub events: &'a [Value],
}

#[derive(Default)]
pub(super) struct Derived {
    pub claims: Vec<Value>,
    pub nested: Vec<Value>,
    pub omissions: Vec<Value>,
    pub unknowns: Vec<String>,
}

/// (stream, function, site, selector, opcode, handler). Rows that agree on
/// every field support one claim; any difference is a separate claim.
type Key = (
    &'static str,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    u64,
);

struct Claim {
    site: Value,
    attribution: &'static str,
    is_default: bool,
    /// The site's table for a call_indirect claim.
    table: Option<u32>,
    events: Vec<Value>,
    count: u64,
}

fn plural(count: u64, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn interpreter(roles: Option<&Roles>, offset: u64) -> bool {
    roles.is_some_and(|roles| {
        usize::try_from(offset)
            .is_ok_and(|offset| roles.get(offset) == Some(Role::InterpreterCandidate))
    })
}

/// A JavaScript dispatch sample names its interpreter artifact, not a site.
/// It is attributed to a site only when the complete classification has
/// exactly one interpreter candidate; otherwise it stays artifact-scoped.
fn javascript_site(inputs: &Inputs<'_>) -> Option<(Value, &'static str)> {
    let classification = inputs.classification?;
    let roles = inputs.roles?;
    let candidates = classification["role_counts"]["interpreter-candidate"].as_u64()?;
    if candidates == 0 {
        return None;
    }
    let complete = !roles.limited()
        && classification["omissions"].as_array().is_some_and(|rows| {
            rows.iter()
                .all(|row| row["reason"] == "handler-binding-unproven")
        });
    let sole = (candidates == 1 && complete)
        .then(|| {
            classification["sites"]
                .as_array()?
                .iter()
                .find(|site| site["role"] == "interpreter-candidate")
        })
        .flatten();
    Some(match sole {
        Some(site) => (
            json!({
                "function_index": null,
                "byte_offset": site["location"]["byte_offset"],
                "line": site["location"]["line"],
                "column": site["location"]["column"],
            }),
            "sole-interpreter-candidate",
        ),
        None => (Value::Null, "artifact"),
    })
}

/// How an observed claim stands against the static claim for the same
/// opcode (JavaScript) or the same site and arm (WebAssembly). Static arms are
/// labeled by their selector, so a guest opcode observed on another arm
/// contradicts that label rather than replacing it.
fn static_claim(inputs: &Inputs<'_>, key: &Key, claim: &Claim) -> Value {
    let (stream, _, site, selector, opcode, handler) = *key;
    let is_default = claim.is_default;
    if stream == "native-wasm-indirect" {
        return indirect_static_claim(
            inputs.tables,
            claim.table.expect("call_indirect claims name a table"),
            selector.expect("call_indirect claims name a slot"),
            handler,
            site.expect("call_indirect claims name a site"),
        );
    }
    let row = |state: &str, opcode: Option<u64>, index: &Value, offset: &Value| json!({"state":state,"opcode":opcode,"handler_index":index,"byte_offset":offset});
    if stream == "dispatch-sample" {
        let opcode = opcode.expect("dispatch samples carry an opcode");
        return match inputs
            .handlers
            .iter()
            .find(|row| row["opcode"].as_u64() == Some(opcode))
        {
            Some(found) => {
                // A switch case names its own case value as its handler.
                let named = found["handler_index"].as_u64().unwrap_or(opcode);
                row(
                    if named == handler {
                        "agrees"
                    } else {
                        "disagrees"
                    },
                    Some(opcode),
                    found.get("handler_index").unwrap_or(&Value::Null),
                    &found["source"]["byte_offset"],
                )
            }
            None if u32::try_from(opcode).is_ok_and(|op| inputs.withheld.contains(&op)) => {
                row("withheld", Some(opcode), &Value::Null, &Value::Null)
            }
            None => row("absent", None, &Value::Null, &Value::Null),
        };
    }
    let found = (!is_default)
        .then(|| {
            inputs.handlers.iter().find(|row| {
                row["source"]["byte_offset"].as_u64() == site && row["opcode"].as_u64() == selector
            })
        })
        .flatten();
    match found {
        Some(found) => row(
            if stream == "native-guest" && opcode != selector {
                "disagrees"
            } else {
                "agrees"
            },
            selector,
            &Value::Null,
            &found["source"]["byte_offset"],
        ),
        None => row("absent", None, &Value::Null, &Value::Null),
    }
}

/// The element segments' claim for one table slot. A slot the layout places
/// agrees or disagrees with the observed callee; a placed null slot that ran a
/// function disagrees. A slot the module fills only at run time, through a
/// relative, unresolved or passive segment or an unexpanded table, has its
/// static claim withheld, as does an entry whose function is unknown. Any
/// other slot has no static claim.
fn indirect_static_claim(
    tables: Option<&Tables>,
    table: u32,
    slot: u64,
    callee: u64,
    site: u64,
) -> Value {
    let row = |state: &str, handler: Option<u32>, offset: Option<u64>| json!({"state":state,"opcode":slot,"handler_index":handler,"byte_offset":offset});
    let Some(tables) = tables else {
        return row("withheld", None, None);
    };
    let placed = u32::try_from(slot).ok().and_then(|slot| {
        let entries = tables.slots.get(&table)?;
        let index = entries.binary_search_by_key(&slot, |(at, _)| *at).ok()?;
        Some(entries[index].1)
    });
    let runtime = || {
        tables.oversized.contains(&table)
            || tables.segments_for(table).iter().any(|index| {
                matches!(
                    tables.segments[*index].placement,
                    Placement::Relative(_) | Placement::Unresolved
                )
            })
            || tables
                .segments
                .iter()
                .any(|segment| segment.placement == Placement::Passive)
    };
    match placed {
        Some(Entry::Function(function)) => row(
            if u64::from(function) == callee {
                "agrees"
            } else {
                "disagrees"
            },
            Some(function),
            Some(site),
        ),
        Some(Entry::Null) => row("disagrees", None, Some(site)),
        Some(Entry::Unknown) => row("withheld", None, None),
        None if runtime() => row("withheld", None, None),
        None => json!({"state":"absent","opcode":null,"handler_index":null,"byte_offset":null}),
    }
}

/// A call_indirect row claims the callee it resolved at an exact site. A row
/// whose entry was null, out of bounds, from another instance or unresolved
/// names no callee and supplies no claim. Returns (not interpreter, no callee).
fn indirect_rows(
    claims: &mut BTreeMap<Key, Claim>,
    roles: Option<&Roles>,
    rows: &[Value],
) -> (u64, u64) {
    let (mut unattached, mut unresolved) = (0, 0);
    for row in rows {
        let (Some(function), Some(site), Some(slot), Some(table)) = (
            row["function_index"].as_u64(),
            row["module_byte_offset"].as_u64(),
            row["slot"].as_u64(),
            row["table_index"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok()),
        ) else {
            continue;
        };
        if !interpreter(roles, site) {
            unattached += 1;
            continue;
        }
        let Some(callee) = row["callee_function_index"].as_u64() else {
            unresolved += 1;
            continue;
        };
        add(
            claims,
            (
                "native-wasm-indirect",
                Some(function),
                Some(site),
                Some(slot),
                None,
                callee,
            ),
            || Claim {
                site: json!({"function_index":function,"byte_offset":site,"line":null,"column":null}),
                attribution: "exact",
                is_default: false,
                table: Some(table),
                events: Vec::new(),
                count: 0,
            },
            &row["event"],
        );
    }
    (unattached, unresolved)
}

fn add(claims: &mut BTreeMap<Key, Claim>, key: Key, make: impl FnOnce() -> Claim, event: &Value) {
    let claim = claims.entry(key).or_insert_with(make);
    claim.count += 1;
    if claim.events.len() < MAX_LISTED_EVENTS {
        claim.events.push(event.clone());
    }
}

fn wasm_rows(
    claims: &mut BTreeMap<Key, Claim>,
    roles: Option<&Roles>,
    stream: &'static str,
    rows: &[Value],
) -> u64 {
    let mut unattached = 0;
    for row in rows {
        let (Some(function), Some(site), Some(selector), Some(arm)) = (
            row["function_index"].as_u64(),
            row["module_byte_offset"].as_u64(),
            row["selector"].as_u64(),
            row["selected_arm"].as_u64(),
        ) else {
            continue;
        };
        if !interpreter(roles, site) {
            unattached += 1;
            continue;
        }
        let opcode = (stream == "native-guest")
            .then(|| row["opcode"].as_u64())
            .flatten();
        let is_default = row["is_default"] == true;
        add(
            claims,
            (
                stream,
                Some(function),
                Some(site),
                Some(selector),
                opcode,
                arm,
            ),
            || Claim {
                site: json!({"function_index":function,"byte_offset":site,"line":null,"column":null}),
                attribution: "exact",
                is_default,
                table: None,
                events: Vec::new(),
                count: 0,
            },
            &row["event"],
        );
    }
    unattached
}

pub(super) fn derive(inputs: Inputs<'_>) -> Derived {
    let mut derived = Derived::default();
    let mut claims = BTreeMap::<Key, Claim>::new();
    // Caller reports are never observations; their rows stay as retained.
    let native = inputs
        .samples
        .iter()
        .filter(|row| row.get("provenance").is_none())
        .collect::<Vec<_>>();
    let mut unsited = 0u64;
    let mut unattached = 0u64;
    let mut unresolved = 0u64;
    if inputs.runtime == "javascript" {
        match javascript_site(&inputs) {
            Some((site, attribution)) => {
                for row in native {
                    let (Some(opcode), Some(handler)) =
                        (row["opcode"].as_u64(), row["handler_index"].as_u64())
                    else {
                        continue;
                    };
                    add(
                        &mut claims,
                        ("dispatch-sample", None, None, None, Some(opcode), handler),
                        || Claim {
                            site: site.clone(),
                            attribution,
                            is_default: false,
                            table: None,
                            events: Vec::new(),
                            count: 0,
                        },
                        &row["event"],
                    );
                }
            }
            None => unsited = native.len() as u64,
        }
    } else {
        // Wasm claims need the exact site that only native streams record.
        unsited = native.len() as u64;
        unattached += wasm_rows(&mut claims, inputs.roles, "native-guest", inputs.guest);
        unattached += wasm_rows(&mut claims, inputs.roles, "native-wasm", inputs.physical);
        let (outside, unnamed) = indirect_rows(&mut claims, inputs.roles, inputs.indirect);
        unattached += outside;
        unresolved = unnamed;
    }
    let omitted = claims.len().saturating_sub(MAX_CLAIMS);
    let mut disagreements = 0u64;
    for (key, claim) in claims.into_iter().take(MAX_CLAIMS) {
        let (stream, _, _, selector, opcode, handler) = key;
        let comparison = static_claim(&inputs, &key, &claim);
        disagreements += u64::from(comparison["state"] == "disagrees");
        derived.claims.push(json!({
            "stream": stream,
            "confidence": "observed",
            "site": claim.site,
            "site_attribution": claim.attribution,
            "selector": selector,
            "opcode": opcode,
            "handler": match (stream, claim.table) {
                ("dispatch-sample", _) => json!({"kind":"handler-index","handler_index":handler}),
                (_, Some(table)) => json!({"kind":"table-entry","table_index":table,"callee_function_index":handler}),
                _ => json!({"kind":"br-table-arm","arm":handler,"is_default":claim.is_default}),
            },
            "sample_count": claim.count,
            "events": claim.events,
            "static_claim": comparison,
        }));
    }
    if disagreements > 0 {
        derived.unknowns.push(format!(
            "{} with the static handler claim for the same opcode, arm or table slot. Both are kept; neither replaces the other.",
            plural(disagreements, "observed dispatch claim disagrees", "observed dispatch claims disagree")
        ));
    }
    if omitted > 0 {
        derived.omissions.push(json!({"reason":"observed-claim-limit","detail":format!(
            "Only the first 256 distinct observed dispatch claims are kept; {omitted} more are omitted. Their retained sample rows are unchanged."
        )}));
    }
    if unattached > 0 {
        derived.omissions.push(json!({"reason":"observed-claims-not-interpreter","detail":format!(
            "{} at a dispatch site that is not a classified interpreter candidate. The rows stay retained and supply no observed claims.",
            plural(unattached, "retained native dispatch record is", "retained native dispatch records are")
        )}));
    }
    if unresolved > 0 {
        derived.omissions.push(json!({"reason":"observed-claims-unresolved-callee","detail":format!(
            "{} no callee in this module: the table entry was null, out of bounds, from another instance or unresolved. The rows stay retained and supply no observed claims.",
            plural(unresolved, "retained call_indirect observation names", "retained call_indirect observations name")
        )}));
    }
    if unsited > 0 {
        derived.omissions.push(json!({"reason":"observed-claims-unsited","detail":format!(
            "{} no dispatch site{}, so {} no observed claims.",
            plural(unsited, "retained dispatch sample names", "retained dispatch samples name"),
            if inputs.runtime == "javascript" { " and this artifact has no classified interpreter-candidate site" } else { "; WebAssembly claims need an exact native site" },
            if unsited == 1 { "it supplies" } else { "they supply" }
        )}));
    }
    nested(&inputs, &mut derived);
    derived
}

fn sequence(reference: &Value) -> Option<u64> {
    reference["sequence_number"].as_str()?.parse().ok()
}

fn buffer(row: &Value) -> (Value, Value, Value) {
    (
        row["memory_index"].clone(),
        row["memory_base"].clone(),
        row["memory_length"].clone(),
    )
}

type Identity = (String, u64, u64);

fn identity(reference: &Value) -> Option<Identity> {
    Some((
        reference["session_id"].as_str()?.to_owned(),
        reference["process_id"].as_u64()?,
        sequence(reference)?,
    ))
}

/// A guest activation that names a parent invocation, runs at another
/// dispatch site and reads another guest buffer is an inner interpreter driven
/// by the parent's handler. Same-site children are reentrant activations of
/// one dispatcher and are not nested guests. A version 2 or 3 marker names the
/// driving dispatch exactly; version 1 evidence and parents whose dispatch the
/// renderer could not resolve fall back to sequence order.
fn nested(inputs: &Inputs<'_>, derived: &mut Derived) {
    if !inputs.guest.iter().any(|row| {
        row["parent_invocation_id"]
            .as_str()
            .is_some_and(|id| id != "0")
    }) {
        return;
    }
    let mut order = Vec::<&str>::new();
    let mut groups = HashMap::<&str, Vec<&Value>>::new();
    for row in inputs.guest {
        let Some(id) = row["invocation_id"].as_str() else {
            continue;
        };
        groups
            .entry(id)
            .or_insert_with(|| {
                order.push(id);
                Vec::new()
            })
            .push(row);
    }
    let index = inputs
        .events
        .iter()
        .filter_map(|event| {
            let reference = json!({"session_id":event["session_id"],"process_id":event["process_id"],"sequence_number":event["sequence_number"]});
            identity(&reference).map(|key| (key, event))
        })
        .collect::<HashMap<_, _>>();
    let site = |row: &Value| {
        (
            row["function_index"].clone(),
            row["module_byte_offset"].clone(),
        )
    };
    let mut unproven = 0u64;
    let mut omitted = 0u64;
    let mut sequence_work = MAX_SEQUENCE_WORK;
    for id in order {
        let rows = &groups[id];
        let first = rows[0];
        let Some(parent) = first["parent_invocation_id"]
            .as_str()
            .filter(|id| *id != "0")
        else {
            continue;
        };
        let Some(parents) = groups.get(parent) else {
            unproven += 1;
            continue;
        };
        if site(parents[0]) == site(first) {
            continue;
        }
        let linked = (|| {
            let child_marker = &first["invocation_event"];
            let parent_marker = &parents[0]["invocation_event"];
            let (child_key, parent_key) = (identity(child_marker)?, identity(parent_marker)?);
            if parents[0]["instance_id"] != first["instance_id"]
                || child_key.0 != parent_key.0
                || child_key.1 != parent_key.1
                || parent_key.2 >= child_key.2
                || index.get(&child_key)?["thread_id"] != index.get(&parent_key)?["thread_id"]
                || !interpreter(inputs.roles, first["module_byte_offset"].as_u64()?)
                || !interpreter(inputs.roles, parents[0]["module_byte_offset"].as_u64()?)
            {
                return None;
            }
            // The parent's handler running when the child activation began: its
            // last retained dispatch before the child's marker. An exact name
            // must be that dispatch; a lost or contradicted one stays unproven
            // rather than falling back to the sequence-order guess.
            let outer = parents
                .iter()
                .filter(|row| sequence(&row["event"]).is_some_and(|seq| seq < child_key.2))
                .max_by_key(|row| sequence(&row["event"]))?;
            let exact = super::native_guest::exact_parent_dispatch(index.get(&child_key)?);
            if exact.is_some_and(|seq| sequence(&outer["event"]) != Some(seq)) {
                return None;
            }
            if buffer(outer) == buffer(first) {
                return None;
            }
            let start = sequence(&outer["event"])?;
            let window = child_key.2 - start - 1;
            let basis = if exact.is_some() {
                "exact-parent-dispatch"
            } else if window <= MAX_SEQUENCE_WINDOW.min(sequence_work)
                && {
                    sequence_work -= window;
                    true
                }
                && (start + 1..child_key.2).all(|seq| {
                    index
                        .get(&(child_key.0.clone(), child_key.1, seq))
                        .is_some_and(|event| {
                            !matches!(event["type"].as_str(), Some("gap" | "wasm_guest_dispatch"))
                        })
                })
            {
                "contiguous-sequence"
            } else {
                "nearest-retained"
            };
            let mut opcodes = BTreeMap::<u64, u64>::new();
            for row in rows {
                if let Some(opcode) = row["opcode"].as_u64() {
                    *opcodes.entry(opcode).or_default() += 1;
                }
            }
            let omitted_opcodes = opcodes.len().saturating_sub(MAX_INNER_OPCODES);
            let side = |row: &Value, invocation: &str| {
                json!({
                    "invocation_id": invocation,
                    "invocation_event": row["invocation_event"],
                    "function_index": row["function_index"],
                    "module_byte_offset": row["module_byte_offset"],
                    "memory_index": row["memory_index"],
                    "memory_base": row["memory_base"],
                    "memory_length": row["memory_length"],
                    "bytecode_artifact_id": row["bytecode_artifact_id"],
                })
            };
            let mut outer_side = side(outer, parent);
            for key in [
                "selector",
                "opcode",
                "selected_arm",
                "is_default",
                "instruction_pointer",
            ] {
                outer_side[key] = outer[key].clone();
            }
            outer_side["dispatch_event"] = outer["event"].clone();
            outer_side["basis"] = json!(basis);
            let mut inner = side(first, id);
            inner["sample_count"] = json!(rows.len());
            inner["events"] = json!(
                rows.iter()
                    .take(MAX_LISTED_EVENTS)
                    .map(|row| row["event"].clone())
                    .collect::<Vec<_>>()
            );
            inner["observed_opcodes"] = json!(
                opcodes
                    .iter()
                    .take(MAX_INNER_OPCODES)
                    .map(|(opcode, count)| json!({"opcode":opcode,"sample_count":count}))
                    .collect::<Vec<_>>()
            );
            inner["omitted_opcode_count"] = json!(omitted_opcodes);
            Some(json!({
                "confidence": "observed",
                "instance_id": first["instance_id"],
                "outer": outer_side,
                "inner": inner,
            }))
        })();
        match linked {
            Some(row) if derived.nested.len() < MAX_NESTED => derived.nested.push(row),
            Some(_) => omitted += 1,
            None => unproven += 1,
        }
    }
    if unproven > 0 {
        derived.omissions.push(json!({"reason":"nested-guest-unproven","detail":format!(
            "{} a parent invocation but cannot be linked as a nested guest: a retained parent, outer dispatch, shared thread and instance, interpreter-candidate sites or a distinct guest buffer is missing.",
            plural(unproven, "guest activation names", "guest activations name")
        )}));
    }
    if omitted > 0 {
        derived.omissions.push(json!({"reason":"nested-guest-limit","detail":format!(
            "Only the first 64 nested guests are kept; {omitted} more are omitted. Their guest sample rows are unchanged."
        )}));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{fs, path::Path};

    // Distinct identities, so the exported store can join other rendered-UI stores.
    const SCOPE: [(&str, &str); 3] = [
        ("session_id", "41"),
        ("navigation_id", "42"),
        ("frame_id", "43"),
    ];
    const MODULE: u64 = 401;

    fn artifact(
        root: &Path,
        id: u64,
        kind: &str,
        bytes: &[u8],
        parent: u64,
        creator: u64,
    ) -> Value {
        let hash = hex::encode(Sha256::digest(bytes));
        fs::create_dir_all(root.join("blobs")).unwrap();
        fs::write(root.join(format!("blobs/{hash}.bin")), bytes).unwrap();
        let origin = match kind {
            "javascript" => "dynamic_javascript",
            "wasm" => "webassembly_compile",
            _ => "native_wasm_guest",
        };
        let mut row = json!({"protocol_version":1,"artifact_id":id.to_string(),"parent_artifact_id":parent.to_string(),
            "creator_event_id":creator.to_string(),"execution_context_id":"1","capture_origin":origin,"kind":kind,
            "url":"fixture://observed-claims","mime_type":"application/octet-stream","byte_size":bytes.len(),
            "sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        for (key, value) in SCOPE {
            row[key] = json!(value);
        }
        row
    }

    /// A complete broker-written event record, as the event API serves it.
    fn event(kind: &str, seq: u64, parent: u64, artifact: u64, payload: &[u8]) -> Value {
        let mut row = json!({"protocol_version":3,"artifact_id":artifact.to_string(),"sequence_number":seq.to_string(),
            "monotonic_time_ns":seq.to_string(),"process_id":41,"thread_id":5,"tab_id":0,"request_id":"0",
            "browser_context_id_high":"0","browser_context_id_low":"0","encoded_data_length":"0","decoded_body_length":"0",
            "status_code":0,"error_code":0,"resource_type":0,"initiator_request_id":0,"initiator_process_id":0,
            "category":"vm","type":kind,"parent_event_id":parent.to_string(),"flags":0,"payload_size":payload.len(),
            "payload_encoding":"hex","payload_truncated":false,"payload":hex::encode(payload)});
        for (key, value) in SCOPE {
            row[key] = json!(value);
        }
        row
    }

    fn put(payload: &mut [u8], at: usize, value: u64, width: usize) {
        payload[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    /// The shipped strict UI consumer, run on an exact backend document.
    fn ui_accepts(document: &Value) -> bool {
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("../research-ui/evidence_models.js");
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(document).unwrap()).unwrap();
        let output = std::process::Command::new("node")
            .args(["--eval", "const fs=require('node:fs');const validate=new Function(fs.readFileSync(process.argv[1],'utf8')+'\\nreturn isVmOpcodeWorkspaceDocument;')();process.exit(validate(JSON.parse(fs.readFileSync(process.argv[2],'utf8')))?0:3);"])
            .arg(model)
            .arg(file.path())
            .output()
            .expect("Node.js runs the shipped UI validator");
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.status.success()
    }

    fn document(root: &Path) -> Value {
        serde_json::from_slice(
            &fs::read(root.join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
        )
        .unwrap()
    }

    /// Runs the real analyzer over one store and returns the first workspace.
    fn analyze(root: &Path, artifacts: &[Value], events: &[Value]) -> Value {
        let lines = |rows: &[Value]| {
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>()
        };
        fs::write(root.join("manifest.jsonl"), lines(artifacts)).unwrap();
        fs::write(root.join("events.jsonl"), lines(events)).unwrap();
        crate::vm::store(root, &root.join("events.jsonl")).unwrap();
        let document = document(root);
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors = validator
            .iter_errors(&document)
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            ui_accepts(&document),
            "shipped UI validator rejected {document:#}"
        );
        document["workspaces"][0].clone()
    }

    fn omission<'a>(workspace: &'a Value, reason: &str) -> Option<&'a str> {
        workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["reason"] == reason)
            .map(|row| row["detail"].as_str().unwrap())
    }

    /// One native `vm_dispatch_sample` naming interpreter artifact `artifact`.
    fn dispatch_sample(seq: u64, artifact: u64, opcode: u32, handler: u32) -> Value {
        let mut payload = vec![0u8; 128];
        payload[..4].copy_from_slice(&[1, 0, 128, 0]);
        put(&mut payload, 8, opcode.into(), 4);
        put(&mut payload, 12, handler.into(), 4);
        put(&mut payload, 16, seq, 4);
        put(&mut payload, 24, 1, 8);
        put(&mut payload, 32, 1, 8);
        put(&mut payload, 40, artifact, 8);
        let mut row = event("vm_dispatch_sample", seq, 0, artifact, &payload);
        row["protocol_version"] = json!(2);
        row
    }

    /// Owned synthetic interpreter. Its table is filled by a host callback
    /// at runtime, so recovery sees only the three literal entries.
    const RUNTIME_TABLE: &str = "function run(code,stack,install){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};install(ops);while(pc<code.length){ops[code[pc++]](stack);}return stack;}";

    #[test]
    fn javascript_runtime_table_claims_are_observed_and_compared() {
        let root = tempfile::tempdir().unwrap();
        let source = artifact(root.path(), 1, "javascript", RUNTIME_TABLE.as_bytes(), 0, 0);
        let other = artifact(root.path(), 9, "javascript", b"function other(){}", 0, 0);
        let mut stale = dispatch_sample(20, 1, 4, 4);
        stale["navigation_id"] = json!("8");
        let mut truncated = dispatch_sample(21, 1, 4, 4);
        truncated["payload_truncated"] = json!(true);
        let events = [
            dispatch_sample(10, 1, 1, 1),
            dispatch_sample(11, 1, 3, 7),
            dispatch_sample(12, 1, 3, 7),
            dispatch_sample(13, 1, 5, 5),
            // Never attached: another artifact, a stale navigation, a truncated record.
            dispatch_sample(14, 9, 4, 4),
            stale,
            truncated,
        ];
        let workspace = analyze(root.path(), &[source, other], &events);
        let claims = workspace["observed_claims"].as_array().unwrap();
        let states = claims
            .iter()
            .map(|c| {
                (
                    c["opcode"].as_u64().unwrap(),
                    c["handler"]["handler_index"].as_u64().unwrap(),
                    c["sample_count"].as_u64().unwrap(),
                    c["static_claim"]["state"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            [
                (1, 1, 1, "agrees"),
                (3, 7, 2, "disagrees"),
                (5, 5, 1, "absent")
            ]
        );
        for claim in claims {
            assert_eq!(claim["confidence"], "observed");
            assert_eq!(claim["stream"], "dispatch-sample");
            assert_eq!(claim["site_attribution"], "sole-interpreter-candidate");
            assert!(claim["selector"].is_null());
        }
        assert_eq!(
            claims[1]["events"],
            json!([{"session_id":"41","process_id":41,"sequence_number":"11"},{"session_id":"41","process_id":41,"sequence_number":"12"}])
        );
        // The static row is unchanged and still names its own handler.
        let three = workspace["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["opcode"] == 3)
            .unwrap();
        assert_eq!(three["handler_index"], 3);
        assert!(workspace["unknowns"].as_array().unwrap().iter().any(|u| {
            u.as_str()
                .unwrap()
                .starts_with("1 observed dispatch claim disagrees")
        }));
        assert_eq!(workspace["sample_count"], 4);
        // The viewer recomputes each comparison; a document cannot hide a contradiction.
        let mut forged = document(root.path());
        forged["workspaces"][0]["observed_claims"][1]["static_claim"]["state"] = json!("agrees");
        assert!(!ui_accepts(&forged));
    }

    /// A one-shot header switch is withheld by the gate; the loop's table is
    /// built at runtime. Observed rows supply the claims and name the gap.
    #[test]
    fn withheld_static_claims_stay_withheld_beside_observed_claims() {
        let source = "function run(code,stack,build){var pc=0;var ops=build();switch(code[pc]){case 1:stack.push(1);break;case 2:stack.pop();break;case 3:stack.length=0;break;}pc++;while(pc<code.length){ops[code[pc++]](stack);}return stack;}";
        let root = tempfile::tempdir().unwrap();
        let js = artifact(root.path(), 1, "javascript", source.as_bytes(), 0, 0);
        let workspace = analyze(
            root.path(),
            &[js],
            &[dispatch_sample(10, 1, 2, 2), dispatch_sample(11, 1, 6, 6)],
        );
        assert!(
            omission(&workspace, "handler-withheld").is_some(),
            "{workspace:#}"
        );
        let claims = workspace["observed_claims"].as_array().unwrap();
        assert_eq!(
            claims[0]["static_claim"],
            json!({"state":"withheld","opcode":2,"handler_index":null,"byte_offset":null})
        );
        assert_eq!(claims[1]["static_claim"]["state"], "absent");
    }
    /// Owned synthetic handler-table interpreter. Table 0 is placed by its
    /// element segment; table 1 is placed through an imported global, so only
    /// run time decides its slots.
    const INDIRECT: &str = r#"(module
      (import "env" "base" (global $base i32))
      (memory 1)
      (type $op (func (param i32) (result i32)))
      (table $placed 3 funcref)
      (table $runtime 4 funcref)
      (func $inc (type $op) (i32.add (local.get 0) (i32.const 1)))
      (func $dec (type $op) (i32.sub (local.get 0) (i32.const 1)))
      (func $dbl (type $op) (i32.shl (local.get 0) (i32.const 1)))
      (elem (table $placed) (i32.const 0) func $inc $dec)
      (elem (table $runtime) (global.get $base) func $dbl)
      (func (export "run") (param $code i32) (param $len i32) (result i32)
        (local $pc i32) (local $acc i32)
        (block $exit (loop $again
          (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
          (local.set $acc (call_indirect $placed (type $op) (local.get $acc)
            (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
          (local.set $acc (call_indirect $runtime (type $op) (local.get $acc)
            (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
          (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
          (br $again)))
        (local.get $acc)))"#;

    /// One native `wasm_indirect_observation` at `site` in function 3.
    fn indirect(seq: u64, site: u64, table: u64, slot: u64, resolution: u64, callee: u64) -> Value {
        let mut p = vec![0u8; 128];
        p[..4].copy_from_slice(&[1, 0, 128, 0]);
        for (at, value) in [
            (4, 3),
            (8, site),
            (12, table),
            (16, slot),
            (20, callee),
            (24, resolution),
        ] {
            put(&mut p, at, value, 4);
        }
        event("wasm_indirect_observation", seq, 0, MODULE, &p)
    }

    #[test]
    fn wasm_call_indirect_claims_compare_with_element_slots() {
        let bytes = wat::parse_str(INDIRECT).unwrap();
        let mut module = super::super::native_module::Module::parse(&bytes).unwrap();
        let sites = module.function(3).unwrap().call_indirects.clone();
        let sites = sites
            .keys()
            .map(|offset| u64::from(*offset))
            .collect::<Vec<_>>();
        let (placed, runtime) = (sites[0], sites[1]);
        let root = tempfile::tempdir().unwrap();
        let wasm = artifact(root.path(), MODULE, "wasm", &bytes, 0, 0);
        let events = [
            indirect(10, placed, 0, 0, 0, 0),
            indirect(11, placed, 0, 0, 0, 0),
            // The host replaced slot 1 at run time.
            indirect(12, placed, 0, 1, 0, 2),
            // Slot 2 is never placed by an element segment.
            indirect(13, placed, 0, 2, 0, 1),
            indirect(14, runtime, 1, 3, 0, 2),
            // Traps and foreign entries name no callee here.
            indirect(15, placed, 0, 9, 2, 0),
            indirect(16, runtime, 1, 0, 3, 0),
            // Never accepted: the wrong table for the site, and a callee
            // reported for a null entry.
            indirect(17, placed, 1, 0, 0, 0),
            indirect(18, placed, 0, 0, 1, 2),
        ];
        let workspace = analyze(root.path(), &[wasm], &events);
        assert_eq!(
            workspace["native_wasm_indirect_observation_count"], 7,
            "{workspace:#}"
        );
        let rows = workspace["native_wasm_indirect_observations"]
            .as_array()
            .unwrap();
        assert_eq!(rows[5]["resolution"], "out-of-bounds");
        assert!(rows[5]["callee_function_index"].is_null());
        assert!(
            omission(&workspace, "native-wasm-indirect-observation-invalid")
                .unwrap()
                .starts_with("Rejected 2 ")
        );
        let claims = workspace["observed_claims"].as_array().unwrap();
        let summary = claims
            .iter()
            .map(|c| {
                (
                    c["site"]["byte_offset"].as_u64().unwrap(),
                    c["selector"].as_u64().unwrap(),
                    c["handler"]["callee_function_index"].as_u64().unwrap(),
                    c["sample_count"].as_u64().unwrap(),
                    c["static_claim"]["state"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                (placed, 0, 0, 2, "agrees"),
                (placed, 1, 2, 1, "disagrees"),
                (placed, 2, 1, 1, "absent"),
                (runtime, 3, 2, 1, "withheld"),
            ]
        );
        for claim in claims {
            assert_eq!(claim["stream"], "native-wasm-indirect");
            assert_eq!(claim["confidence"], "observed");
            assert!(claim["opcode"].is_null());
        }
        assert_eq!(
            claims[1]["static_claim"],
            json!({"state":"disagrees","opcode":1,"handler_index":1,"byte_offset":placed})
        );
        assert_eq!(
            claims[3]["static_claim"],
            json!({"state":"withheld","opcode":3,"handler_index":null,"byte_offset":null})
        );
        assert_eq!(claims[3]["handler"]["table_index"], 1);
        assert!(
            omission(&workspace, "observed-claims-unresolved-callee")
                .unwrap()
                .starts_with("2 retained call_indirect observations name no callee")
        );
        assert!(workspace["unknowns"].as_array().unwrap().iter().any(|u| {
            u.as_str()
                .unwrap()
                .starts_with("1 observed dispatch claim disagrees")
        }));
        // The viewer recomputes each comparison against the listed element slots.
        let mut forged = document(root.path());
        forged["workspaces"][0]["observed_claims"][1]["static_claim"]["state"] = json!("agrees");
        assert!(!ui_accepts(&forged));
        let mut forged = document(root.path());
        forged["workspaces"][0]["observed_claims"][0]["static_claim"]["handler_index"] = json!(2);
        forged["workspaces"][0]["observed_claims"][0]["static_claim"]["state"] = json!("disagrees");
        assert!(!ui_accepts(&forged));
        let mut forged = document(root.path());
        forged["workspaces"][0]["observed_claims"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!ui_accepts(&forged), "every resolved row needs its claim");
    }

    /// Owned two-level interpreter. The outer loop masks each fetched byte to
    /// a selector, and its arm 2 runs a second interpreter over its own buffer.
    /// `route` is a one-shot router, never an interpreter.
    const NESTED: &str = r#"(module
      (memory 1)
      (func $inner (param $code i32) (param $len i32) (local $pc i32) (local $op i32)
        (block $exit (loop $dispatch
          (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
          (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
          (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
          (block $two (block $one (block $zero
            (br_table $zero $one $two $exit (local.get $op)))
            (br $dispatch)) (br $dispatch))
          (br $dispatch))))
      (func $outer (export "run") (param $code i32) (param $len i32) (local $pc i32) (local $op i32)
        (block $exit (loop $dispatch
          (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
          (local.set $op (i32.and (i32.load8_u (i32.add (local.get $code) (local.get $pc))) (i32.const 3)))
          (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
          (block $call (block $one (block $zero
            (br_table $zero $one $call $exit (local.get $op)))
            (br $dispatch)) (br $dispatch))
          (call $inner (i32.const 64) (i32.const 3))
          (br $dispatch))))
      (func $route (export "route") (param $k i32) (result i32)
        (block $b (block $a (br_table $a $b (local.get $k))) (return (i32.const 1)))
        (i32.const 2)))"#;

    struct Guest {
        root: tempfile::TempDir,
        artifacts: Vec<Value>,
        events: Vec<Value>,
    }

    /// Native guest records exactly as the reader admits them: one adapter per
    /// dispatch site, one invocation marker per activation, one snapshot per
    /// dispatch. Buffers: outer [1, 6, 3, 0] at 0, inner [0, 1, 3] at 64.
    fn guest() -> Guest {
        let bytes = wat::parse_str(NESTED).unwrap();
        let mut module = super::super::native_module::Module::parse(&bytes).unwrap();
        let site = |module: &mut super::super::native_module::Module<'_>, index| {
            let tables = &module.function(index).unwrap().br_tables;
            let (offset, count) = tables.iter().next().unwrap();
            (u64::from(*offset), u64::from(*count))
        };
        let (inner_site, inner_count) = site(&mut module, 0);
        let (outer_site, outer_count) = site(&mut module, 1);
        let (route_site, route_count) = site(&mut module, 2);
        let root = tempfile::tempdir().unwrap();
        let wasm = artifact(root.path(), MODULE, "wasm", &bytes, 0, 0);
        let mut artifacts = vec![wasm.clone()];
        let mut adapter = |id: u64, function: u64, offset: u64, creator: u64| {
            let recipe = json!({"version":1,"sample_limit":16,"module_sha256":wasm["sha256"],"function_index":function,
                "dispatch_module_offset":offset,"pc":{"local_index":2,"value_type":"i32","adjustment":"-1","subtract_memory_base":false},
                "bytecode":{"memory_index":0,"base":{"kind":"local","local_index":0,"value_type":"i32"},
                "length":{"kind":"local","local_index":1,"value_type":"i32"}},"opcode":{"width":1,"endian":"little"},"import_call_offsets":[]});
            let row = artifact(
                root.path(),
                id,
                "wasm_guest_adapter",
                &crate::vm::canonical(&recipe).unwrap(),
                MODULE,
                creator,
            );
            let sha = hex::decode(row["sha256"].as_str().unwrap()).unwrap();
            artifacts.push(row);
            sha
        };
        let outer_sha = adapter(MODULE + 1, 1, outer_site, 1);
        let inner_sha = adapter(MODULE + 2, 0, inner_site, 4);
        let invocation = |seq, function, invocation, adapter_id, parent, sha: &[u8]| {
            let mut p = vec![0u8; 128];
            p[..4].copy_from_slice(&[1, 0, 128, 0]);
            put(&mut p, 4, function, 4);
            put(&mut p, 8, 7, 8);
            put(&mut p, 16, invocation, 8);
            put(&mut p, 24, adapter_id, 8);
            p[32..64].copy_from_slice(sha);
            put(&mut p, 64, parent, 8);
            event("wasm_guest_invocation", seq, 0, MODULE, &p)
        };
        let mut events = vec![invocation(1, 1, 8, MODULE + 1, 0, &outer_sha)];
        let mut dispatch = |seq: u64,
                            parent,
                            function,
                            (offset, count): (u64, u64),
                            invocation,
                            buffer: (u64, &[u8]),
                            pc: u64,
                            sha: &[u8]| {
            let opcode = u64::from(buffer.1[pc as usize]);
            let selector = if function == 1 { opcode & 3 } else { opcode };
            artifacts.push(artifact(
                root.path(),
                MODULE + 100 + seq,
                "bytecode_buffer",
                buffer.1,
                MODULE,
                seq,
            ));
            let mut p = vec![0u8; 128];
            p[..4].copy_from_slice(&[1, 0, 128, 0]);
            for (at, value, width) in [
                (4, function, 4),
                (8, offset, 4),
                (12, selector, 4),
                (16, count, 4),
                (20, seq, 4),
                (24, 7, 8),
                (32, invocation, 8),
                (40, pc, 8),
                (48, pc + 1, 8),
                (56, MODULE + 100 + seq, 8),
                (64, buffer.0, 8),
                (72, buffer.1.len() as u64, 4),
                (76, 2, 4),
                (80, u64::MAX, 8),
                (88, 0, 4),
                (92, opcode, 4),
            ] {
                put(&mut p, at, value, width);
            }
            p[96..].copy_from_slice(sha);
            event("wasm_guest_dispatch", seq, parent, MODULE, &p)
        };
        let outer_code: &[u8] = &[1, 6, 3, 0];
        let inner_code: &[u8] = &[0, 1, 3];
        let outer = (outer_site, outer_count);
        let inner = (inner_site, inner_count);
        events.push(dispatch(2, 1, 1, outer, 8, (0, outer_code), 0, &outer_sha));
        events.push(dispatch(3, 1, 1, outer, 8, (0, outer_code), 1, &outer_sha));
        events.push(invocation(4, 0, 9, MODULE + 2, 8, &inner_sha));
        events.push(dispatch(5, 4, 0, inner, 9, (64, inner_code), 0, &inner_sha));
        events.push(dispatch(6, 4, 0, inner, 9, (64, inner_code), 1, &inner_sha));
        events.push(dispatch(7, 1, 1, outer, 8, (0, outer_code), 2, &outer_sha));
        // A physical br_table execution at the one-shot router.
        let mut physical = vec![0u8; 128];
        physical[..4].copy_from_slice(&[1, 0, 128, 0]);
        put(&mut physical, 4, 2, 4);
        put(&mut physical, 8, route_site, 4);
        put(&mut physical, 16, route_count, 4);
        events.push(event("wasm_dispatch_observation", 8, 0, MODULE, &physical));
        Guest {
            root,
            artifacts,
            events,
        }
    }

    fn rerun(guest: &Guest) -> Value {
        analyze(guest.root.path(), &guest.artifacts, &guest.events)
    }

    #[test]
    fn wasm_observed_claims_keep_exact_sites_and_contradictions() {
        let guest = guest();
        let workspace = rerun(&guest);
        assert_eq!(workspace["native_guest_sample_count"], 5, "{workspace:#}");
        let claims = workspace["observed_claims"].as_array().unwrap();
        let rows = claims
            .iter()
            .map(|c| {
                (
                    c["site"]["function_index"].as_u64().unwrap(),
                    c["selector"].as_u64().unwrap(),
                    c["opcode"].as_u64().unwrap(),
                    c["handler"]["arm"].as_u64().unwrap(),
                    c["static_claim"]["state"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                (0, 0, 0, 0, "agrees"),
                (0, 1, 1, 1, "agrees"),
                (1, 1, 1, 1, "agrees"),
                (1, 2, 6, 2, "disagrees"),
                (1, 3, 3, 3, "absent")
            ]
        );
        let contradiction = &claims[3];
        assert_eq!(contradiction["stream"], "native-guest");
        assert_eq!(contradiction["site_attribution"], "exact");
        assert_eq!(
            contradiction["events"],
            json!([{"session_id":"41","process_id":41,"sequence_number":"3"}])
        );
        assert_eq!(contradiction["static_claim"]["opcode"], 2);
        assert_eq!(claims[4]["handler"]["is_default"], true);
        // The router's physical execution is retained but claims nothing.
        assert_eq!(workspace["native_wasm_observation_count"], 1);
        assert!(claims.iter().all(|c| c["stream"] == "native-guest"));
        assert!(
            omission(&workspace, "observed-claims-not-interpreter")
                .unwrap()
                .starts_with("1 retained native dispatch record is")
        );
        // Static arm rows keep their selector labels.
        let arm = workspace["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| {
                h["source"]["byte_offset"] == contradiction["site"]["byte_offset"]
                    && h["opcode"] == 2
            })
            .unwrap();
        assert_eq!(arm["state"], "observed");
    }

    #[test]
    fn nested_guest_links_inner_interpreter_to_outer_handler() {
        let mut guest = guest();
        let workspace = rerun(&guest);
        // The rendered UI acceptance shows this exact store.
        super::super::export_golden_evidence(guest.root.path(), "REB_VM_OBSERVED_EVIDENCE_OUTPUT");
        let nested = workspace["nested_guests"].as_array().unwrap();
        assert_eq!(nested.len(), 1, "{workspace:#}");
        let (outer, inner) = (&nested[0]["outer"], &nested[0]["inner"]);
        assert_eq!(nested[0]["confidence"], "observed");
        assert_eq!(
            (
                outer["function_index"].as_u64(),
                outer["invocation_id"].as_str()
            ),
            (Some(1), Some("8"))
        );
        assert_eq!(outer["dispatch_event"]["sequence_number"], "3");
        assert_eq!(
            (
                outer["selector"].as_u64(),
                outer["opcode"].as_u64(),
                outer["selected_arm"].as_u64()
            ),
            (Some(2), Some(6), Some(2))
        );
        assert_eq!(outer["basis"], "contiguous-sequence");
        assert_eq!(
            (
                inner["function_index"].as_u64(),
                inner["invocation_id"].as_str(),
                inner["memory_base"].as_str()
            ),
            (Some(0), Some("9"), Some("64"))
        );
        assert_eq!(
            inner["observed_opcodes"],
            json!([{"opcode":0,"sample_count":1},{"opcode":1,"sample_count":1}])
        );
        assert_eq!(inner["sample_count"], 2);
        assert!(omission(&workspace, "nested-guest-unproven").is_none());
        // A nested guest must name the inner rows it summarizes.
        let mut forged = document(guest.root.path());
        forged["workspaces"][0]["nested_guests"][0]["inner"]["invocation_id"] = json!("8");
        assert!(!ui_accepts(&forged));
        // A lost driving dispatch still links, but only to the nearest retained one.
        let saved = guest.events.remove(2);
        let workspace = rerun(&guest);
        let outer = &workspace["nested_guests"][0]["outer"];
        assert_eq!(
            (
                outer["dispatch_event"]["sequence_number"].as_str(),
                outer["basis"].as_str()
            ),
            (Some("2"), Some("nearest-retained"))
        );
        guest.events.insert(2, saved);
        // Another thread, or a parent this capture never retained, is not nesting.
        for change in ["thread", "parent"] {
            let mut guest = super::tests::guest();
            for event in &mut guest.events[3..6] {
                if change == "thread" {
                    event["thread_id"] = json!(6);
                } else if event["type"] == "wasm_guest_invocation" {
                    let mut p = hex::decode(event["payload"].as_str().unwrap()).unwrap();
                    put(&mut p, 64, 99, 8);
                    event["payload"] = json!(hex::encode(p));
                }
            }
            let workspace = rerun(&guest);
            assert_eq!(workspace["native_guest_sample_count"], 5, "{change}");
            assert!(workspace.get("nested_guests").is_none(), "{change}");
            assert!(
                omission(&workspace, "nested-guest-unproven")
                    .unwrap()
                    .starts_with("1 guest activation names"),
                "{change}"
            );
        }
    }

    /// Rewrites the inner invocation marker as version 2 naming `dispatch`.
    fn name_parent_dispatch(guest: &mut Guest, dispatch: u64) {
        let marker = &mut guest.events[3];
        assert_eq!(marker["type"], "wasm_guest_invocation");
        let mut p = hex::decode(marker["payload"].as_str().unwrap()).unwrap();
        p[0] = 2;
        put(&mut p, 72, dispatch, 8);
        marker["payload"] = json!(hex::encode(p));
    }

    #[test]
    fn nested_guest_uses_the_exact_parent_dispatch_when_named() {
        let mut guest = guest();
        name_parent_dispatch(&mut guest, 3);
        let workspace = rerun(&guest);
        assert_eq!(workspace["native_guest_sample_count"], 5, "{workspace:#}");
        let outer = &workspace["nested_guests"][0]["outer"];
        assert_eq!(outer["dispatch_event"]["sequence_number"], "3");
        assert_eq!(outer["basis"], "exact-parent-dispatch");
        assert!(omission(&workspace, "nested-guest-unproven").is_none());
        // A named dispatch that is lost (3 removed), contradicted by a later
        // retained parent dispatch (2), or not a dispatch at all (1, the outer
        // marker) is unproven. It never falls back to the nearest retained guess.
        for named in [3, 2, 1] {
            let mut guest = super::tests::guest();
            name_parent_dispatch(&mut guest, named);
            if named == 3 {
                guest.events.remove(2);
            }
            let workspace = rerun(&guest);
            assert_eq!(
                workspace["native_guest_sample_count"],
                5 - u64::from(named == 3)
            );
            assert!(workspace.get("nested_guests").is_none(), "{named}");
            assert!(
                omission(&workspace, "nested-guest-unproven").is_some(),
                "{named}"
            );
        }
        // A version 2 parent without an exact dispatch keeps the sequence basis.
        let mut guest = super::tests::guest();
        name_parent_dispatch(&mut guest, 0);
        let outer = &rerun(&guest)["nested_guests"][0]["outer"];
        assert_eq!(outer["basis"], "contiguous-sequence");
        assert_eq!(outer["dispatch_event"]["sequence_number"], "3");
    }

    /// Rewrites the store as one live multi-site capture: a single version 2
    /// adapter names both dispatchers (site 0 the inner function 0, site 1 the
    /// outer function 1) and every marker is version 3 with its site.
    fn share_one_adapter(guest: &mut Guest) {
        let recipe = |id: u64| -> Value {
            let row = guest
                .artifacts
                .iter()
                .find(|a| a["artifact_id"] == id.to_string())
                .unwrap();
            serde_json::from_slice(&fs::read(guest.root.path().join(row["content_path"].as_str().unwrap())).unwrap())
                .unwrap()
        };
        let site = |mut r: Value| {
            let map = r.as_object_mut().unwrap();
            for key in ["version", "sample_limit", "module_sha256"] {
                map.remove(key);
            }
            r
        };
        let (outer, inner) = (recipe(MODULE + 1), recipe(MODULE + 2));
        let shared = json!({"version":2,"sample_limit":16,"module_sha256":outer["module_sha256"],
            "sites":[site(inner),site(outer)]});
        let row = artifact(
            guest.root.path(),
            MODULE + 1,
            "wasm_guest_adapter",
            &crate::vm::canonical(&shared).unwrap(),
            MODULE,
            1,
        );
        let sha = hex::decode(row["sha256"].as_str().unwrap()).unwrap();
        guest.artifacts.retain(|a| a["kind"] != "wasm_guest_adapter");
        guest.artifacts.push(row);
        for event in &mut guest.events {
            let mut p = hex::decode(event["payload"].as_str().unwrap()).unwrap();
            match event["type"].as_str() {
                Some("wasm_guest_invocation") => {
                    p[0] = 3;
                    put(&mut p, 24, MODULE + 1, 8);
                    p[32..64].copy_from_slice(&sha);
                    let function = u64::from(p[4]);
                    put(&mut p, 80, if function == 0 { 0 } else { 1 }, 4);
                }
                Some("wasm_guest_dispatch") => p[96..].copy_from_slice(&sha),
                _ => continue,
            }
            event["payload"] = json!(hex::encode(p));
        }
    }

    #[test]
    fn nested_guest_links_two_sites_of_one_adapter() {
        // The inner interpreter at site 0 names the outer interpreter's exact
        // current dispatch at site 1, as a live two-site capture writes it.
        let mut guest = guest();
        name_parent_dispatch(&mut guest, 3);
        share_one_adapter(&mut guest);
        let workspace = rerun(&guest);
        assert_eq!(workspace["native_guest_sample_count"], 5, "{workspace:#}");
        let nested = workspace["nested_guests"].as_array().unwrap();
        assert_eq!(nested.len(), 1, "{workspace:#}");
        let (outer, inner) = (&nested[0]["outer"], &nested[0]["inner"]);
        assert_eq!(
            (
                outer["function_index"].as_u64(),
                outer["invocation_id"].as_str(),
                outer["dispatch_event"]["sequence_number"].as_str(),
                outer["basis"].as_str()
            ),
            (Some(1), Some("8"), Some("3"), Some("exact-parent-dispatch"))
        );
        assert_eq!(
            (inner["function_index"].as_u64(), inner["sample_count"].as_u64()),
            (Some(0), Some(2))
        );
        assert!(omission(&workspace, "nested-guest-unproven").is_none());
        // A marker naming the other site of the same adapter is refused, so the
        // inner rows are not retained and nothing is linked.
        let mut wrong = super::tests::guest();
        name_parent_dispatch(&mut wrong, 3);
        share_one_adapter(&mut wrong);
        let marker = &mut wrong.events[3];
        let mut p = hex::decode(marker["payload"].as_str().unwrap()).unwrap();
        put(&mut p, 80, 1, 4);
        marker["payload"] = json!(hex::encode(p));
        let workspace = rerun(&wrong);
        assert_eq!(workspace["native_guest_sample_count"], 3);
        assert!(workspace.get("nested_guests").is_none());
    }

    /// The OpenAPI component carries the same definitions without descriptions.
    #[test]
    fn observed_contract_copies_match_the_standalone_schema() {
        fn strip(value: &Value) -> Value {
            match value {
                Value::Object(map) => map
                    .iter()
                    .filter(|(k, _)| *k != "description")
                    .map(|(k, v)| (k.clone(), strip(v)))
                    .collect(),
                Value::Array(items) => items.iter().map(strip).collect(),
                other => other.clone(),
            }
        }
        let standalone: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        let openapi: Value =
            serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap();
        let copy = &openapi["components"]["schemas"]["VmOpcodeWorkspace"]["$defs"];
        let rewrite = |value: &Value| -> Value {
            serde_json::from_str(&serde_json::to_string(&strip(value)).unwrap().replace(
                "\"#/$defs/",
                "\"#/components/schemas/VmOpcodeWorkspace/$defs/",
            ))
            .unwrap()
        };
        for name in ["observedClaim", "nestedGuest"] {
            assert_eq!(copy[name], rewrite(&standalone["$defs"][name]), "{name}");
        }
        for field in ["observed_claims", "nested_guests"] {
            let path = |defs: &Value| defs["workspace"]["properties"][field].clone();
            assert_eq!(path(copy), rewrite(&path(&standalone["$defs"])), "{field}");
        }
    }
}
