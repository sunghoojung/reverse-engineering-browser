//! Physical native Wasm observations, never inferred guest ISA or guest-PC samples.
use super::native_module::Module;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Observations {
    pub rows: Vec<Value>,
    pub count: u64,
    pub invalid: u64,
    /// Records for a module whose section structure did not decode. They are
    /// neither accepted nor rejected and stay visible as an omission.
    pub undecodable: u64,
    counts: BTreeMap<(u32, Option<u32>), u64>,
}

/// Envelope rules shared by both physical streams: exact artifact scope, no
/// parent event, and canonical native identities. A walked direct caller lives
/// in the dispatch payload. It is not parent_event_id.
fn envelope(event: &Value, artifact: &Value) -> bool {
    !(event["protocol_version"] != 3
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || event["payload_truncated"] != false
        || ["artifact_id", "session_id", "navigation_id", "frame_id"]
            .iter()
            .any(|key| event[*key] != artifact[*key])
        || event.get("dispatch_provenance").is_some()
        || event["parent_event_id"] != "0"
        || event["flags"].as_u64().is_none_or(|v| v != 0)
        || event["thread_id"]
            .as_u64()
            .is_none_or(|v| v == 0 || v > u32::MAX as u64)
        || !crate::evidence::canonical(&event["monotonic_time_ns"], 64, true)
        || !crate::evidence::canonical(&event["frame_id"], 64, true)
        || !crate::evidence::canonical(&event["artifact_id"], 64, true))
}

const LIMIT: u32 = 16 * 1024 * 1024;
const RESOLUTIONS: [&str; 5] = ["resolved", "null", "out-of-bounds", "foreign", "unresolved"];

struct DispatchPayload {
    function_index: u32,
    module_byte_offset: u32,
    selector: u32,
    table_count: u32,
    sample_index: u32,
    js_invocation_state: u8,
    js_invocation_id: u32,
    /// `None` on payload versions 1 and 2: those bytes were reserved, so the
    /// caller was not observed. Version 3 always sets this.
    direct_caller: Option<DirectCaller>,
}

#[derive(Clone, Copy)]
enum DirectCaller {
    Unknown,
    SameInstance(u32),
}

fn direct_caller_value(caller: DirectCaller) -> Value {
    match caller {
        DirectCaller::Unknown => json!({"kind":"unknown","function_index":null}),
        DirectCaller::SameInstance(index) => {
            json!({"kind":"same-instance","function_index":index})
        }
    }
}

struct IndirectPayload {
    function_index: u32,
    module_byte_offset: u32,
    table_index: u32,
    slot: u32,
    callee_function_index: u32,
    resolution: &'static str,
    sample_index: u32,
    js_invocation_state: u8,
    js_invocation_id: u32,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed payload"))
}

/// Little-endian version of a 128-byte observation whose size field is 128.
/// Indirect observations know versions 1 and 2. Dispatch version 3 is decoded
/// by `decode_dispatch_payload` and is not a version-2 prefix: a zero caller
/// there is unknown, which versions 1 and 2 do not record.
fn supported_observation_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 128 {
        return None;
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    let size = u16::from_le_bytes([bytes[2], bytes[3]]);
    (size == 128 && matches!(version, 1 | 2)).then_some(version)
}

/// Field map of a `wasm_dispatch_observation` payload. The opcode workspace and
/// event queries both use this function, so the offsets stay in one place.
/// `None` rejects the bytes: unknown version, nonzero reserved bytes, a broken
/// invocation context, or a bound the wire contract refuses. No module is read.
fn decode_dispatch_payload(bytes: &[u8]) -> Option<DispatchPayload> {
    if bytes.len() != 128 {
        return None;
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    let size = u16::from_le_bytes([bytes[2], bytes[3]]);
    if size != 128 || !matches!(version, 1..=3) {
        return None;
    }
    // Version 2 stores the JavaScript invocation context at bytes 24..32.
    // Version 1 reserved those bytes and decodes as not observed.
    let (state, invocation) = crate::js_invocation::wasm_context(bytes, 2, 24)?;
    let direct_caller = if version < 3 {
        if bytes[32..].iter().any(|byte| *byte != 0) {
            return None;
        }
        None
    } else if bytes[33..36].iter().any(|byte| *byte != 0)
        || bytes[40..].iter().any(|byte| *byte != 0)
    {
        return None;
    } else {
        let index = u32_at(bytes, 36);
        match bytes[32] {
            0 if index == 0 => Some(DirectCaller::Unknown),
            1 if index < LIMIT => Some(DirectCaller::SameInstance(index)),
            _ => return None,
        }
    };
    let fields = DispatchPayload {
        function_index: u32_at(bytes, 4),
        module_byte_offset: u32_at(bytes, 8),
        selector: u32_at(bytes, 12),
        table_count: u32_at(bytes, 16),
        sample_index: u32_at(bytes, 20),
        js_invocation_state: state,
        js_invocation_id: invocation,
        direct_caller,
    };
    (fields.function_index < LIMIT
        && (8..LIMIT).contains(&fields.module_byte_offset)
        && fields.table_count < LIMIT
        && fields.sample_index < 16)
        .then_some(fields)
}

/// Field map of a `wasm_indirect_observation` payload. Same rejection rules as
/// `decode_dispatch_payload`, plus an unknown resolution or a callee on an
/// entry that did not resolve. `resolution` is the enum name.
fn decode_indirect_payload(bytes: &[u8]) -> Option<IndirectPayload> {
    supported_observation_version(bytes)?;
    // Version 2 stores the JavaScript invocation context at bytes 32..40.
    let (state, invocation) = crate::js_invocation::wasm_context(bytes, 2, 32)?;
    if bytes[40..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let resolution = *RESOLUTIONS.get(u32_at(bytes, 24) as usize)?;
    let fields = IndirectPayload {
        function_index: u32_at(bytes, 4),
        module_byte_offset: u32_at(bytes, 8),
        table_index: u32_at(bytes, 12),
        slot: u32_at(bytes, 16),
        callee_function_index: u32_at(bytes, 20),
        resolution,
        sample_index: u32_at(bytes, 28),
        js_invocation_state: state,
        js_invocation_id: invocation,
    };
    let resolved = fields.resolution == "resolved";
    (fields.function_index < LIMIT
        && (8..LIMIT).contains(&fields.module_byte_offset)
        && fields.table_index < LIMIT
        && fields.callee_function_index < LIMIT
        && fields.sample_index < 16
        && (resolved || fields.callee_function_index == 0))
        .then_some(fields)
}

fn observation(event: &Value, artifact: &Value, module: &mut Module<'_>) -> Option<Value> {
    if !envelope(event, artifact) {
        return None;
    }
    let bytes = super::event_payload_versions(event, "wasm_dispatch_observation", &[1, 2, 3])?;
    let fields = decode_dispatch_payload(&bytes)?;
    if module.function(fields.function_index).is_none_or(|facts| {
        facts.br_tables.get(&fields.module_byte_offset) != Some(&fields.table_count)
    }) {
        return None;
    }
    if let Some(DirectCaller::SameInstance(index)) = fields.direct_caller
        && index as usize >= module.function_count()
    {
        return None;
    }
    let mut row = json!({"event":super::event_reference(event),"monotonic_time_ns":event["monotonic_time_ns"],"function_index":fields.function_index,"module_byte_offset":fields.module_byte_offset,
        "selector":fields.selector,"table_count":fields.table_count,"sample_index":fields.sample_index,"selected_arm":fields.selector.min(fields.table_count),"is_default":fields.selector >= fields.table_count});
    if let Some(context) =
        crate::js_invocation::context_row(fields.js_invocation_state, fields.js_invocation_id)
    {
        row["js_invocation"] = context;
    }
    if let Some(caller) = fields.direct_caller {
        row["direct_caller"] = direct_caller_value(caller);
    }
    Some(row)
}

pub(super) fn collect(
    artifact: &Value,
    mut module: Option<&mut Module<'_>>,
    events: &[Value],
) -> Observations {
    let mut output = Observations::default();
    if artifact["kind"] != "wasm" {
        return output;
    }
    // The caller verified the artifact digest and deduplicated event identities.
    for event in events.iter().filter(|e| {
        e["type"] == "wasm_dispatch_observation" && e["artifact_id"] == artifact["artifact_id"]
    }) {
        let Some(module) = module.as_deref_mut() else {
            output.undecodable += 1;
            continue;
        };
        let Some(row) = observation(event, artifact, module) else {
            output.invalid += 1;
            continue;
        };
        output.count += 1;
        let offset = row["module_byte_offset"].as_u64().expect("offset") as u32;
        let selector = (!row["is_default"].as_bool().expect("default"))
            .then(|| row["selector"].as_u64().expect("selector") as u32);
        *output.counts.entry((offset, selector)).or_default() += 1;
        if output.rows.len() < super::MAX_SAMPLES {
            output.rows.push(row);
        }
    }
    output
}

/// Accepted call_indirect observations. Only `resolved` names a callee in
/// this module's function index space.
#[derive(Default)]
pub(super) struct IndirectObservations {
    pub rows: Vec<Value>,
    pub count: u64,
    pub invalid: u64,
    pub undecodable: u64,
}

fn indirect_observation(event: &Value, artifact: &Value, module: &mut Module<'_>) -> Option<Value> {
    if !envelope(event, artifact) {
        return None;
    }
    let bytes = super::event_payload_versions(event, "wasm_indirect_observation", &[1, 2])?;
    let fields = decode_indirect_payload(&bytes)?;
    let resolved = fields.resolution == "resolved";
    if resolved && fields.callee_function_index as usize >= module.function_count() {
        return None;
    }
    let &(site_table, tail) = module
        .function(fields.function_index)?
        .call_indirects
        .get(&fields.module_byte_offset)?;
    if site_table != fields.table_index {
        return None;
    }
    let mut row = json!({"event":super::event_reference(event),"monotonic_time_ns":event["monotonic_time_ns"],
        "function_index":fields.function_index,"module_byte_offset":fields.module_byte_offset,
        "instruction":if tail {"return_call_indirect"} else {"call_indirect"},"table_index":fields.table_index,"slot":fields.slot,
        "resolution":fields.resolution,"callee_function_index":resolved.then_some(fields.callee_function_index),"sample_index":fields.sample_index});
    if let Some(context) =
        crate::js_invocation::context_row(fields.js_invocation_state, fields.js_invocation_id)
    {
        row["js_invocation"] = context;
    }
    Some(row)
}

/// Decoded `wasm_observation` for an event query. `None` means the record is
/// not a complete observation; the caller reports that as invalid and does not
/// fill any field. This does not open a module or an opcode workspace. The
/// envelope checks are the ones C++, Python and JavaScript apply before the
/// payload: these records are protocol 3, category `vm`, and flags 0.
pub(super) fn query_observation(event: &Value) -> Option<Value> {
    if event["protocol_version"] != 3
        || event["category"] != "vm"
        || event["flags"].as_u64() != Some(0)
        || event["payload_encoding"] != "hex"
        || event["payload_size"] != 128
        || event["payload_truncated"] != false
    {
        return None;
    }
    let text = event["payload"].as_str()?;
    if text.len() != 256 {
        return None;
    }
    let bytes = hex::decode(text).ok()?;
    match event["type"].as_str()? {
        "wasm_dispatch_observation" => decode_dispatch_payload(&bytes).map(|fields| {
            let mut row = json!({"status":"decoded","function_index":fields.function_index,"module_byte_offset":fields.module_byte_offset,
                "selector":fields.selector,"table_count":fields.table_count,"sample_index":fields.sample_index,
                "js_invocation_state":fields.js_invocation_state,"js_invocation_id":fields.js_invocation_id});
            if let Some(caller) = fields.direct_caller {
                row["direct_caller"] = direct_caller_value(caller);
            }
            row
        }),
        "wasm_indirect_observation" => decode_indirect_payload(&bytes).map(|fields| {
            json!({"status":"decoded","function_index":fields.function_index,"module_byte_offset":fields.module_byte_offset,
                "table_index":fields.table_index,"slot":fields.slot,"callee_function_index":fields.callee_function_index,
                "resolution":fields.resolution,"sample_index":fields.sample_index,
                "js_invocation_state":fields.js_invocation_state,"js_invocation_id":fields.js_invocation_id})
        }),
        _ => None,
    }
}

/// Decoded `wasm_overflow` for an event query. `None` means the record is not
/// a valid compact identity; the caller reports that as invalid and does not
/// fill any field. This does not open a module. Artifact id and parent event
/// id must be zero: this record does not invent either.
pub(super) fn query_overflow(event: &Value) -> Option<Value> {
    let indirect = event["type"] == "wasm_indirect_overflow";
    if event["type"] != "wasm_dispatch_overflow" && !indirect {
        return None;
    }
    let size = if indirect { 40 } else { 32 };
    if event["protocol_version"] != 3
        || event["category"] != "vm"
        || event["flags"].as_u64() != Some(0)
        || event["payload_encoding"] != "hex"
        || event["payload_size"] != size
        || event["payload_truncated"] != false
        || event["artifact_id"] != "0"
        || event["parent_event_id"] != "0"
    {
        return None;
    }
    let text = event["payload"].as_str()?;
    if text.len() != size * 2 {
        return None;
    }
    let bytes = hex::decode(text).ok()?;
    if bytes.len() != size
        || u16::from_le_bytes(bytes[0..2].try_into().ok()?) != 1
        || u16::from_le_bytes(bytes[2..4].try_into().ok()?) != size as u16
        || bytes[5] != 0
    {
        return None;
    }
    if indirect {
        if u64::from_le_bytes(bytes[32..40].try_into().ok()?) != 0 {
            return None;
        }
    } else if u32::from_le_bytes(bytes[28..32].try_into().ok()?) != 0 {
        return None;
    }
    let record_kind = bytes[4];
    let ring = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let omitted_at = if indirect { 28 } else { 24 };
    let omitted = u32::from_le_bytes(bytes[omitted_at..omitted_at + 4].try_into().ok()?);
    if record_kind == 2 {
        if ring != 0 || omitted == 0 || bytes[8..omitted_at].iter().any(|byte| *byte != 0) {
            return None;
        }
        return Some(json!({"status":"decoded","kind":"omitted","omitted_count":omitted}));
    }
    let limit = 16 * 1024 * 1024;
    let function = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let offset = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    if record_kind != 1
        || omitted != 0
        || ring >= 32
        || function >= limit
        || !(8..limit).contains(&offset)
    {
        return None;
    }
    if !indirect {
        let selector = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let arms = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        if arms >= limit {
            return None;
        }
        return Some(
            json!({"status":"decoded","kind":"identity","ring_index":ring,
            "function_index":function,"module_byte_offset":offset,"selector":selector,"arm_count":arms}),
        );
    }
    let table = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
    let slot = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let resolution = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
    let name =
        ["resolved", "null", "out-of-bounds", "foreign", "unresolved"].get(resolution as usize)?;
    if table >= limit {
        return None;
    }
    Some(
        json!({"status":"decoded","kind":"identity","ring_index":ring,"function_index":function,
        "module_byte_offset":offset,"table_index":table,"slot":slot,"resolution":name}),
    )
}

pub(super) fn collect_indirect(
    artifact: &Value,
    mut module: Option<&mut Module<'_>>,
    events: &[Value],
) -> IndirectObservations {
    let mut output = IndirectObservations::default();
    if artifact["kind"] != "wasm" {
        return output;
    }
    // The caller verified the artifact digest and deduplicated event identities.
    for event in events.iter().filter(|e| {
        e["type"] == "wasm_indirect_observation" && e["artifact_id"] == artifact["artifact_id"]
    }) {
        let Some(module) = module.as_deref_mut() else {
            output.undecodable += 1;
            continue;
        };
        let Some(row) = indirect_observation(event, artifact, module) else {
            output.invalid += 1;
            continue;
        };
        output.count += 1;
        if output.rows.len() < super::MAX_SAMPLES {
            output.rows.push(row);
        }
    }
    output
}

impl Observations {
    pub fn attach(&self, handlers: &mut [Value]) {
        for handler in handlers {
            let Some(offset) = handler["source"]["byte_offset"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
            else {
                continue;
            };
            let selector = handler["opcode"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok());
            if selector.is_none()
                && !handler["label"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("br_table ") && v.ends_with("default"))
            {
                continue;
            }
            if let Some(count) = self.counts.get(&(offset, selector)) {
                handler["native_wasm_sample_count"] = json!(count);
                handler["state"] = json!("observed");
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn module() -> Vec<u8> {
        hex::decode("0061736d010000000104016000000302010005030100010a1d011b01017f0340200041016a210041002d00001a41000e020000000b0b").unwrap()
    }
    /// Owned handler-table loop: function 1 dispatches table 0, whose slots
    /// hold functions 0 and 2. The C++ golden producer names its site.
    pub(crate) const INDIRECT_MODULE: &str = r#"(module (memory 1)
      (type $t (func (param i32) (result i32)))
      (table 2 funcref)
      (func $inc (type $t) (i32.add (local.get 0) (i32.const 1)))
      (func (export "run") (param $code i32) (param $len i32) (result i32)
        (local $pc i32) (local $acc i32)
        (block $exit (loop $again
          (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
          (local.set $acc (call_indirect (type $t) (local.get $acc)
            (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
          (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
          (br $again)))
        (local.get $acc))
      (func $dbl (type $t) (i32.shl (local.get 0) (i32.const 1)))
      (elem (i32.const 0) func $inc $dbl))"#;
    const INDIRECT_SITE: u32 = 94;
    fn indirect_event(slot: u32, resolution: u32, callee: u32) -> Value {
        let mut bytes = [0u8; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        for (at, value) in [
            (4, 1),
            (8, INDIRECT_SITE),
            (16, slot),
            (20, callee),
            (24, resolution),
        ] {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut event = event(0);
        event["type"] = json!("wasm_indirect_observation");
        event["payload"] = json!(hex::encode(bytes));
        event
    }
    #[test]
    fn native_wasm_indirect_exact_site_table_and_callee() {
        let bytes = wat::parse_str(INDIRECT_MODULE).unwrap();
        let event = indirect_event(1, 0, 2);
        let scope = artifact(&event);
        let read =
            |events: &[Value]| collect_indirect(&scope, Module::parse(&bytes).as_mut(), events);
        let output = read(std::slice::from_ref(&event));
        assert_eq!((output.count, output.invalid), (1, 0));
        let row = &output.rows[0];
        assert_eq!(row["instruction"], "call_indirect");
        assert_eq!(
            (row["table_index"].clone(), row["slot"].clone()),
            (json!(0), json!(1))
        );
        assert_eq!(
            (
                row["resolution"].clone(),
                row["callee_function_index"].clone()
            ),
            (json!("resolved"), json!(2))
        );
        let trap = read(&[indirect_event(u32::MAX, 2, 0)]);
        assert_eq!(trap.rows[0]["resolution"], "out-of-bounds");
        assert!(trap.rows[0]["callee_function_index"].is_null());
        // Wrong table, a non-site offset, a callee on a null entry, an unknown
        // resolution, a callee past the function space, the sample budget and
        // a reserved byte are each rejected.
        for (offset, value) in [
            (12, 1u32),
            (8, INDIRECT_SITE - 1),
            (24, 1),
            (24, 5),
            (20, 3),
            (28, 16),
            (32, 1),
        ] {
            let mut bad = event.clone();
            let mut payload = hex::decode(bad["payload"].as_str().unwrap()).unwrap();
            payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            bad["payload"] = json!(hex::encode(payload));
            assert_eq!(read(&[bad]).invalid, 1, "payload offset {offset}");
        }
        for field in ["session_id", "navigation_id", "frame_id"] {
            let mut bad = event.clone();
            bad[field] = json!("2");
            assert_eq!(read(&[bad]).invalid, 1, "{field}");
        }
        let output = collect_indirect(&artifact(&event), None, std::slice::from_ref(&event));
        assert_eq!((output.count, output.undecodable), (0, 1));
    }
    fn read(artifact: &Value, bytes: &[u8], events: &[Value]) -> Observations {
        collect(artifact, Module::parse(bytes).as_mut(), events)
    }
    fn leb(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            out.push(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                break;
            }
        }
    }
    /// The `module()` fixture with `nops` extra instructions before its loop.
    /// Returns the module and the module byte offset of its br_table.
    pub(crate) fn padded_module(nops: usize) -> (Vec<u8>, u32) {
        let original = module();
        let mut body = vec![1, 1, 0x7f];
        body.extend(std::iter::repeat_n(0x01, nops));
        body.extend_from_slice(&original[30..]);
        let mut entry = Vec::new();
        leb(body.len(), &mut entry);
        let site_in_entry = entry.len() + 3 + nops + 17;
        entry.extend_from_slice(&body);
        let mut section = vec![1];
        let site_in_section = section.len() + site_in_entry;
        section.extend_from_slice(&entry);
        let mut bytes = original[..23].to_vec();
        bytes.push(0x0a);
        leb(section.len(), &mut bytes);
        let site = bytes.len() + site_in_section;
        bytes.extend_from_slice(&section);
        assert_eq!(bytes[site], 0x0e);
        (bytes, site as u32)
    }
    fn artifact(event: &Value) -> Value {
        json!({"kind":"wasm","artifact_id":event["artifact_id"],"session_id":event["session_id"],"navigation_id":event["navigation_id"],"frame_id":event["frame_id"]})
    }
    pub(crate) fn event(selector: u32) -> Value {
        let mut bytes = [0u8; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        bytes[8..12].copy_from_slice(&47u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&selector.to_le_bytes());
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        json!({"protocol_version":3,"session_id":"1","sequence_number":"1","process_id":1,"thread_id":1,"monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"1","parent_event_id":"0","flags":0,"payload_size":128,"payload_encoding":"hex","payload_truncated":false,"category":"vm","type":"wasm_dispatch_observation","payload":hex::encode(bytes)})
    }
    #[test]
    fn overflow_identities_are_not_observations() {
        let mut event = event(0);
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[2] = 32;
        bytes[4] = 1;
        bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&47u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
        event["type"] = json!("wasm_dispatch_overflow");
        event["payload_size"] = json!(32);
        event["payload"] = json!(hex::encode(bytes));
        let scope = artifact(&event);
        let output = read(&scope, &module(), std::slice::from_ref(&event));
        assert_eq!((output.count, output.invalid, output.rows.len()), (0, 0, 0));
    }
    #[test]
    fn query_overflow_decodes_identities_and_rejects_an_artifact_id() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[2] = 32;
        bytes[4] = 1;
        bytes[6] = 3;
        bytes[8..12].copy_from_slice(&9u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&47u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1000u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
        let mut event = event(0);
        event["type"] = json!("wasm_dispatch_overflow");
        event["artifact_id"] = json!("0");
        event["payload_size"] = json!(32);
        event["payload"] = json!(hex::encode(bytes));
        assert_eq!(
            query_overflow(&event),
            Some(
                json!({"status":"decoded","kind":"identity","ring_index":3,"function_index":9,
                "module_byte_offset":47,"selector":1000,"arm_count":2})
            )
        );
        event["artifact_id"] = json!("1");
        assert!(query_overflow(&event).is_none());
        let mut events = vec![event];
        events[0]["artifact_id"] = json!("0");
        super::super::annotate_wasm_observations(&mut events);
        assert_eq!(events[0]["wasm_overflow"]["kind"], "identity");
        assert!(events[0].get("wasm_observation").is_none());
        events[0]["artifact_id"] = json!("1");
        super::super::annotate_wasm_observations(&mut events);
        assert_eq!(events[0]["wasm_overflow"], json!({"status":"invalid"}));
        let mut omitted = [0u8; 32];
        omitted[0] = 1;
        omitted[2] = 32;
        omitted[4] = 2;
        omitted[24..28].copy_from_slice(&4u32.to_le_bytes());
        events[0]["artifact_id"] = json!("0");
        events[0]["payload"] = json!(hex::encode(omitted));
        assert_eq!(
            query_overflow(&events[0]),
            Some(json!({"status":"decoded","kind":"omitted","omitted_count":4}))
        );
        let mut indirect = [0u8; 40];
        indirect[0] = 1;
        indirect[2] = 40;
        indirect[4] = 1;
        indirect[6] = 1;
        indirect[8..12].copy_from_slice(&4u32.to_le_bytes());
        indirect[12..16].copy_from_slice(&10u32.to_le_bytes());
        indirect[20..24].copy_from_slice(&5u32.to_le_bytes());
        indirect[24..28].copy_from_slice(&1u32.to_le_bytes());
        events[0]["type"] = json!("wasm_indirect_overflow");
        events[0]["payload_size"] = json!(40);
        events[0]["payload"] = json!(hex::encode(indirect));
        assert_eq!(
            query_overflow(&events[0]),
            Some(
                json!({"status":"decoded","kind":"identity","ring_index":1,"function_index":4,
                "module_byte_offset":10,"table_index":0,"slot":5,"resolution":"null"})
            )
        );
        events[0]["parent_event_id"] = json!("9");
        assert!(query_overflow(&events[0]).is_none());
    }
    #[test]
    fn native_wasm_exact_site_and_scope() {
        let event = event(u32::MAX);
        let artifact = artifact(&event);
        let output = read(&artifact, &module(), std::slice::from_ref(&event));
        assert_eq!(output.count, 1);
        assert_eq!(output.rows[0]["is_default"], true);
        assert_eq!(output.rows[0]["selected_arm"], 2);
        for field in [
            "payload_size",
            "payload_encoding",
            "payload_truncated",
            "protocol_version",
            "thread_id",
            "monotonic_time_ns",
            "parent_event_id",
            "flags",
        ] {
            for value in [None, Some(Value::Null), Some(json!([]))] {
                let mut bad = event.clone();
                if let Some(value) = value {
                    bad[field] = value;
                } else {
                    bad.as_object_mut().unwrap().remove(field);
                }
                assert_eq!(read(&artifact, &module(), &[bad]).count, 0, "field {field}");
            }
        }
        for field in ["session_id", "navigation_id", "frame_id"] {
            let mut bad = event.clone();
            bad[field] = json!("2");
            assert_eq!(read(&artifact, &module(), &[bad]).count, 0);
        }
        for (offset, value) in [(4, 1u32), (8, 46), (16, 3), (20, 16), (24, 1)] {
            let mut bad = event.clone();
            let mut bytes = hex::decode(bad["payload"].as_str().unwrap()).unwrap();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            bad["payload"] = json!(hex::encode(bytes));
            assert_eq!(read(&artifact, &module(), &[bad]).count, 0);
        }
        let mut handlers = vec![
            json!({"source":{"byte_offset":47},"opcode":null,"label":"br_table default","sample_count":0}),
            json!({"source":{"byte_offset":70},"opcode":null,"label":"br_table default","sample_count":0}),
        ];
        output.attach(&mut handlers);
        assert_eq!(handlers[0]["native_wasm_sample_count"], 1);
        assert_eq!(handlers[0]["sample_count"], 0);
        assert!(handlers[1].get("native_wasm_sample_count").is_none());
    }
    #[test]
    fn native_wasm_imported_function_index_and_retention() {
        let original = module();
        let mut bytes = original[..14].to_vec();
        bytes.extend_from_slice(&[2, 7, 1, 1, b'm', 1, b'f', 0, 0]);
        bytes.extend_from_slice(&original[14..]);
        let mut index = Module::parse(&bytes).unwrap();
        assert_eq!(index.function(1).unwrap().br_tables.get(&56), Some(&2));
        assert!(index.function(0).is_none(), "imported function has no body");
        let mut event = event(0);
        let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        payload[8..12].copy_from_slice(&56u32.to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let artifact = artifact(&event);
        assert_eq!(
            read(&artifact, &bytes, std::slice::from_ref(&event)).count,
            1
        );
        payload[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut wrong = event.clone();
        wrong["payload"] = json!(hex::encode(payload));
        assert_eq!(read(&artifact, &bytes, &[wrong]).count, 0);
        let events = (1..=4097)
            .map(|i| {
                let mut event = event.clone();
                event["sequence_number"] = json!(i.to_string());
                event
            })
            .collect::<Vec<_>>();
        let output = read(&artifact, &bytes, &events);
        assert_eq!(output.count, 4097);
        assert_eq!(output.rows.len(), 4096);
    }
    // Modules are bounded by the 16 MiB artifact limit, not by an
    // instruction count that silently discards every record.
    #[test]
    fn native_wasm_large_module_keeps_exact_site_observations() {
        let (bytes, site) = padded_module(1_000_001);
        assert_eq!(padded_module(0), (module(), 47));
        let mut event = event(0);
        let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        payload[8..12].copy_from_slice(&site.to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let artifact = artifact(&event);
        let output = read(&artifact, &bytes, std::slice::from_ref(&event));
        assert_eq!((output.count, output.invalid), (1, 0));
        payload[8..12].copy_from_slice(&(site - 1).to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let output = read(&artifact, &bytes, std::slice::from_ref(&event));
        assert_eq!(
            (output.count, output.invalid),
            (0, 1),
            "a nop is not a site"
        );
        let output = collect(&artifact, None, std::slice::from_ref(&event));
        assert_eq!(
            (output.count, output.invalid, output.undecodable),
            (0, 0, 1),
            "an undecodable module is reported, not dropped"
        );
    }
    #[test]
    fn native_wasm_direct_caller_names_the_calling_function() {
        let bytes = wat::parse_str(
            r#"(module
                (func (result i32) (call 1))
                (func (result i32)
                  (block (result i32)
                    (br_table 0 0 (i32.const 0)))))"#,
        )
        .unwrap();
        let mut parsed = Module::parse(&bytes).unwrap();
        assert_eq!(parsed.function_count(), 2);
        let (offset, count) = parsed
            .function(1)
            .unwrap()
            .br_tables
            .iter()
            .map(|(site, arms)| (*site, *arms))
            .next()
            .unwrap();
        let event = |version: u8, kind: u8, caller: u32, sequence: &str| {
            let mut payload = [0u8; 128];
            payload[0] = version;
            payload[2] = 128;
            payload[4..8].copy_from_slice(&1u32.to_le_bytes());
            payload[8..12].copy_from_slice(&offset.to_le_bytes());
            payload[16..20].copy_from_slice(&count.to_le_bytes());
            payload[32] = kind;
            payload[36..40].copy_from_slice(&caller.to_le_bytes());
            json!({"protocol_version":3,"session_id":"1","sequence_number":sequence,"process_id":1,"thread_id":1,"monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"1","parent_event_id":"0","flags":0,"payload_size":128,"payload_encoding":"hex","payload_truncated":false,"category":"vm","type":"wasm_dispatch_observation","payload":hex::encode(payload)})
        };
        let artifact = artifact(&event(3, 1, 0, "1"));
        let same = event(3, 1, 0, "1");
        let output = read(&artifact, &bytes, std::slice::from_ref(&same));
        assert_eq!(output.count, 1);
        assert_eq!(output.rows[0]["function_index"], 1);
        assert_eq!(
            output.rows[0]["direct_caller"],
            json!({"kind":"same-instance","function_index":0})
        );
        assert_eq!(same["parent_event_id"], "0");
        let unknown = event(3, 0, 0, "2");
        let output = read(&artifact, &bytes, std::slice::from_ref(&unknown));
        assert_eq!(
            output.rows[0]["direct_caller"],
            json!({"kind":"unknown","function_index":null})
        );
        let unwalked = event(1, 0, 0, "3");
        let output = read(&artifact, &bytes, std::slice::from_ref(&unwalked));
        assert!(output.rows[0].get("direct_caller").is_none());
        for (version, kind, caller) in [(3u8, 0u8, 1u32), (3, 1, 2), (3, 2, 0), (2, 1, 0)] {
            let bad = event(version, kind, caller, "4");
            assert_eq!(
                read(&artifact, &bytes, std::slice::from_ref(&bad)).count,
                0,
                "version {version} kind {kind} caller {caller}"
            );
        }
        let both = [event(3, 1, 0, "5"), event(3, 1, 1, "6")];
        let output = read(&artifact, &bytes, &both);
        assert_eq!(output.count, 2);
        assert_eq!(output.rows[0]["direct_caller"]["function_index"], 0);
        assert_eq!(output.rows[1]["direct_caller"]["function_index"], 1);
        let imported = wat::parse_str(
            r#"(module
                (import "m" "f" (func))
                (func (result i32)
                  (block (result i32)
                    (br_table 0 0 (i32.const 0)))))"#,
        )
        .unwrap();
        let mut imported_module = Module::parse(&imported).unwrap();
        assert!(imported_module.function(0).is_none());
        assert_eq!(imported_module.function_count(), 2);
        let (import_offset, import_count) = imported_module
            .function(1)
            .unwrap()
            .br_tables
            .iter()
            .map(|(site, arms)| (*site, *arms))
            .next()
            .unwrap();
        let mut payload = [0u8; 128];
        payload[0] = 3;
        payload[2] = 128;
        payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        payload[8..12].copy_from_slice(&import_offset.to_le_bytes());
        payload[16..20].copy_from_slice(&import_count.to_le_bytes());
        payload[32] = 1;
        let mut import_event = event(3, 1, 0, "7");
        import_event["payload"] = json!(hex::encode(payload));
        let output = read(&artifact, &imported, std::slice::from_ref(&import_event));
        assert_eq!(output.count, 1, "an imported function is a real caller");
        assert_eq!(
            output.rows[0]["direct_caller"],
            json!({"kind":"same-instance","function_index":0})
        );
    }
    #[test]
    #[ignore = "requires actual C++ producer; make check supplies REB_NATIVE_WASM_GOLDEN"]
    fn native_wasm_cpp_golden() {
        let exe = std::env::var("REB_NATIVE_WASM_GOLDEN").expect("actual C++ producer required");
        for case in [
            "default",
            "arm",
            "wide-identities",
            "envelope-version",
            "reserved",
            "version",
            "size",
            "truncated",
            "big-endian",
            "sample-index",
            "offset",
            "function",
            "count",
            "flags",
            "parent",
            "identity",
            "legacy-v1",
            "invocation",
            "invocation-legacy",
            "invocation-mismatch",
            "caller-same-instance",
            "caller-unknown",
            "caller-unknown-index",
            "caller-kind",
            "caller-v2",
        ] {
            let process = std::process::Command::new(&exe)
                .args(["--case", case])
                .output()
                .expect("run C++ producer");
            assert!(
                process.status.success(),
                "C++ case {case}: {}",
                String::from_utf8_lossy(&process.stderr)
            );
            let event: Value = serde_json::from_slice(&process.stdout).expect("EventToJson output");
            let output = read(&artifact(&event), &module(), std::slice::from_ref(&event));
            let accepted = matches!(
                case,
                "default"
                    | "arm"
                    | "wide-identities"
                    | "legacy-v1"
                    | "invocation"
                    | "caller-same-instance"
                    | "caller-unknown"
            );
            assert_eq!(output.count, u64::from(accepted), "C++ case {case}");
            if accepted {
                // Version 2 names the JavaScript invocation the instruction ran
                // in; version 1 and not-observed records omit the field.
                assert_eq!(
                    output.rows[0].get("js_invocation"),
                    (case == "invocation")
                        .then(|| json!({"state":"inside","invocation_id":"7"}))
                        .as_ref(),
                    "C++ case {case}"
                );
                let caller = match case {
                    "caller-same-instance" => {
                        Some(json!({"kind":"same-instance","function_index":0}))
                    }
                    "caller-unknown" => Some(json!({"kind":"unknown","function_index":null})),
                    _ => None,
                };
                assert_eq!(
                    output.rows[0].get("direct_caller"),
                    caller.as_ref(),
                    "C++ case {case}"
                );
                assert_eq!(event["parent_event_id"], "0", "C++ case {case}");
            }
            if matches!(
                case,
                "default" | "arm" | "wide-identities" | "caller-same-instance" | "caller-unknown"
            ) {
                use sha2::{Digest, Sha256};
                let root = tempfile::tempdir().unwrap();
                let bytes = module();
                let hash = hex::encode(Sha256::digest(&bytes));
                std::fs::create_dir(root.path().join("blobs")).unwrap();
                std::fs::write(root.path().join(format!("blobs/{hash}.bin")), &bytes).unwrap();
                let mut manifest = artifact(&event);
                for (key,value) in json!({"protocol_version":1,"parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown","url":"fixture://native-wasm-golden","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")}).as_object().unwrap() {manifest[key]=value.clone();}
                std::fs::write(root.path().join("manifest.jsonl"), format!("{manifest}\n"))
                    .unwrap();
                let events = root.path().join("events.jsonl");
                std::fs::write(&events, format!("{event}\n")).unwrap();
                crate::vm::store(root.path(), &events).unwrap();
                let document: Value = serde_json::from_slice(
                    &std::fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json"))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    document["workspaces"][0]["native_wasm_observation_count"], 1,
                    "golden product path {case}"
                );
                assert_eq!(
                    document["workspaces"][0]["native_wasm_observations"][0]["monotonic_time_ns"],
                    event["monotonic_time_ns"],
                    "physical row carries the accepted event time {case}"
                );
                let schema: Value = serde_json::from_str(include_str!(
                    "../../../protocol/vm-opcode-workspace-v2.schema.json"
                ))
                .unwrap();
                jsonschema::validator_for(&schema)
                    .unwrap()
                    .validate(&document)
                    .unwrap();
                if case == "wide-identities"
                    && let Ok(path) = std::env::var("REB_NATIVE_WASM_WORKSPACE_OUTPUT")
                {
                    std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
                }
                if case == "wide-identities" {
                    super::super::export_golden_evidence(
                        root.path(),
                        "REB_NATIVE_WASM_EVIDENCE_OUTPUT",
                    );
                }
            }
        }
        // call_indirect records from the same producer, read against the
        // owned module whose site the producer names.
        let bytes = wat::parse_str(INDIRECT_MODULE).unwrap();
        for (case, accepted) in [
            ("indirect-resolved", true),
            ("indirect-out-of-bounds", true),
            ("indirect-wide-identities", true),
            ("indirect-table", false),
            ("indirect-offset", false),
            ("indirect-reserved", false),
            ("indirect-resolution", false),
            ("indirect-callee", false),
            ("indirect-sample-index", false),
            ("indirect-invocation", true),
            ("indirect-invocation-mismatch", false),
        ] {
            let process = std::process::Command::new(&exe)
                .args(["--case", case])
                .output()
                .expect("run C++ producer");
            assert!(process.status.success(), "C++ case {case}");
            let event: Value = serde_json::from_slice(&process.stdout).expect("EventToJson output");
            let output = collect_indirect(
                &artifact(&event),
                Module::parse(&bytes).as_mut(),
                std::slice::from_ref(&event),
            );
            assert_eq!(output.count, u64::from(accepted), "C++ case {case}");
            if case == "indirect-resolved" {
                use sha2::{Digest, Sha256};
                let root = tempfile::tempdir().unwrap();
                let hash = hex::encode(Sha256::digest(&bytes));
                std::fs::create_dir(root.path().join("blobs")).unwrap();
                std::fs::write(root.path().join(format!("blobs/{hash}.bin")), &bytes).unwrap();
                let mut manifest = artifact(&event);
                for (key,value) in json!({"protocol_version":1,"parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown","url":"fixture://native-wasm-golden","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")}).as_object().unwrap() {manifest[key]=value.clone();}
                std::fs::write(root.path().join("manifest.jsonl"), format!("{manifest}\n"))
                    .unwrap();
                let events = root.path().join("events.jsonl");
                std::fs::write(&events, format!("{event}\n")).unwrap();
                crate::vm::store(root.path(), &events).unwrap();
                let document: Value = serde_json::from_slice(
                    &std::fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json"))
                        .unwrap(),
                )
                .unwrap();
                let workspace = &document["workspaces"][0];
                assert_eq!(
                    workspace["native_wasm_indirect_observation_count"], 1,
                    "{workspace:#}"
                );
                assert_eq!(
                    workspace["observed_claims"][0]["static_claim"]["state"],
                    "agrees"
                );
                let schema: Value = serde_json::from_str(include_str!(
                    "../../../protocol/vm-opcode-workspace-v2.schema.json"
                ))
                .unwrap();
                jsonschema::validator_for(&schema)
                    .unwrap()
                    .validate(&document)
                    .unwrap();
            }
        }
    }
    fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn versioned(version: u8, state_at: usize, state: u8, id: u32) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        bytes[0] = version;
        bytes[2] = 128;
        bytes[state_at] = state;
        put_u32(&mut bytes, state_at + 4, id);
        bytes
    }
    fn dispatch_bytes(version: u8, state: u8, id: u32) -> [u8; 128] {
        let mut bytes = versioned(version, 24, state, id);
        put_u32(&mut bytes, 4, 7);
        put_u32(&mut bytes, 8, 40);
        put_u32(&mut bytes, 12, u32::MAX);
        put_u32(&mut bytes, 16, 3);
        put_u32(&mut bytes, 20, 4);
        bytes
    }
    fn indirect_bytes(resolution: u32, callee: u32, state: u8, id: u32) -> [u8; 128] {
        let mut bytes = versioned(2, 32, state, id);
        put_u32(&mut bytes, 4, 1);
        put_u32(&mut bytes, 8, 80);
        put_u32(&mut bytes, 12, 2);
        put_u32(&mut bytes, 16, 6);
        put_u32(&mut bytes, 20, callee);
        put_u32(&mut bytes, 24, resolution);
        put_u32(&mut bytes, 28, 2);
        bytes
    }
    fn payload_event(kind: &str, bytes: &[u8]) -> Value {
        let mut record = event(0);
        record["type"] = json!(kind);
        record["payload"] = json!(hex::encode(bytes));
        record["payload_size"] = json!(bytes.len());
        record
    }
    #[test]
    fn query_observation_decodes_without_a_module_and_names_resolution() {
        // No Module::parse and no workspace: the payload is the only input.
        let row = query_observation(&payload_event(
            "wasm_dispatch_observation",
            &dispatch_bytes(2, 2, 11),
        ))
        .unwrap();
        assert_eq!(
            row,
            json!({"status":"decoded","function_index":7,"module_byte_offset":40,"selector":u32::MAX,
                "table_count":3,"sample_index":4,"js_invocation_state":2,"js_invocation_id":11})
        );
        let older = query_observation(&payload_event(
            "wasm_dispatch_observation",
            &dispatch_bytes(1, 0, 0),
        ))
        .unwrap();
        assert_eq!(older["js_invocation_state"], 0);
        assert_eq!(older["js_invocation_id"], 0);
        assert!(older.get("direct_caller").is_none());
        let walked = query_observation(&payload_event(
            "wasm_dispatch_observation",
            &dispatch_bytes(3, 0, 0),
        ))
        .unwrap();
        assert_eq!(
            walked["direct_caller"],
            json!({"kind":"unknown","function_index":null})
        );
        assert_eq!(walked["function_index"], 7);
        let mut named = dispatch_bytes(3, 0, 0);
        named[32] = 1;
        assert_eq!(
            query_observation(&payload_event("wasm_dispatch_observation", &named)).unwrap()["direct_caller"],
            json!({"kind":"same-instance","function_index":0})
        );
        let stored = event(5);
        let shared = query_observation(&stored).unwrap();
        let workspace = read(&artifact(&stored), &module(), std::slice::from_ref(&stored));
        for key in [
            "function_index",
            "module_byte_offset",
            "selector",
            "table_count",
            "sample_index",
        ] {
            assert_eq!(shared[key], workspace.rows[0][key], "{key}");
        }
        let names = ["resolved", "null", "out-of-bounds", "foreign", "unresolved"];
        for (value, name) in names.iter().enumerate() {
            let callee = u32::from(value == 0);
            let row = query_observation(&payload_event(
                "wasm_indirect_observation",
                &indirect_bytes(value as u32, callee, 1, 0),
            ))
            .unwrap();
            assert_eq!(row["resolution"], *name);
            assert!(row["resolution"].is_string(), "{name}");
            assert_eq!(row["callee_function_index"], callee);
            assert_eq!(row["table_index"], 2);
            assert_eq!(row["slot"], 6);
            assert_eq!(row["function_index"], 1);
            assert_eq!(row["module_byte_offset"], 80);
            assert_eq!(row["sample_index"], 2);
            assert_eq!(row["js_invocation_state"], 1);
            assert_eq!(row["js_invocation_id"], 0);
            assert!(row.get("selector").is_none());
        }
        let indirect = indirect_event(1, 2, 0);
        let named = query_observation(&indirect).unwrap();
        let rows = collect_indirect(
            &artifact(&indirect),
            Module::parse(&wat::parse_str(INDIRECT_MODULE).unwrap()).as_mut(),
            std::slice::from_ref(&indirect),
        );
        assert_eq!(named["resolution"], rows.rows[0]["resolution"]);
        assert_eq!(named["resolution"], "out-of-bounds");
        assert_eq!(named["slot"], rows.rows[0]["slot"]);
        assert_eq!(named["callee_function_index"], 0);
        // Legal extremes stay the stored integers. Nothing here is clamped
        // into a default arm, a guest sample, or a caller.
        let mut edge = dispatch_bytes(2, 1, 0);
        put_u32(&mut edge, 4, LIMIT - 1);
        put_u32(&mut edge, 8, 8);
        put_u32(&mut edge, 16, LIMIT - 1);
        put_u32(&mut edge, 20, 15);
        let row = query_observation(&payload_event("wasm_dispatch_observation", &edge)).unwrap();
        assert_eq!(
            row,
            json!({"status":"decoded","function_index":LIMIT - 1,"module_byte_offset":8,
                "selector":u32::MAX,"table_count":LIMIT - 1,"sample_index":15,
                "js_invocation_state":1,"js_invocation_id":0})
        );
        let mut far = dispatch_bytes(2, 0, 0);
        put_u32(&mut far, 8, LIMIT - 1);
        assert_eq!(
            query_observation(&payload_event("wasm_dispatch_observation", &far)).unwrap()["module_byte_offset"],
            LIMIT - 1
        );
        let mut indirect_edge = indirect_bytes(0, LIMIT - 1, 0, 0);
        put_u32(&mut indirect_edge, 12, LIMIT - 1);
        put_u32(&mut indirect_edge, 16, u32::MAX);
        let row =
            query_observation(&payload_event("wasm_indirect_observation", &indirect_edge)).unwrap();
        assert_eq!(row["resolution"], "resolved");
        assert_eq!(row["table_index"], LIMIT - 1);
        assert_eq!(row["slot"], u32::MAX);
        assert_eq!(row["callee_function_index"], LIMIT - 1);
        assert!(row.get("instruction").is_none());
        // Callee 0 with resolution resolved is the stored function index 0.
        let row = query_observation(&payload_event(
            "wasm_indirect_observation",
            &indirect_bytes(0, 0, 0, 0),
        ))
        .unwrap();
        assert_eq!(row["resolution"], "resolved");
        assert_eq!(row["callee_function_index"], 0);
        let mut older_indirect = indirect_bytes(4, 0, 0, 0);
        older_indirect[0] = 1;
        let row = query_observation(&payload_event("wasm_indirect_observation", &older_indirect))
            .unwrap();
        assert_eq!(row["resolution"], "unresolved");
        assert_eq!(row["callee_function_index"], 0);
        assert_eq!(row["js_invocation_state"], 0);
        assert_eq!(row["js_invocation_id"], 0);
    }
    fn assert_rejected(kind: &str, bytes: &[u8]) {
        let mut events = vec![payload_event(kind, bytes)];
        let payload = events[0]["payload"].clone();
        assert!(
            query_observation(&events[0]).is_none(),
            "{kind} {}",
            hex::encode(bytes)
        );
        super::super::annotate_wasm_observations(&mut events);
        let observation = &events[0]["wasm_observation"];
        assert_eq!(observation, &json!({"status": "invalid"}), "{kind}");
        assert_eq!(observation.as_object().unwrap().len(), 1, "{kind}");
        assert_eq!(events[0]["payload"], payload);
    }
    #[test]
    fn query_observation_rejects_malformed_payloads_without_partial_fields() {
        let mut rejected: Vec<(&str, Vec<u8>)> = Vec::new();
        // Version 3 with kind 0 and index 0 is an observed unknown caller.
        // A guessed index, another kind, or a reserved byte is not that caller.
        let mut guessed = dispatch_bytes(3, 0, 0);
        put_u32(&mut guessed, 36, 9);
        rejected.push(("wasm_dispatch_observation", guessed.to_vec()));
        let mut other_kind = dispatch_bytes(3, 0, 0);
        other_kind[32] = 2;
        rejected.push(("wasm_dispatch_observation", other_kind.to_vec()));
        let mut caller_reserved = dispatch_bytes(3, 0, 0);
        caller_reserved[33] = 1;
        rejected.push(("wasm_dispatch_observation", caller_reserved.to_vec()));
        let mut huge_caller = dispatch_bytes(3, 0, 0);
        huge_caller[32] = 1;
        put_u32(&mut huge_caller, 36, LIMIT);
        rejected.push(("wasm_dispatch_observation", huge_caller.to_vec()));
        rejected.push((
            "wasm_dispatch_observation",
            dispatch_bytes(0, 0, 0).to_vec(),
        ));
        let mut high = dispatch_bytes(2, 0, 0);
        high[1] = 1;
        rejected.push(("wasm_dispatch_observation", high.to_vec()));
        rejected.push((
            "wasm_dispatch_observation",
            dispatch_bytes(1, 2, 9).to_vec(),
        ));
        let mut reserved = dispatch_bytes(2, 2, 11);
        reserved[32] = 1;
        rejected.push(("wasm_dispatch_observation", reserved.to_vec()));
        let mut padding = dispatch_bytes(2, 2, 11);
        padding[25] = 1;
        rejected.push(("wasm_dispatch_observation", padding.to_vec()));
        let mut offset = dispatch_bytes(2, 0, 0);
        put_u32(&mut offset, 8, 7);
        rejected.push(("wasm_dispatch_observation", offset.to_vec()));
        let mut far = dispatch_bytes(2, 0, 0);
        put_u32(&mut far, 8, LIMIT);
        rejected.push(("wasm_dispatch_observation", far.to_vec()));
        let mut function = dispatch_bytes(2, 0, 0);
        put_u32(&mut function, 4, LIMIT);
        rejected.push(("wasm_dispatch_observation", function.to_vec()));
        let mut count = dispatch_bytes(2, 0, 0);
        put_u32(&mut count, 16, LIMIT);
        rejected.push(("wasm_dispatch_observation", count.to_vec()));
        let mut sample = dispatch_bytes(2, 0, 0);
        put_u32(&mut sample, 20, 16);
        rejected.push(("wasm_dispatch_observation", sample.to_vec()));
        rejected.push((
            "wasm_dispatch_observation",
            dispatch_bytes(2, 2, 0).to_vec(),
        ));
        rejected.push((
            "wasm_dispatch_observation",
            dispatch_bytes(2, 3, 1).to_vec(),
        ));
        let mut indirect_v3 = indirect_bytes(0, 1, 0, 0);
        indirect_v3[0] = 3;
        rejected.push(("wasm_indirect_observation", indirect_v3.to_vec()));
        rejected.push((
            "wasm_indirect_observation",
            indirect_bytes(5, 0, 0, 0).to_vec(),
        ));
        rejected.push((
            "wasm_indirect_observation",
            indirect_bytes(1, 4, 0, 0).to_vec(),
        ));
        let mut table = indirect_bytes(0, 1, 0, 0);
        put_u32(&mut table, 12, LIMIT);
        rejected.push(("wasm_indirect_observation", table.to_vec()));
        let mut callee = indirect_bytes(0, 1, 0, 0);
        put_u32(&mut callee, 20, LIMIT);
        rejected.push(("wasm_indirect_observation", callee.to_vec()));
        let mut indirect_reserved = indirect_bytes(0, 1, 0, 0);
        indirect_reserved[40] = 1;
        rejected.push(("wasm_indirect_observation", indirect_reserved.to_vec()));
        let mut indirect_pad = indirect_bytes(0, 1, 2, 4);
        indirect_pad[33] = 1;
        rejected.push(("wasm_indirect_observation", indirect_pad.to_vec()));
        let mut version1_context = indirect_bytes(1, 0, 0, 0);
        version1_context[0] = 1;
        version1_context[32] = 1;
        rejected.push(("wasm_indirect_observation", version1_context.to_vec()));
        let mut size = indirect_bytes(0, 1, 0, 0);
        size[2] = 127;
        rejected.push(("wasm_indirect_observation", size.to_vec()));
        let mut size_high = indirect_bytes(0, 1, 0, 0);
        size_high[3] = 1;
        rejected.push(("wasm_indirect_observation", size_high.to_vec()));
        let mut short = dispatch_bytes(2, 0, 0).to_vec();
        short.pop();
        rejected.push(("wasm_dispatch_observation", short));
        for (kind, bytes) in &rejected {
            assert_rejected(kind, bytes);
        }
        let mut events = vec![payload_event("module_compiled", &reserved)];
        super::super::annotate_wasm_observations(&mut events);
        assert!(events[0].get("wasm_observation").is_none());
        let good = payload_event("wasm_dispatch_observation", &dispatch_bytes(2, 0, 0));
        for (field, value) in [
            ("protocol_version", json!(2)),
            ("category", json!("wasm")),
            ("flags", json!(1)),
            ("payload_encoding", json!("utf8")),
        ] {
            let mut event = good.clone();
            event[field] = value;
            let payload = event["payload"].clone();
            assert!(query_observation(&event).is_none(), "{field}");
            let mut events = vec![event];
            super::super::annotate_wasm_observations(&mut events);
            assert_eq!(
                events[0]["wasm_observation"],
                json!({"status": "invalid"}),
                "{field}"
            );
            assert_eq!(events[0]["wasm_observation"].as_object().unwrap().len(), 1);
            assert_eq!(events[0]["payload"], payload);
        }
        let mut truncated = good.clone();
        truncated["payload_truncated"] = json!(true);
        assert!(query_observation(&truncated).is_none());
        let mut events = vec![truncated];
        super::super::annotate_wasm_observations(&mut events);
        assert_eq!(events[0]["wasm_observation"], json!({"status": "invalid"}));
        assert_eq!(events[0]["wasm_observation"].as_object().unwrap().len(), 1);
    }
}
