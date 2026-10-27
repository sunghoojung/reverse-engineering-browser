//! Actual native runtime values, interpreted by a retained, digest-bound adapter.
//! A caller's adapter is not proof of a recovered instruction set.
use crate::evidence;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use wasmparser::{Operator, Parser, Payload, TypeRef, ValType};

const MAX_BYTES: usize = 65536;
#[derive(Default)]
pub(super) struct Samples {
    pub rows: Vec<Value>,
    pub count: u64,
    pub invalid: u64,
}
type FunctionState = (Vec<ValType>, BTreeMap<u32, u32>);
struct ModuleFacts {
    functions: BTreeMap<u32, Option<FunctionState>>,
    imports: Vec<u32>,
    binding: Option<crate::native_guest_binding::VerifiedGuestBinding>,
}
fn exact(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)))
}
fn decimal(v: &Value) -> Option<u64> {
    if !evidence::canonical(v, 64, false) {
        return None;
    }
    v.as_str()?.parse().ok()
}
fn signed(v: &Value) -> Option<i64> {
    let s = v.as_str()?;
    let n = s.parse::<i64>().ok()?;
    (n.to_string() == s).then_some(n)
}
fn uint(v: &Value) -> Option<u32> {
    let n = v.as_u64()?;
    (n <= i32::MAX as u64).then_some(n as u32)
}
fn le32(p: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(p[n..n + 4].try_into().expect("fixed payload"))
}
fn le64(p: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(p[n..n + 8].try_into().expect("fixed payload"))
}
fn scope(a: &Value, b: &Value) -> bool {
    ["session_id", "navigation_id", "frame_id"]
        .iter()
        .all(|k| a[*k] == b[*k])
}
fn payload(event: &Value, kind: &str) -> Option<Vec<u8>> {
    if event["protocol_version"] != 3
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || event["payload_truncated"] != false
        || event["flags"] != 0
        || event.get("dispatch_provenance").is_some()
        || !["monotonic_time_ns", "artifact_id", "frame_id"]
            .iter()
            .all(|k| evidence::canonical(&event[*k], 64, true))
        || event["thread_id"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > u32::MAX as u64)
    {
        return None;
    }
    super::event_payload(event, kind)
}
fn child<'a>(artifacts: &'a [Value], id: u64, module: &Value, kind: &str) -> Option<&'a Value> {
    if id == 0 {
        return None;
    }
    let mut found = artifacts
        .iter()
        .filter(|a| decimal(&a["artifact_id"]) == Some(id));
    let a = found.next()?;
    (found.next().is_none()
        && a["kind"] == kind
        && a["parent_artifact_id"] == module["artifact_id"]
        && scope(a, module)
        && a["capture_origin"] == "native_wasm_guest"
        && evidence::canonical(&a["execution_context_id"], 64, true)
        && a["execution_context_id"] == module["execution_context_id"]
        && evidence::canonical(&a["creator_event_id"], 64, true))
    .then_some(a)
}
// Local indexing includes parameters. Unsupported GC types fail closed.
fn function_state(module: &[u8], wanted: u32) -> Option<FunctionState> {
    let mut types = Vec::new();
    let mut functions = Vec::new();
    let mut imported = 0u32;
    let mut body_index = 0u32;
    for item in Parser::new(0).parse_all(module) {
        match item.ok()? {
            Payload::TypeSection(r) => {
                for t in r.into_iter_err_on_gc_types() {
                    types.push(t.ok()?);
                }
            }
            Payload::ImportSection(r) => {
                for i in r {
                    if let TypeRef::Func(t) = i.ok()?.ty {
                        functions.push(t);
                        imported = imported.checked_add(1)?;
                    }
                }
            }
            Payload::FunctionSection(r) => {
                for t in r {
                    functions.push(t.ok()?);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported.checked_add(body_index)?;
                body_index += 1;
                if index != wanted {
                    continue;
                }
                let mut locals = types
                    .get(*functions.get(index as usize)? as usize)?
                    .params()
                    .to_vec();
                for local in body.get_locals_reader().ok()? {
                    let (n, ty) = local.ok()?;
                    if locals.len().checked_add(n as usize)? > 65536 {
                        return None;
                    }
                    locals.extend(std::iter::repeat_n(ty, n as usize));
                }
                let mut sites = BTreeMap::new();
                let mut r = body.get_operators_reader().ok()?;
                while !r.eof() {
                    let offset = u32::try_from(r.original_position()).ok()?;
                    if let Operator::BrTable { targets } = r.read().ok()? {
                        sites.insert(offset, targets.len());
                    }
                }
                return Some((locals, sites));
            }
            _ => {}
        }
    }
    None
}
fn global_import_sites(module: &[u8]) -> Option<Vec<u32>> {
    let mut imported = 0u32;
    let mut calls = Vec::new();
    let mut instructions = 0usize;
    for item in Parser::new(0).parse_all(module) {
        match item.ok()? {
            Payload::ImportSection(r) => {
                for i in r {
                    if matches!(i.ok()?.ty, TypeRef::Func(_)) {
                        imported = imported.checked_add(1)?;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut r = body.get_operators_reader().ok()?;
                while !r.eof() {
                    instructions += 1;
                    if instructions > 1_000_000 {
                        return None;
                    }
                    let offset = u32::try_from(r.original_position()).ok()?;
                    if let Operator::Call { function_index } = r.read().ok()?
                        && function_index < imported
                    {
                        calls.push(offset);
                    }
                }
            }
            _ => {}
        }
    }
    Some(calls)
}
fn memory_supported(module: &[u8], wanted: u32) -> bool {
    let mut index = 0u32;
    for item in Parser::new(0).parse_all(module) {
        let Ok(item) = item else {
            return false;
        };
        let mut check = |m: wasmparser::MemoryType| {
            let selected = index == wanted;
            index += 1;
            selected.then_some(!m.shared && !m.memory64)
        };
        match item {
            Payload::ImportSection(r) => {
                for i in r {
                    let Ok(i) = i else {
                        return false;
                    };
                    if let TypeRef::Memory(m) = i.ty
                        && let Some(ok) = check(m)
                    {
                        return ok;
                    }
                }
            }
            Payload::MemorySection(r) => {
                for m in r {
                    let Ok(m) = m else {
                        return false;
                    };
                    if let Some(ok) = check(m) {
                        return ok;
                    }
                }
            }
            _ => {}
        }
    }
    false
}
fn local_kind(locals: &[ValType], index: &Value, kind: &Value) -> bool {
    let expected = match kind.as_str() {
        Some("i32") => ValType::I32,
        Some("i64") => ValType::I64,
        _ => return false,
    };
    uint(index)
        .and_then(|n| locals.get(n as usize))
        .is_some_and(|v| *v == expected)
}
fn source(v: &Value, actual: u64, locals: &[ValType]) -> bool {
    match v["kind"].as_str() {
        Some("constant") => exact(v, &["kind", "value"]) && decimal(&v["value"]) == Some(actual),
        Some("local") => {
            exact(v, &["kind", "local_index", "value_type"])
                && local_kind(locals, &v["local_index"], &v["value_type"])
                && (v["value_type"] != "i32" || actual <= u32::MAX as u64)
        }
        Some("memory-chain") => {
            exact(
                v,
                &[
                    "kind",
                    "local_index",
                    "value_type",
                    "memory_index",
                    "offsets",
                ],
            ) && v["value_type"] == "i32"
                && local_kind(locals, &v["local_index"], &v["value_type"])
                && uint(&v["memory_index"]).is_some()
                && v["offsets"].as_array().is_some_and(|a| {
                    !a.is_empty() && a.len() <= 3 && a.iter().all(|n| uint(n).is_some())
                })
                && actual <= u32::MAX as u64
        }
        _ => false,
    }
}
fn resolve(
    root: &Path,
    module: &Value,
    bytes: &[u8],
    artifacts: &[Value],
    event: &Value,
    invocations: &BTreeMap<(String, u32, String), &Value>,
    facts: &mut ModuleFacts,
) -> Option<Value> {
    let p = payload(event, "wasm_guest_dispatch")?;
    if !scope(event, module) || event["artifact_id"] != module["artifact_id"] {
        return None;
    }
    let function = le32(&p, 4);
    let site = le32(&p, 8);
    let selector = le32(&p, 12);
    let count = le32(&p, 16);
    let index = le32(&p, 20);
    let instance = le64(&p, 24);
    let invocation = le64(&p, 32);
    let pc = le64(&p, 40);
    let raw = le64(&p, 48);
    let bytecode_id = le64(&p, 56);
    let base = le64(&p, 64);
    let length = le32(&p, 72);
    let local = le32(&p, 76);
    let adjustment = le64(&p, 80) as i64;
    let memory = le32(&p, 88);
    let opcode = le32(&p, 92);
    let recipe_sha = hex::encode(&p[96..]);
    if instance == 0
        || invocation == 0
        || index >= 256
        || length == 0
        || length as usize > MAX_BYTES
        || base.checked_add(length as u64).is_none()
    {
        return None;
    }
    let mut key = super::event_identity(event)?;
    key.2 = event["parent_event_id"].as_str()?.to_owned();
    let marker = *invocations.get(&key)?;
    let m = payload(marker, "wasm_guest_invocation")?;
    if !scope(marker, event)
        || marker["artifact_id"] != module["artifact_id"]
        || marker["thread_id"] != event["thread_id"]
        || marker["parent_event_id"] != "0"
        || m[72..].iter().any(|b| *b != 0)
        || le32(&m, 4) != function
        || le64(&m, 8) != instance
        || le64(&m, 16) != invocation
        || le64(&m, 64) == invocation
        || m[32..64] != p[96..]
        || decimal(&marker["sequence_number"])? >= decimal(&event["sequence_number"])?
        || decimal(&marker["monotonic_time_ns"])? > decimal(&event["monotonic_time_ns"])?
    {
        return None;
    }
    let adapter = child(artifacts, le64(&m, 24), module, "wasm_guest_adapter")?;
    if adapter["sha256"] != recipe_sha {
        return None;
    }
    // A cached adapter belongs to the first retained invocation that created it,
    // not whichever activation happens to use its bytes later.
    let mut creator_key = super::event_identity(marker)?;
    creator_key.2 = adapter["creator_event_id"].as_str()?.to_owned();
    let creator = *invocations.get(&creator_key)?;
    let creator_payload = payload(creator, "wasm_guest_invocation")?;
    if !scope(creator, marker)
        || creator["artifact_id"] != module["artifact_id"]
        || creator["parent_event_id"] != "0"
        || le32(&creator_payload, 4) != function
        || le64(&creator_payload, 8) == 0
        || le64(&creator_payload, 16) == 0
        || le64(&creator_payload, 64) == le64(&creator_payload, 16)
        || le64(&creator_payload, 24) != le64(&m, 24)
        || creator_payload[32..64] != m[32..64]
        || creator_payload[72..].iter().any(|b| *b != 0)
        || decimal(&creator["sequence_number"])? > decimal(&marker["sequence_number"])?
        || decimal(&creator["monotonic_time_ns"])? > decimal(&marker["monotonic_time_ns"])?
    {
        return None;
    }
    let adapter_bytes = evidence::content(root, adapter, MAX_BYTES).ok()?;
    let recipe: Value = serde_json::from_slice(&adapter_bytes).ok()?;
    // Exact canonical bytes reject duplicate keys and alternate JSON spellings.
    if crate::vm::canonical(&recipe).ok()? != adapter_bytes {
        return None;
    }
    if !exact(
        &recipe,
        &[
            "version",
            "sample_limit",
            "module_sha256",
            "function_index",
            "dispatch_module_offset",
            "pc",
            "bytecode",
            "opcode",
            "import_call_offsets",
        ],
    ) || recipe["version"] != 1
        || recipe["sample_limit"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > 256 || u64::from(index) >= n)
        || recipe["module_sha256"] != module["sha256"]
        || uint(&recipe["function_index"]) != Some(function)
        || uint(&recipe["dispatch_module_offset"]) != Some(site)
    {
        return None;
    }
    let (locals, sites) = facts
        .functions
        .entry(function)
        .or_insert_with(|| function_state(bytes, function))
        .as_ref()?;
    if sites.get(&site) != Some(&count) || !memory_supported(bytes, memory) {
        return None;
    }
    let pc_recipe = &recipe["pc"];
    let byte_recipe = &recipe["bytecode"];
    let op_recipe = &recipe["opcode"];
    if !exact(
        pc_recipe,
        &[
            "local_index",
            "value_type",
            "adjustment",
            "subtract_memory_base",
        ],
    ) || uint(&pc_recipe["local_index"]) != Some(local)
        || !local_kind(locals, &pc_recipe["local_index"], &pc_recipe["value_type"])
        || signed(&pc_recipe["adjustment"]) != Some(adjustment)
        || (pc_recipe["value_type"] == "i32" && raw > u32::MAX as u64)
        || !exact(byte_recipe, &["memory_index", "base", "length"])
        || uint(&byte_recipe["memory_index"]) != Some(memory)
        || !source(&byte_recipe["base"], base, locals)
        || !source(&byte_recipe["length"], length as u64, locals)
        || !exact(op_recipe, &["width", "endian"])
    {
        return None;
    }
    let adjusted = if adjustment >= 0 {
        raw.checked_add(adjustment as u64)?
    } else {
        raw.checked_sub(adjustment.unsigned_abs())?
    };
    let resolved = if pc_recipe["subtract_memory_base"].as_bool()? {
        adjusted.checked_sub(base)?
    } else {
        adjusted
    };
    if resolved != pc {
        return None;
    }
    for source in [&byte_recipe["base"], &byte_recipe["length"]] {
        if source["kind"] == "memory-chain"
            && !memory_supported(bytes, uint(&source["memory_index"])?)
        {
            return None;
        }
    }
    let import_sites = recipe["import_call_offsets"].as_array()?;
    if import_sites.len() > 64
        || import_sites
            .iter()
            .any(|v| uint(v).is_none_or(|n| !facts.imports.contains(&n)))
        || import_sites
            .iter()
            .enumerate()
            .any(|(i, v)| import_sites[..i].contains(v))
    {
        return None;
    }
    let width = uint(&op_recipe["width"])? as usize;
    if ![1, 2, 4].contains(&width) {
        return None;
    }
    let snapshot = child(artifacts, bytecode_id, module, "bytecode_buffer")?;
    if snapshot["byte_size"] != length as u64
        || snapshot["creator_event_id"] != event["sequence_number"]
    {
        return None;
    }
    let captured = evidence::content(root, snapshot, MAX_BYTES).ok()?;
    let start = usize::try_from(pc).ok()?;
    let opbytes = captured.get(start..start.checked_add(width)?)?;
    let observed = match op_recipe["endian"].as_str() {
        Some("little") => opbytes
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (i * 8)),
        Some("big") => opbytes.iter().fold(0u32, |n, b| (n << 8) | *b as u32),
        _ => return None,
    };
    if observed != opcode {
        return None;
    }
    let interpretation = facts
        .binding
        .filter(|b| {
            let chain = |v: &Value, offsets: &[u32]| {
                v["kind"] == "memory-chain"
                    && v["local_index"] == b.frame_local_index
                    && v["value_type"] == "i32"
                    && v["memory_index"] == b.memory_index
                    && v["offsets"] == json!(offsets)
            };
            b.module_sha256 == module["sha256"].as_str().unwrap_or("")
                && !b.adapter.is_empty()
                && b.function_index == function
                && b.dispatch_module_offset == site
                && b.table_count == count
                && b.pc_local_index == local
                && b.memory_index == memory
                && b.opcode_width as usize == width
                && adjustment == 0
                && pc_recipe["subtract_memory_base"] == true
                && pc_recipe["value_type"] == "i32"
                && op_recipe["endian"] == "little"
                && chain(&byte_recipe["base"], b.base_offsets)
                && chain(&byte_recipe["length"], b.length_offsets)
        })
        .map_or("explicit-adapter", |_| "verified-dataflow");
    if interpretation == "verified-dataflow" && selector != opcode {
        return None;
    }
    Some(
        json!({"event":super::event_reference(event),"invocation_event":super::event_reference(marker),"invocation_id":invocation.to_string(),"instance_id":instance.to_string(),"parent_invocation_id":le64(&m,64).to_string(),"function_index":function,"module_byte_offset":site,"selector":selector,"table_count":count,"selected_arm":selector.min(count),"is_default":selector>=count,"sample_index":index,"instruction_pointer":pc,"instruction_pointer_units":"byte-offset","raw_pc_bits":raw.to_string(),"pc_local_index":local,"pc_adjustment":adjustment.to_string(),"pc_value_type":pc_recipe["value_type"],"pc_subtract_memory_base":pc_recipe["subtract_memory_base"],"memory_index":memory,"memory_base":base.to_string(),"memory_length":length,"opcode":opcode,"opcode_width":width,"opcode_endian":op_recipe["endian"],"adapter_artifact_id":adapter["artifact_id"],"adapter_sha256":recipe_sha,"bytecode_artifact_id":snapshot["artifact_id"],"bytecode_sha256":snapshot["sha256"],"interpretation":interpretation,"host_import_call_offsets":import_sites}),
    )
}
pub(super) fn collect(
    root: &Path,
    module: &Value,
    bytes: &[u8],
    artifacts: &[Value],
    events: &[Value],
) -> Samples {
    let mut result = Samples::default();
    if module["kind"] != "wasm" {
        return result;
    }
    let Some(imports) = global_import_sites(bytes) else {
        return result;
    };
    let mut facts = ModuleFacts {
        functions: BTreeMap::new(),
        imports,
        binding: crate::native_guest_binding::verify(bytes),
    };
    let invocations = events
        .iter()
        .filter(|e| e["type"] == "wasm_guest_invocation")
        .filter_map(|e| super::event_identity(e).map(|id| (id, e)))
        .collect();
    for event in events
        .iter()
        .filter(|e| e["type"] == "wasm_guest_dispatch" && e["artifact_id"] == module["artifact_id"])
    {
        if let Some(row) = resolve(
            root,
            module,
            bytes,
            artifacts,
            event,
            &invocations,
            &mut facts,
        ) {
            result.count += 1;
            if result.rows.len() < super::MAX_SAMPLES {
                result.rows.push(row);
            }
        } else {
            result.invalid += 1;
        }
    }
    result
}
impl Samples {
    pub fn attach(&self, handlers: &mut [Value]) {
        for handler in handlers {
            let count = self
                .rows
                .iter()
                .filter(|r| {
                    r["module_byte_offset"] == handler["source"]["byte_offset"]
                        && if r["is_default"] == true {
                            handler["opcode"].is_null()
                                && handler["label"].as_str().is_some_and(|s| {
                                    s.starts_with("br_table ") && s.ends_with("default")
                                })
                        } else {
                            handler["opcode"] == r["selector"]
                        }
                })
                .count();
            if count > 0 {
                handler["native_guest_sample_count"] = json!(count);
                handler["state"] = json!("observed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    fn wasm() -> Vec<u8> {
        hex::decode("0061736d010000000104016000000302010005030100010a1d011b01017f0340200041016a210041002d00001a41000e020000000b0b").unwrap()
    }
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
        json!({"protocol_version":1,"artifact_id":id.to_string(),"session_id":"1","navigation_id":"2","frame_id":"3","parent_artifact_id":parent.to_string(),"creator_event_id":creator.to_string(),"execution_context_id":"1","capture_origin":if parent==0{"webassembly_compile"}else{"native_wasm_guest"},"kind":kind,"url":"fixture://native-guest","mime_type":"application/octet-stream","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")})
    }
    fn recipe(hash: &Value) -> Value {
        json!({"version":1,"sample_limit":16,"module_sha256":hash,"function_index":0,"dispatch_module_offset":47,"pc":{"local_index":0,"value_type":"i32","adjustment":"-3","subtract_memory_base":false},"bytecode":{"memory_index":0,"base":{"kind":"constant","value":"0"},"length":{"kind":"constant","value":"2"}},"opcode":{"width":1,"endian":"little"},"import_call_offsets":[]})
    }
    fn event(kind: &str, seq: u64, parent: u64, p: &[u8]) -> Value {
        json!({"protocol_version":3,"session_id":"1","navigation_id":"2","frame_id":"3","artifact_id":"1","sequence_number":seq.to_string(),"monotonic_time_ns":seq.to_string(),"process_id":4,"thread_id":5,"category":"vm","type":kind,"parent_event_id":parent.to_string(),"flags":0,"payload_size":128,"payload_encoding":"hex","payload_truncated":false,"payload":hex::encode(p)})
    }
    fn put32(p: &mut [u8], at: usize, v: u32) {
        p[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(p: &mut [u8], at: usize, v: u64) {
        p[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn mutate(e: &mut Value, f: impl FnOnce(&mut Vec<u8>)) {
        let mut p = hex::decode(e["payload"].as_str().unwrap()).unwrap();
        f(&mut p);
        e["payload"] = json!(hex::encode(p));
    }
    struct Fixture {
        root: tempfile::TempDir,
        module: Value,
        aux: Vec<Value>,
        events: Vec<Value>,
        bytes: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let bytes = wasm();
            let module = artifact(root.path(), 1, "wasm", &bytes, 0, 0);
            let a = artifact(
                root.path(),
                2,
                "wasm_guest_adapter",
                &crate::vm::canonical(&recipe(&module["sha256"])).unwrap(),
                1,
                1,
            );
            let b = artifact(root.path(), 3, "bytecode_buffer", &[42, 5], 1, 2);
            let sha = hex::decode(a["sha256"].as_str().unwrap()).unwrap();
            let mut inv = vec![0u8; 128];
            inv[..4].copy_from_slice(&[1, 0, 128, 0]);
            put64(&mut inv, 8, 7);
            put64(&mut inv, 16, 8);
            put64(&mut inv, 24, 2);
            inv[32..64].copy_from_slice(&sha);
            let mut p = vec![0u8; 128];
            p[..4].copy_from_slice(&[1, 0, 128, 0]);
            put32(&mut p, 8, 47);
            put32(&mut p, 12, u32::MAX);
            put32(&mut p, 16, 2);
            put64(&mut p, 24, 7);
            put64(&mut p, 32, 8);
            put64(&mut p, 40, 1);
            put64(&mut p, 48, 4);
            put64(&mut p, 56, 3);
            put32(&mut p, 72, 2);
            put64(&mut p, 80, (-3i64) as u64);
            put32(&mut p, 92, 5);
            p[96..].copy_from_slice(&sha);
            Self {
                root,
                module,
                aux: vec![a, b],
                events: vec![
                    event("wasm_guest_invocation", 1, 0, &inv),
                    event("wasm_guest_dispatch", 2, 1, &p),
                ],
                bytes,
            }
        }
        fn read(&self) -> Samples {
            collect(
                self.root.path(),
                &self.module,
                &self.bytes,
                &self.aux,
                &self.events,
            )
        }
        fn set_recipe(&mut self, r: Value) {
            self.aux[0] = artifact(
                self.root.path(),
                2,
                "wasm_guest_adapter",
                &crate::vm::canonical(&r).unwrap(),
                1,
                1,
            );
            let hash = hex::decode(self.aux[0]["sha256"].as_str().unwrap()).unwrap();
            mutate(&mut self.events[0], |p| p[32..64].copy_from_slice(&hash));
            mutate(&mut self.events[1], |p| p[96..].copy_from_slice(&hash));
        }
    }
    #[test]
    fn native_guest_values_are_bound_and_fail_closed() {
        let f = Fixture::new();
        let rows = f.read();
        assert_eq!(rows.count, 1);
        assert_eq!(rows.rows[0]["instruction_pointer"], 1);
        assert_eq!(rows.rows[0]["opcode"], 5);
        assert_eq!(rows.rows[0]["is_default"], true);
        assert_eq!(rows.rows[0]["interpretation"], "explicit-adapter");
        for offset in [4, 8, 16, 24, 32, 40, 48, 56, 64, 72, 76, 80, 88, 92, 96] {
            let mut f = Fixture::new();
            mutate(&mut f.events[1], |p| p[offset] ^= 1);
            assert_eq!(f.read().count, 0, "offset {offset}");
        }
        for key in ["session_id", "navigation_id", "frame_id", "parent_event_id"] {
            let mut f = Fixture::new();
            f.events[1][key] = json!("99");
            assert_eq!(f.read().count, 0, "{key}");
        }
        for key in ["process_id", "thread_id"] {
            let mut f = Fixture::new();
            f.events[1][key] = json!(99);
            assert_eq!(f.read().count, 0, "{key}");
        }
        let mut f = Fixture::new();
        f.events.remove(0);
        assert_eq!(f.read().count, 0);
    }
    #[test]
    fn native_guest_envelope_and_adapter_rejections() {
        for key in [
            "payload_size",
            "payload_encoding",
            "flags",
            "payload_truncated",
            "monotonic_time_ns",
        ] {
            let mut f = Fixture::new();
            f.events[1].as_object_mut().unwrap().remove(key);
            assert_eq!(f.read().count, 0, "missing {key}");
        }
        for offset in [0, 2] {
            let mut f = Fixture::new();
            mutate(&mut f.events[1], |p| p[offset] ^= 1);
            assert_eq!(f.read().count, 0);
        }
        let mut f = Fixture::new();
        mutate(&mut f.events[0], |p| p[72] = 1);
        assert_eq!(f.read().count, 0);
        for (path, value) in [
            ("/version", json!(2)),
            ("/sample_limit", json!(0)),
            ("/sample_limit", json!(257)),
            ("/pc/local_index", json!(999)),
            ("/pc/value_type", json!("i64")),
            ("/pc/adjustment", json!("-0")),
            ("/opcode/width", json!(3)),
            ("/opcode/endian", json!("native")),
            ("/bytecode/memory_index", json!(1)),
            ("/import_call_offsets", json!([47])),
            ("/module_sha256", json!("0".repeat(64))),
        ] {
            let mut f = Fixture::new();
            let mut r = recipe(&f.module["sha256"]);
            *r.pointer_mut(path).unwrap() = value;
            f.set_recipe(r);
            assert_eq!(f.read().count, 0, "{path}");
        }
        for index in [0, 1] {
            let mut f = Fixture::new();
            f.aux[index]["execution_context_id"] = json!("99");
            assert_eq!(f.read().count, 0, "cross-context child {index}");
        }
        let mut f = Fixture::new();
        f.module["execution_context_id"] = json!("0");
        assert_eq!(f.read().count, 0);
        let mut f = Fixture::new();
        f.aux.push(f.aux[1].clone());
        assert_eq!(f.read().count, 0);
        let f = Fixture::new();
        fs::write(
            f.root
                .path()
                .join(f.aux[1]["content_path"].as_str().unwrap()),
            [0, 0],
        )
        .unwrap();
        assert_eq!(f.read().count, 0);
    }
    #[test]
    fn native_guest_exact_site_and_empty_import_policy() {
        let f = Fixture::new();
        let s = f.read();
        let mut handlers = vec![
            json!({"opcode":null,"label":"br_table default","source":{"byte_offset":47},"sample_count":0}),
            json!({"opcode":null,"label":"br_table default","source":{"byte_offset":99},"sample_count":0}),
        ];
        s.attach(&mut handlers);
        assert_eq!(handlers[0]["native_guest_sample_count"], 1);
        assert!(handlers[1].get("native_guest_sample_count").is_none());
        let workspace = json!({"workspaces":[{"interpreter_artifact_id":"1","source_artifact_sha256":f.module["sha256"],"samples":[],"native_guest_samples":s.rows,"sample_count":1}]});
        let mut host = f.events[1].clone();
        host["category"] = json!("runtime");
        host["type"] = json!("api_call");
        host["sequence_number"] = json!("3");
        host["parent_event_id"] = json!("2");
        let links =
            crate::vm_host_links::store(f.root.path(), &workspace, &[f.module], &[host]).unwrap();
        assert!(links["workspaces"][0]["links"][0]["guest_position"].is_null());
    }
    // V8 fires the physical and the guest callback for one br_table execution
    // at an adapter site. The workspace must not count that execution twice.
    #[test]
    fn physical_and_guest_events_for_one_execution_are_not_summed() {
        let f = Fixture::new();
        let mut physical = vec![0u8; 128];
        physical[..4].copy_from_slice(&[1, 0, 128, 0]);
        put32(&mut physical, 8, 47);
        put32(&mut physical, 12, u32::MAX);
        put32(&mut physical, 16, 2);
        let observation = event("wasm_dispatch_observation", 10, 0, &physical);
        let mut events = f.events.clone();
        events.insert(1, observation);
        fs::write(
            f.root.path().join("manifest.jsonl"),
            [&f.module, &f.aux[0], &f.aux[1]]
                .iter()
                .map(|a| format!("{}\n", serde_json::to_string(a).unwrap()))
                .collect::<String>(),
        )
        .unwrap();
        let path = f.root.path().join("events.jsonl");
        fs::write(
            &path,
            events
                .iter()
                .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
                .collect::<String>(),
        )
        .unwrap();
        crate::vm::store(f.root.path(), &path).unwrap();
        let doc: Value = serde_json::from_slice(
            &fs::read(f.root.path().join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
        )
        .unwrap();
        let workspace = &doc["workspaces"][0];
        assert_eq!(workspace["native_wasm_observation_count"], 1);
        assert_eq!(workspace["native_guest_sample_count"], 1);
        assert_eq!(workspace["sample_count"], 0, "dispatch reports only");
        assert_eq!(doc["summary"]["sample_count"], 0);
        let handler = workspace["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["source"]["byte_offset"] == 47 && h["opcode"].is_null())
            .unwrap();
        assert_eq!(handler["state"], "observed");
        assert_eq!(handler["native_wasm_sample_count"], 1);
        assert_eq!(handler["native_guest_sample_count"], 1);
        assert_eq!(handler["sample_count"], 0);
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            validator.is_valid(&doc),
            "{:?}",
            validator
                .iter_errors(&doc)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }
    #[test]
    #[ignore = "requires actual native C++ golden encoder"]
    fn native_guest_cpp_golden() {
        golden(false);
    }
    #[test]
    #[ignore = "requires actual native encoder and pinned public QuickJS module; authored ABI fixture, not live capture"]
    fn native_guest_quickjs_cpp_golden() {
        golden(true);
    }
    fn golden(quickjs: bool) {
        let exe = std::env::var("REB_NATIVE_GUEST_GOLDEN").expect("native encoder path");
        let root = tempfile::tempdir().unwrap();
        let mut bytes = wasm();
        bytes[24] += 2;
        bytes[26] += 2;
        bytes.splice(32..32, [0x10, 0]);
        bytes.splice(14..14, [2, 7, 1, 1, b'h', 1, b'f', 0, 0]);
        assert_eq!(global_import_sites(&bytes), Some(vec![41]));
        if quickjs {
            bytes =
                fs::read(std::env::var("REB_QUICKJS_WASM").expect("pinned public QuickJS module"))
                    .unwrap();
            assert!(crate::native_guest_binding::verify(&bytes).is_some());
        }
        let mut module = artifact(root.path(), 107, "wasm", &bytes, 0, 0);
        for (k, v) in [
            ("session_id", "101"),
            ("navigation_id", "0"),
            ("frame_id", "103"),
        ] {
            module[k] = json!(v);
        }
        let mut r = recipe(&module["sha256"]);
        r["function_index"] = json!(1);
        r["dispatch_module_offset"] = json!(58);
        r["pc"]["adjustment"] = json!("0");
        r["pc"]["subtract_memory_base"] = json!(true);
        r["bytecode"]["base"]["value"] = json!("256");
        r["bytecode"]["length"]["value"] = json!("4");
        r["import_call_offsets"] = json!([41]);
        if quickjs {
            r["function_index"] = json!(414);
            r["dispatch_module_offset"] = json!(0x20677);
            r["pc"]["local_index"] = json!(320);
            for (name, offset) in [("base", 20), ("length", 24)] {
                r["bytecode"][name] = json!({"kind":"memory-chain","local_index":10,"value_type":"i32","memory_index":0,"offsets":[1708,offset]});
            }
            r["import_call_offsets"] = json!([26646]);
        }
        let mut a = artifact(
            root.path(),
            108,
            "wasm_guest_adapter",
            &crate::vm::canonical(&r).unwrap(),
            107,
            104,
        );
        let mut b = artifact(
            root.path(),
            109,
            "bytecode_buffer",
            &[0, 0x42, 0, 0],
            107,
            105,
        );
        for item in [&mut a, &mut b] {
            for key in ["session_id", "navigation_id", "frame_id"] {
                item[key] = module[key].clone();
            }
        }
        for mode in [
            "default",
            "wide-identities",
            "version",
            "size",
            "reserved",
            "pc-range",
            "snapshot-limit",
            "memory-overflow",
            "sample-limit",
            "digest",
            "signed-adjustment",
            "parent",
            "truncated",
            "big-endian",
        ] {
            let output = std::process::Command::new(&exe)
                .args([
                    if quickjs {
                        "--quickjs-fixture"
                    } else {
                        "--host-fixture"
                    },
                    "--recipe-sha",
                    a["sha256"].as_str().unwrap(),
                    "--case",
                    mode,
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "encoder {mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let events = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str::<Value>(s).unwrap())
                .collect::<Vec<_>>();
            let accepted = matches!(mode, "default" | "wide-identities");
            let rows = collect(
                root.path(),
                &module,
                &bytes,
                &[a.clone(), b.clone()],
                &events,
            );
            assert_eq!(rows.count, u64::from(accepted), "{mode}");
            if !accepted {
                continue;
            }
            fs::write(
                root.path().join("manifest.jsonl"),
                [&module, &a, &b]
                    .iter()
                    .map(|a| format!("{}\n", serde_json::to_string(a).unwrap()))
                    .collect::<String>(),
            )
            .unwrap();
            let mut all = events;
            let mut host = all[1].clone();
            host["category"] = json!("runtime");
            host["type"] = json!("api_call");
            host["sequence_number"] = json!("106");
            host["parent_event_id"] = json!("105");
            host["payload_size"] = json!(0);
            host["payload"] = json!("");
            all.push(host);
            let path = root.path().join("events.jsonl");
            fs::write(
                &path,
                all.iter()
                    .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
                    .collect::<String>(),
            )
            .unwrap();
            crate::vm::store(root.path(), &path).unwrap();
            let doc: Value = serde_json::from_slice(
                &fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(doc["workspaces"][0]["native_guest_sample_count"], 1);
            assert_eq!(doc["workspaces"][0]["sample_count"], 0);
            let schema: Value = serde_json::from_str(include_str!(
                "../../../protocol/vm-opcode-workspace-v2.schema.json"
            ))
            .unwrap();
            let validator = jsonschema::validator_for(&schema).unwrap();
            assert!(
                validator.is_valid(&doc),
                "{:?}",
                validator
                    .iter_errors(&doc)
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
            );
            let links: Value = serde_json::from_slice(
                &fs::read(root.path().join("analysis/vm-host-links-v1.json")).unwrap(),
            )
            .unwrap();
            if quickjs {
                assert_eq!(
                    doc["workspaces"][0]["native_guest_samples"][0]["interpretation"],
                    "verified-dataflow"
                );
                assert_eq!(
                    links["workspaces"][0]["links"][0]["guest_position"]["instruction_pointer"],
                    1
                );
            } else {
                assert!(
                    links["workspaces"][0]["links"][0]["guest_position"].is_null(),
                    "Explicit adapter does not prove guest semantics"
                );
            }
            if mode == "wide-identities"
                && let Ok(out) = std::env::var("REB_NATIVE_GUEST_WORKSPACE_OUTPUT")
            {
                fs::write(&out, serde_json::to_vec(&doc).unwrap()).unwrap();
                fs::write(
                    format!("{out}.host-links.json"),
                    serde_json::to_vec(&links).unwrap(),
                )
                .unwrap();
            }
        }
    }
    #[test]
    fn native_guest_instance_invocation_and_snapshot_lifecycle() {
        let mut f = Fixture::new();
        let mut inv = f.events[0].clone();
        let mut sample = f.events[1].clone();
        inv["sequence_number"] = json!("3");
        inv["monotonic_time_ns"] = json!("3");
        sample["sequence_number"] = json!("4");
        sample["monotonic_time_ns"] = json!("4");
        sample["parent_event_id"] = json!("3");
        mutate(&mut inv, |p| {
            put64(p, 8, 9);
            put64(p, 16, 10);
            put64(p, 64, 8);
        });
        mutate(&mut sample, |p| {
            put64(p, 24, 9);
            put64(p, 32, 10);
            put64(p, 56, 4);
        });
        f.aux.push(artifact(
            f.root.path(),
            4,
            "bytecode_buffer",
            &[99, 5],
            1,
            4,
        ));
        f.events.extend([inv, sample]);
        let rows = f.read();
        assert_eq!(rows.count, 2);
        assert_eq!(rows.rows[0]["instance_id"], "7");
        assert_eq!(rows.rows[1]["instance_id"], "9");
        assert_eq!(rows.rows[1]["parent_invocation_id"], "8");
        let saved = f.aux[0]["creator_event_id"].clone();
        f.aux[0]["creator_event_id"] = json!("99");
        assert_eq!(f.read().count, 0);
        f.aux[0]["creator_event_id"] = saved;
        let saved = f.events[0].clone();
        f.events.remove(0);
        assert_eq!(
            f.read().count,
            0,
            "lost adapter creator cannot rebind to later invocation"
        );
        f.events.insert(0, saved);
        // Reusing another activation's bytecode artifact is not an observation of this dispatch.
        mutate(&mut f.events[3], |p| put64(p, 56, 3));
        assert_eq!(f.read().count, 1);
        // A lost parent never binds to the last surviving invocation.
        f.events[3]["parent_event_id"] = json!("99");
        assert_eq!(f.read().count, 1);
        // Navigation changes invalidate the child even if module bytes and tokens match.
        f.events[3]["parent_event_id"] = json!("3");
        f.events[3]["navigation_id"] = json!("99");
        assert_eq!(f.read().count, 1);
    }
    #[test]
    fn native_guest_noncanonical_recipe_and_capture_caps() {
        let mut f = Fixture::new();
        let mut r = recipe(&f.module["sha256"]);
        r["pc"]["adjustment"] = json!("9223372036854775808");
        f.set_recipe(r);
        assert_eq!(f.read().count, 0);
        let mut f = Fixture::new();
        mutate(&mut f.events[1], |p| put32(p, 20, 16));
        assert_eq!(f.read().count, 0);
        let mut f = Fixture::new();
        let r = recipe(&f.module["sha256"]);
        let mut encoded = crate::vm::canonical(&r).unwrap();
        encoded.push(b' ');
        f.aux[0] = artifact(f.root.path(), 2, "wasm_guest_adapter", &encoded, 1, 1);
        let digest = hex::decode(f.aux[0]["sha256"].as_str().unwrap()).unwrap();
        mutate(&mut f.events[0], |p| p[32..64].copy_from_slice(&digest));
        mutate(&mut f.events[1], |p| p[96..].copy_from_slice(&digest));
        assert_eq!(f.read().count, 0);
        let mut f = Fixture::new();
        let mut r = recipe(&f.module["sha256"]);
        r["unknown"] = json!(true);
        f.set_recipe(r);
        assert_eq!(f.read().count, 0);
    }
}
