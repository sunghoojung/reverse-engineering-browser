//! Exact-build source-reviewed bindings, not a universal semantic classifier.
//! QuickJS source revision df4efb9ef2cb25c417ecb57986da462d11b244ed:
//! JS_CallInternal initializes pc=b->byte_code_buf and dispatches *pc++.
//! The debug-sync 0.32.0 binary preserves the original address in local 320;
//! local 322 is advanced and must not be used as the instruction address.
use sha2::{Digest, Sha256};
use wasmparser::{Operator, Parser, Payload, TypeRef, ValType};
pub(crate) const QUICKJS_SHA256: &str = "4d2f9f8adf28c48ed273515b815e05ae9a698b54955f7348e951faf43b1febc3";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedGuestBinding {
    pub module_sha256: &'static str,
    pub adapter: &'static str,
    pub function_index: u32,
    pub dispatch_module_offset: u32,
    pub table_count: u32,
    pub pc_local_index: u32,
    pub frame_local_index: u32,
    pub base_offsets: &'static [u32],
    pub length_offsets: &'static [u32],
    pub memory_index: u32,
    pub opcode_width: u32,
}
const QUICKJS: VerifiedGuestBinding = VerifiedGuestBinding {
    module_sha256: QUICKJS_SHA256, adapter: "quickjs-wasm-debug-sync-0.32.0",
    function_index: 414, dispatch_module_offset: 0x20677, table_count: 244,
    pc_local_index: 320, frame_local_index: 10, base_offsets: &[1708,20],
    length_offsets: &[1708,24], memory_index: 0, opcode_width: 1,
};
/// Caller assertions cannot grant semantic provenance: require the reviewed
/// digest and independently checked local types and opcode-fetch relationship.
pub(crate) fn verify(bytes: &[u8]) -> Option<VerifiedGuestBinding> {
    if bytes.len() > 16*1024*1024 || hex::encode(Sha256::digest(bytes)) != QUICKJS_SHA256 || !verify_structure(bytes)? { return None; }
    Some(QUICKJS)
}
fn verify_structure(bytes: &[u8]) -> Option<bool> {
    let mut types = Vec::new();
    let mut function_types = Vec::new();
    let mut function_index = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.ok()? {
            Payload::TypeSection(reader) => { for ty in reader.into_iter_err_on_gc_types() { types.push(ty.ok()?); } }
            Payload::ImportSection(reader) => { for import in reader { if let TypeRef::Func(ty) = import.ok()?.ty { function_types.push(ty); function_index = function_index.checked_add(1)?; } } }
            Payload::FunctionSection(reader) => { for ty in reader { function_types.push(ty.ok()?); } }
            Payload::CodeSectionEntry(body) => {
                if function_index != QUICKJS.function_index { function_index = function_index.checked_add(1)?; continue; }
                let ty = types.get(*function_types.get(function_index as usize)? as usize)?;
                let mut locals = ty.params().to_vec();
                for group in body.get_locals_reader().ok()? { let (count,kind)=group.ok()?; let end=locals.len().checked_add(count as usize)?; if end>100_000 { return None; } locals.resize(end,kind); }
                for index in [10,310,311,320,321,322,323,324,3240,3241] { if locals.get(index)!=Some(&ValType::I32) { return None; } }
                let mut reader=body.get_operators_reader().ok()?;
                let mut checks=0u32;
                let mut instructions=0u32;
                while !reader.eof() {
                    instructions+=1; if instructions>1_000_000 { return None; }
                    let at=reader.original_position(); let op=reader.read().ok()?;
                    if (0x20493..0x20677).contains(&at) && matches!(op,Operator::LocalSet{local_index:320|323}|Operator::LocalTee{local_index:320|323}) { return None; }
                    let expected=match at {
                        0x203c6|0x20469|0x28473=>Some(local_get(&op,10)),
                        0x203c8|0x28475=>Some(load32(&op,1708)),
                        0x203cc=>Some(local_set(&op,310)), 0x203cf=>Some(local_get(&op,310)),
                        0x203d2=>Some(load32(&op,20)), 0x203d5=>Some(local_set(&op,311)),
                        0x2046b=>Some(load32(&op,1648)), 0x2046f=>Some(local_set(&op,320)),
                        0x2048a=>Some(local_get(&op,320)),
                        0x2048d=>Some(matches!(&op,Operator::I32Load8U{memarg} if memarg.memory==0 && memarg.offset==0)),
                        0x20490=>Some(local_set(&op,323)), 0x20674=>Some(local_get(&op,323)),
                        0x20677=>Some(matches!(&op,Operator::BrTable{targets} if targets.len()==244)),
                        0x28479=>Some(local_set(&op,3240)), 0x2847c=>Some(local_get(&op,3240)),
                        0x2847f=>Some(load32(&op,24)), 0x28482=>Some(local_set(&op,3241)),
                        _=>None,
                    };
                    if let Some(valid)=expected { if !valid { return None; } checks+=1; }
                }
                return Some(checks==20);
            }
            _=>{}
        }
    }
    None
}
fn local_get(op:&Operator<'_>,index:u32)->bool { matches!(op,Operator::LocalGet{local_index} if *local_index==index) }
fn local_set(op:&Operator<'_>,index:u32)->bool { matches!(op,Operator::LocalSet{local_index} if *local_index==index) }
fn load32(op:&Operator<'_>,offset:u64)->bool { matches!(op,Operator::I32Load{memarg} if memarg.memory==0 && memarg.offset==offset) }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn unknown_modules_never_acquire_guest_semantics() {
        assert!(verify(b"\0asm\x01\0\0\0").is_none());
        assert!(verify(b"reviewed quickjs local 320").is_none());
        assert!(verify(&vec![0;16*1024*1024+1]).is_none());
    }
    #[test]
    #[ignore="requires pinned public QuickJS package; set REB_QUICKJS_WASM"]
    fn pinned_public_module_and_corruption() {
        let bytes=std::fs::read(std::env::var("REB_QUICKJS_WASM").expect("set REB_QUICKJS_WASM")).expect("read public module");
        assert_eq!(verify(&bytes),Some(QUICKJS));
        for offset in [0x2046f,0x2048d,0x20677,0x2847f] {
            let mut corrupted=bytes.clone(); corrupted[offset]^=1;
            assert!(verify(&corrupted).is_none()); assert_ne!(verify_structure(&corrupted),Some(true));
        }
    }
}
