//! One lazily decoded view of a captured module for native record admission.
//! The artifact reader already bounds module bytes at 16 MiB. Each function
//! body is decoded at most once, when a record names it, so a large module
//! costs at most one pass and never silently discards records.
use std::collections::{BTreeMap, BTreeSet};
use wasmparser::{FuncType, FunctionBody, MemoryType, Operator, Parser, Payload, TypeRef, ValType};

/// Wasm allows more, but adapter local indexes are bounded well below this.
const MAX_LOCALS: usize = 65536;

pub(super) struct Function {
    /// Parameters then declared locals. None when the signature uses GC
    /// types or the locals exceed the bound; guest admission fails closed.
    pub locals: Option<Vec<ValType>>,
    /// Module byte offset of each br_table to its explicit target count.
    pub br_tables: BTreeMap<u32, u32>,
    /// Module byte offsets of direct calls to imported functions.
    pub import_calls: BTreeSet<u32>,
    /// Module byte offset of each call_indirect or return_call_indirect to
    /// its table index and whether it is the tail-call form.
    pub call_indirects: BTreeMap<u32, (u32, bool)>,
}

pub(super) struct Module<'a> {
    /// None when the type section uses GC types.
    types: Option<Vec<FuncType>>,
    function_types: Vec<u32>,
    imported: u32,
    memories: Vec<MemoryType>,
    bodies: Vec<FunctionBody<'a>>,
    decoded: BTreeMap<u32, Option<Function>>,
}

impl<'a> Module<'a> {
    /// None only for a module whose section structure does not decode.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let mut module = Self {
            types: Some(Vec::new()),
            function_types: Vec::new(),
            imported: 0,
            memories: Vec::new(),
            bodies: Vec::new(),
            decoded: BTreeMap::new(),
        };
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.ok()? {
                Payload::TypeSection(reader) => {
                    for ty in reader.into_iter_err_on_gc_types() {
                        match (ty, module.types.as_mut()) {
                            (Ok(ty), Some(types)) => types.push(ty),
                            _ => module.types = None,
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        match import.ok()?.ty {
                            TypeRef::Func(ty) => {
                                module.function_types.push(ty);
                                module.imported = module.imported.checked_add(1)?;
                            }
                            TypeRef::Memory(memory) => module.memories.push(memory),
                            _ => {}
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        module.function_types.push(ty.ok()?);
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        module.memories.push(memory.ok()?);
                    }
                }
                Payload::CodeSectionEntry(body) => module.bodies.push(body),
                _ => {}
            }
        }
        Some(module)
    }

    /// Decoded facts for one defined function, or None for an imported,
    /// absent or undecodable function.
    pub fn function(&mut self, index: u32) -> Option<&Function> {
        if !self.decoded.contains_key(&index) {
            let facts = self.decode(index);
            self.decoded.insert(index, facts);
        }
        self.decoded.get(&index)?.as_ref()
    }

    /// The function whose body contains a module byte offset.
    pub fn function_at(&mut self, offset: u32) -> Option<&Function> {
        let offset = offset as usize;
        let position = self
            .bodies
            .partition_point(|body| body.range().start <= offset)
            .checked_sub(1)?;
        if offset >= self.bodies[position].range().end {
            return None;
        }
        self.function(self.imported.checked_add(u32::try_from(position).ok()?)?)
    }

    /// Functions in the module's index space, imports first.
    pub fn function_count(&self) -> usize {
        self.function_types.len()
    }

    /// Guest memory chains read only unshared 32-bit memories.
    pub fn memory_supported(&self, index: u32) -> bool {
        self.memories
            .get(index as usize)
            .is_some_and(|memory| !memory.shared && !memory.memory64)
    }

    fn decode(&self, index: u32) -> Option<Function> {
        let body = self
            .bodies
            .get(index.checked_sub(self.imported)? as usize)?;
        let locals = self.locals(index, body);
        let mut br_tables = BTreeMap::new();
        let mut import_calls = BTreeSet::new();
        let mut call_indirects = BTreeMap::new();
        let mut reader = body.get_operators_reader().ok()?;
        while !reader.eof() {
            let offset = u32::try_from(reader.original_position()).ok()?;
            match reader.read().ok()? {
                Operator::BrTable { targets } => {
                    br_tables.insert(offset, targets.len());
                }
                Operator::Call { function_index } if function_index < self.imported => {
                    import_calls.insert(offset);
                }
                Operator::CallIndirect { table_index, .. } => {
                    call_indirects.insert(offset, (table_index, false));
                }
                Operator::ReturnCallIndirect { table_index, .. } => {
                    call_indirects.insert(offset, (table_index, true));
                }
                _ => {}
            }
        }
        Some(Function {
            locals,
            br_tables,
            import_calls,
            call_indirects,
        })
    }

    fn locals(&self, index: u32, body: &FunctionBody<'a>) -> Option<Vec<ValType>> {
        let ty = self
            .types
            .as_ref()?
            .get(*self.function_types.get(index as usize)? as usize)?;
        let mut locals = ty.params().to_vec();
        for group in body.get_locals_reader().ok()? {
            let (count, kind) = group.ok()?;
            if locals.len().checked_add(count as usize)? > MAX_LOCALS {
                return None;
            }
            locals.extend(std::iter::repeat_n(kind, count as usize));
        }
        Some(locals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions_decode_once_and_offsets_resolve_to_their_body() {
        let (bytes, site) = super::super::native_wasm::tests::padded_module(3);
        let mut module = Module::parse(&bytes).unwrap();
        assert_eq!(module.function(0).unwrap().br_tables.get(&site), Some(&2));
        assert!(module.function(1).is_none());
        assert!(module.function_at(site).is_some());
        assert!(module.function_at(7).is_none());
        assert!(module.function_at(bytes.len() as u32).is_none());
        assert!(module.memory_supported(0));
        assert!(!module.memory_supported(1));
        assert_eq!(module.decoded.len(), 2);
        assert!(Module::parse(&bytes[..bytes.len() - 1]).is_none());
    }
}
