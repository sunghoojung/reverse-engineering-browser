//! Declared operand-stack effects of one Wasm function body.
//!
//! This is the shared stack-simulation layer: the readable lift
//! (`wasm_pseudocode`) folds instructions with it, and an intra-function value
//! analysis can use the same three pieces without depending on the lift:
//!
//! - [`ModuleTypes`] holds what a stack effect depends on outside the body:
//!   the type section, each function's declared type (imports first, as
//!   function indexes count them) and each tag's type. Fill it from a module
//!   pass in section order.
//! - [`Label`] is one open control frame as the arity rules see it: its frame
//!   kind and block type. A caller keeps its own frames and passes the labels
//!   outermost first, the function's own frame at position 0 with
//!   `BlockType::FuncType` of the function's type.
//! - [`arity`] returns `(pops, pushes)` for any operator wasmparser decodes,
//!   from wasmparser's own `operator_arity` table, so every opcode the pinned
//!   parser knows has a declared effect. `None` means the effect depends on
//!   something this module does not resolve (an unknown type or label), and a
//!   caller must treat the stack shape after it as unknown.
//!
//! Nothing here runs the module, validates types, or tracks values; the
//! effects are declared counts. Polymorphic stacks after an unconditional
//! transfer are the caller's to model.
use wasmparser::{
    BlockType, CompositeInnerType, ContType, FrameKind, FuncType, ModuleArity, Operator, RecGroup,
    RefType, SubType,
};

/// Module-level declarations that operator arities depend on.
#[derive(Default)]
pub struct ModuleTypes {
    types: Vec<SubType>,
    /// Declared type index per function index, imports first.
    functions: Vec<u32>,
    imported_functions: u32,
    /// Declared type index per tag index, imports first.
    tags: Vec<u32>,
}

impl ModuleTypes {
    /// Appends one recursion group's types in index order.
    pub fn add_rec_group(&mut self, group: RecGroup) {
        self.types.extend(group.into_types());
    }
    /// Appends an imported function. Imports precede the function section.
    pub fn add_imported_function(&mut self, type_index: u32) {
        self.functions.push(type_index);
        self.imported_functions += 1;
    }
    /// Appends one function-section declaration.
    pub fn add_function(&mut self, type_index: u32) {
        self.functions.push(type_index);
    }
    /// Appends one tag, imported or defined, in index order.
    pub fn add_tag(&mut self, type_index: u32) {
        self.tags.push(type_index);
    }
    pub fn imported_functions(&self) -> u32 {
        self.imported_functions
    }
    /// Declared type index of a function, including imported numbering.
    pub fn function_type_index(&self, function: u32) -> Option<u32> {
        self.functions.get(function as usize).copied()
    }
    /// The function type at `type_index`, or `None` for another composite.
    pub fn func_type(&self, type_index: u32) -> Option<&FuncType> {
        match &self.types.get(type_index as usize)?.composite_type.inner {
            CompositeInnerType::Func(ty) => Some(ty),
            _ => None,
        }
    }
    /// The parameter and result types of a function index.
    pub fn function_signature(&self, function: u32) -> Option<&FuncType> {
        self.func_type(self.function_type_index(function)?)
    }
}

/// One open control frame as the arity rules see it.
#[derive(Clone, Copy)]
pub struct Label {
    pub kind: FrameKind,
    pub block_type: BlockType,
}

struct View<'a> {
    module: &'a ModuleTypes,
    labels: &'a [Label],
}

impl ModuleArity for View<'_> {
    fn sub_type_at(&self, type_idx: u32) -> Option<&SubType> {
        self.module.types.get(type_idx as usize)
    }
    fn tag_type_arity(&self, at: u32) -> Option<(u32, u32)> {
        let ty = self.module.func_type(*self.module.tags.get(at as usize)?)?;
        Some((ty.params().len() as u32, ty.results().len() as u32))
    }
    fn type_index_of_function(&self, function_idx: u32) -> Option<u32> {
        self.module.function_type_index(function_idx)
    }
    fn func_type_of_cont_type(&self, c: &ContType) -> Option<&FuncType> {
        self.module.func_type(c.0.as_module_index()?)
    }
    fn sub_type_of_ref_type(&self, rt: &RefType) -> Option<&SubType> {
        self.sub_type_at(rt.type_index()?.as_module_index()?)
    }
    fn control_stack_height(&self) -> u32 {
        self.labels.len() as u32
    }
    fn label_block(&self, depth: u32) -> Option<(BlockType, FrameKind)> {
        let position = self.labels.len().checked_sub(depth as usize + 1)?;
        let label = self.labels.get(position)?;
        Some((label.block_type, label.kind))
    }
}

/// Declared `(pops, pushes)` of `op` with `labels` open, outermost first.
pub fn arity(op: &Operator<'_>, module: &ModuleTypes, labels: &[Label]) -> Option<(u32, u32)> {
    op.operator_arity(&View { module, labels })
}

/// Declared `(params, results)` of a block type.
pub fn block_arity(module: &ModuleTypes, block_type: BlockType) -> Option<(u32, u32)> {
    View {
        module,
        labels: &[],
    }
    .block_type_arity(block_type)
}

/// How many values a branch to `label` carries: a loop's parameters, any
/// other frame's results.
pub fn branch_arity(module: &ModuleTypes, label: Label) -> Option<u32> {
    let (params, results) = block_arity(module, label.block_type)?;
    Some(if label.kind == FrameKind::Loop {
        params
    } else {
        results
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmparser::{Parser, Payload};

    fn module_of(wat: &str) -> (ModuleTypes, Vec<u8>) {
        let bytes = wat::parse_str(wat).unwrap();
        let mut module = ModuleTypes::default();
        for payload in Parser::new(0).parse_all(&bytes) {
            match payload.unwrap() {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        module.add_rec_group(group.unwrap());
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        if let wasmparser::TypeRef::Func(ty) = import.unwrap().ty {
                            module.add_imported_function(ty);
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        module.add_function(ty.unwrap());
                    }
                }
                _ => {}
            }
        }
        (module, bytes)
    }

    #[test]
    fn calls_and_branches_take_their_declared_counts() {
        let (module, _) = module_of(
            r#"(module (import "env" "f" (func (param i32 i64) (result f32)))
                (func (result i32) i32.const 1))"#,
        );
        assert_eq!(module.imported_functions(), 1);
        let function = Label {
            kind: FrameKind::Block,
            block_type: BlockType::FuncType(module.function_type_index(1).unwrap()),
        };
        let call = Operator::Call { function_index: 0 };
        assert_eq!(arity(&call, &module, &[function]), Some((2, 1)));
        assert_eq!(arity(&Operator::Return, &module, &[function]), Some((1, 0)));
        let looped = Label {
            kind: FrameKind::Loop,
            block_type: BlockType::Type(wasmparser::ValType::I32),
        };
        // A branch to a loop carries its parameters, here none.
        assert_eq!(branch_arity(&module, looped), Some(0));
        assert_eq!(branch_arity(&module, function), Some(1));
        // An unknown function index has no declared effect.
        let unknown = Operator::Call { function_index: 9 };
        assert_eq!(arity(&unknown, &module, &[function]), None);
    }
}
