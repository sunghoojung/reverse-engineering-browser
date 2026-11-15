//! The operand-stack and control-frame rules of one Wasm function body.
//!
//! This is the one stack-simulation layer: the readable lift
//! (`wasm_pseudocode`) folds instructions into expressions with it, and the
//! value-flow simulation (`wasm_def_use`) builds def-use edges with it. Each
//! keeps its own payload per frame and per stack entry; what an operator does
//! to the stack and to the open frames is decided here once:
//!
//! - [`ModuleTypes`] holds what a stack effect depends on outside the body:
//!   the type section, each function's declared type (imports first, as
//!   function indexes count them) and each tag's type. Fill it from a module
//!   pass in section order. It resolves the counts of block types, calls and
//!   tags.
//! - [`effect`] classifies an operator into an [`Effect`]: which frame it
//!   opens, moves to an arm of or closes, which label it branches to, which
//!   function it calls and whether control falls through after it
//!   ([`Effect::ends_path`]). Every other operator is [`Effect::Plain`], with
//!   the counts [`arity`] declares.
//! - [`Control`] is the stack of open frames, the function's own frame at
//!   position 0. Each [`Frame`] has the shared facts (its [`Kind`], parameter
//!   and result counts, and the operand-stack height below it) and the
//!   consumer's own `state`. It resolves branch labels and keeps the
//!   [`Label`] list [`arity`] needs.
//! - [`arity`] returns `(pops, pushes)` for any operator wasmparser decodes,
//!   from wasmparser's own `operator_arity` table, so every opcode the pinned
//!   parser knows has a declared effect. `None` means the effect depends on
//!   something this module does not resolve (an unknown type or label), and a
//!   caller must treat the stack shape after it as unknown.
//!
//! Nothing here runs the module, validates types, or tracks values; the
//! effects are declared counts. What a consumer does with an unknown count,
//! with unreachable code and with its budgets stays the consumer's.
use std::ops::{Index, IndexMut};
use wasmparser::{
    BlockType, BrTable, Catch, CompositeInnerType, ContType, FrameKind, FuncType, ModuleArity,
    Operator, RecGroup, RefType, SubType,
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
    /// Functions in the index space, imports included.
    pub fn function_count(&self) -> u64 {
        self.functions.len() as u64
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
    /// Parameter and result counts of the function type at `type_index`.
    pub fn type_arity(&self, type_index: u32) -> Option<(u32, u32)> {
        self.func_type(type_index)
            .map(|ty| (ty.params().len() as u32, ty.results().len() as u32))
    }
    /// Declared `(params, results)` of a block type. A type index must name
    /// a function type; any other composite has no block arity.
    pub fn block_arity(&self, block_type: BlockType) -> Option<(u32, u32)> {
        match block_type {
            BlockType::Empty => Some((0, 0)),
            BlockType::Type(_) => Some((0, 1)),
            BlockType::FuncType(index) => self.type_arity(index),
        }
    }
    /// How many values a tag carries: its function type's parameters.
    pub fn tag_params(&self, tag: u32) -> Option<u32> {
        self.type_arity(*self.tags.get(tag as usize)?)
            .map(|(params, _)| params)
    }
    /// `(params, results)` of a call. The callee operand of an indirect or
    /// reference call, popped after the arguments, is not counted.
    pub fn call_arity(&self, callee: Callee) -> Option<(u32, u32)> {
        match callee {
            Callee::Function(function) => self.type_arity(self.function_type_index(function)?),
            Callee::Indirect { type_index, .. } | Callee::Ref { type_index } => {
                self.type_arity(type_index)
            }
        }
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
    module.block_arity(block_type)
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

/// What a frame is. `Else` and `Catch` are the arms an `if` and a legacy
/// `try` move to; `Function` is the body's own frame, a branch to which
/// returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Function,
    Block,
    Loop,
    If,
    Else,
    Try,
    Catch,
    TryTable,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Block => "block",
            Self::Loop => "loop",
            Self::If => "if",
            Self::Else => "else",
            Self::Try => "try",
            Self::Catch => "catch",
            Self::TryTable => "try_table",
        }
    }
    fn label_kind(self) -> FrameKind {
        match self {
            Self::Function | Self::Block => FrameKind::Block,
            Self::Loop => FrameKind::Loop,
            Self::If => FrameKind::If,
            Self::Else => FrameKind::Else,
            Self::Try => FrameKind::LegacyTry,
            Self::Catch => FrameKind::LegacyCatch,
            Self::TryTable => FrameKind::TryTable,
        }
    }
}

/// The function a call reaches: a direct index, a table entry of a declared
/// type, or a typed function reference.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Callee {
    Function(u32),
    Indirect { type_index: u32, table: u32 },
    Ref { type_index: u32 },
}

/// What a GC branch tests before it branches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Test {
    /// `br_on_null`: branches with the operands below the reference, and
    /// leaves the non-null reference when it falls through.
    Null,
    /// `br_on_non_null`: branches with the reference on top, and leaves
    /// nothing in its place when it falls through.
    NonNull,
    Cast,
    CastFail,
}

/// What one operator does to the open frames and to control flow.
#[derive(Clone, Copy)]
pub enum Effect<'o> {
    /// `block`, `loop`, `if`, legacy `try` and `try_table` open a frame of
    /// `kind` whose parameters stay on the stack as its first values; an `if`
    /// pops its condition first. `catches` are a `try_table`'s clauses,
    /// resolved with [`Clause::of`] before the frame is opened.
    Open {
        kind: Kind,
        block_type: BlockType,
        catches: &'o [Catch],
    },
    /// Moves an `if` frame to its `else` arm, restarting from its parameters.
    Else,
    /// Moves a legacy `try` or `catch` frame to a `catch` (`tag`) or
    /// `catch_all` (`None`) arm, which starts from the tag's values.
    Catch {
        tag: Option<u32>,
    },
    /// Closes the innermost frame; the function's own frame ends the body.
    End,
    /// Closes a legacy `try`, sending what it catches to the handler around
    /// the frame `depth` names from outside the `try`.
    Delegate {
        depth: u32,
    },
    /// `br` and `br_if` (`conditional`, which pops its condition first).
    Branch {
        depth: u32,
        conditional: bool,
    },
    /// Pops its selector and branches to one of its labels.
    BrTable(&'o BrTable<'o>),
    Return,
    /// Pops the callee's parameters (then the callee operand, for an indirect
    /// or reference call) and pushes its results; a `tail` call returns them
    /// to this function's caller instead.
    Call {
        callee: Callee,
        tail: bool,
    },
    /// `throw` pops its tag's values; `throw_ref` (`None`) pops an exnref.
    Throw {
        tag: Option<u32>,
    },
    Rethrow {
        depth: u32,
    },
    /// A GC branch on its reference operand, taken or not at run time.
    BrOn {
        depth: u32,
        test: Test,
    },
    /// Stack switching: `resume`, `resume_throw`, `switch` and `suspend`
    /// move control to another stack.
    Switching,
    Unreachable,
    /// No control effect: pops and pushes what [`arity`] declares.
    Plain,
}

impl Effect<'_> {
    /// Opens, moves to an arm of, or closes a frame. Structure is followed
    /// even in unreachable code, so the frames stay aligned with the bytes.
    pub fn is_structure(&self) -> bool {
        matches!(
            self,
            Self::Open { .. } | Self::Else | Self::Catch { .. } | Self::End | Self::Delegate { .. }
        )
    }
    /// Control never falls through to the next instruction, so the rest of
    /// the frame up to its next arm or end is unreachable, and the frame's
    /// stack is polymorphic there.
    pub fn ends_path(&self) -> bool {
        matches!(
            self,
            Self::Unreachable
                | Self::Branch {
                    conditional: false,
                    ..
                }
                | Self::BrTable(_)
                | Self::Return
                | Self::Call { tail: true, .. }
                | Self::Throw { .. }
                | Self::Rethrow { .. }
        )
    }
}

/// Classifies one operator.
pub fn effect<'o>(op: &'o Operator<'o>) -> Effect<'o> {
    let open = |kind, block_type| Effect::Open {
        kind,
        block_type,
        catches: &[],
    };
    match op {
        Operator::Block { blockty } => open(Kind::Block, *blockty),
        Operator::Loop { blockty } => open(Kind::Loop, *blockty),
        Operator::If { blockty } => open(Kind::If, *blockty),
        Operator::Try { blockty } => open(Kind::Try, *blockty),
        Operator::TryTable { try_table } => Effect::Open {
            kind: Kind::TryTable,
            block_type: try_table.ty,
            catches: &try_table.catches,
        },
        Operator::Else => Effect::Else,
        Operator::Catch { tag_index } => Effect::Catch {
            tag: Some(*tag_index),
        },
        Operator::CatchAll => Effect::Catch { tag: None },
        Operator::End => Effect::End,
        Operator::Delegate { relative_depth } => Effect::Delegate {
            depth: *relative_depth,
        },
        Operator::Br { relative_depth } => Effect::Branch {
            depth: *relative_depth,
            conditional: false,
        },
        Operator::BrIf { relative_depth } => Effect::Branch {
            depth: *relative_depth,
            conditional: true,
        },
        Operator::BrTable { targets } => Effect::BrTable(targets),
        Operator::Return => Effect::Return,
        Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
            Effect::Call {
                callee: Callee::Function(*function_index),
                tail: matches!(op, Operator::ReturnCall { .. }),
            }
        }
        Operator::CallIndirect {
            type_index,
            table_index,
        }
        | Operator::ReturnCallIndirect {
            type_index,
            table_index,
        } => Effect::Call {
            callee: Callee::Indirect {
                type_index: *type_index,
                table: *table_index,
            },
            tail: matches!(op, Operator::ReturnCallIndirect { .. }),
        },
        Operator::CallRef { type_index } | Operator::ReturnCallRef { type_index } => Effect::Call {
            callee: Callee::Ref {
                type_index: *type_index,
            },
            tail: matches!(op, Operator::ReturnCallRef { .. }),
        },
        Operator::Throw { tag_index } => Effect::Throw {
            tag: Some(*tag_index),
        },
        Operator::ThrowRef => Effect::Throw { tag: None },
        Operator::Rethrow { relative_depth } => Effect::Rethrow {
            depth: *relative_depth,
        },
        Operator::BrOnNull { relative_depth } => Effect::BrOn {
            depth: *relative_depth,
            test: Test::Null,
        },
        Operator::BrOnNonNull { relative_depth } => Effect::BrOn {
            depth: *relative_depth,
            test: Test::NonNull,
        },
        Operator::BrOnCast { relative_depth, .. } => Effect::BrOn {
            depth: *relative_depth,
            test: Test::Cast,
        },
        Operator::BrOnCastFail { relative_depth, .. } => Effect::BrOn {
            depth: *relative_depth,
            test: Test::CastFail,
        },
        Operator::Resume { .. }
        | Operator::ResumeThrow { .. }
        | Operator::Switch { .. }
        | Operator::Suspend { .. } => Effect::Switching,
        Operator::Unreachable => Effect::Unreachable,
        _ => Effect::Plain,
    }
}

/// One `try_table` catch clause: where a caught exception goes and how many
/// values it carries there.
#[derive(Clone, Copy, Debug)]
pub struct Clause {
    /// The tag it catches; `None` for `catch_all` and `catch_all_ref`.
    pub tag: Option<u32>,
    /// `catch_ref` and `catch_all_ref` also deliver the exnref.
    pub with_ref: bool,
    pub label: u32,
    /// The frame the clause branches to, `None` past the open frames.
    pub target: Option<usize>,
    /// The tag's values plus the exnref, `None` for an undeclared tag.
    pub values: Option<u32>,
}

impl Clause {
    /// Resolves `catch` against the frames open around the `try_table`, so
    /// call it before the `try_table`'s own frame is pushed.
    pub fn of<S>(catch: &Catch, module: &ModuleTypes, control: &Control<S>) -> Self {
        let (tag, label, with_ref) = match catch {
            Catch::One { tag, label } => (Some(*tag), *label, false),
            Catch::OneRef { tag, label } => (Some(*tag), *label, true),
            Catch::All { label } => (None, *label, false),
            Catch::AllRef { label } => (None, *label, true),
        };
        let values = match tag {
            Some(tag) => module.tag_params(tag),
            None => Some(0),
        }
        .map(|params| params + u32::from(with_ref));
        Clause {
            tag,
            with_ref,
            label,
            target: control.target(label),
            values,
        }
    }
}

/// One open frame: the facts the stack rules need, and the consumer's own
/// `state`.
pub struct Frame<S> {
    pub kind: Kind,
    /// The kind it opened as; `Else` and `Catch` keep `If` and `Try` here.
    pub opened: Kind,
    pub params: u32,
    pub results: u32,
    /// Operand-stack height below the frame's own values.
    pub height: usize,
    pub state: S,
}

impl<S> Frame<S> {
    /// How many values a branch to this frame carries: a loop's parameters
    /// (a branch to a loop restarts it), any other frame's results.
    pub fn branch_arity(&self) -> u32 {
        if self.kind == Kind::Loop {
            self.params
        } else {
            self.results
        }
    }
}

/// The open frames of one body, outermost first, with the labels [`arity`]
/// reads kept beside them.
pub struct Control<S> {
    frames: Vec<Frame<S>>,
    labels: Vec<Label>,
}

impl<S> Control<S> {
    /// The function's own frame, of the function type at `type_index`. It has
    /// no parameters on the stack, and a branch to it returns `results`.
    pub fn new(type_index: u32, results: u32, state: S) -> Self {
        Control {
            frames: vec![Frame {
                kind: Kind::Function,
                opened: Kind::Function,
                params: 0,
                results,
                height: 0,
                state,
            }],
            labels: vec![Label {
                kind: Kind::Function.label_kind(),
                block_type: BlockType::FuncType(type_index),
            }],
        }
    }
    /// Opens a frame whose `(params, results)` are `arity`, with `height`
    /// values of enclosing frames below it.
    pub fn push(
        &mut self,
        kind: Kind,
        block_type: BlockType,
        (params, results): (u32, u32),
        height: usize,
        state: S,
    ) {
        self.frames.push(Frame {
            kind,
            opened: kind,
            params,
            results,
            height,
            state,
        });
        self.labels.push(Label {
            kind: kind.label_kind(),
            block_type,
        });
    }
    pub fn pop(&mut self) -> Option<Frame<S>> {
        self.labels.pop();
        self.frames.pop()
    }
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
    pub fn last(&self) -> Option<&Frame<S>> {
        self.frames.last()
    }
    pub fn last_mut(&mut self) -> Option<&mut Frame<S>> {
        self.frames.last_mut()
    }
    pub fn iter(&self) -> std::slice::Iter<'_, Frame<S>> {
        self.frames.iter()
    }
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Frame<S>> {
        self.frames.iter_mut()
    }
    /// The operand-stack height the innermost frame starts at: a pop below
    /// it reads past what the frame owns.
    pub fn base(&self) -> usize {
        self.frames.last().map_or(0, |frame| frame.height)
    }
    /// The frame a branch of relative `depth` names, `None` past the open
    /// frames.
    pub fn target(&self, depth: u32) -> Option<usize> {
        self.frames.len().checked_sub(depth as usize + 1)
    }
    /// The frame a `delegate` of `depth` names: the depth counts from the
    /// frame around the `try`.
    pub fn delegate_target(&self, depth: u32) -> Option<usize> {
        self.frames.len().checked_sub(depth as usize + 2)
    }
    /// Whether the innermost frame can take `effect`: an `else` needs an `if`
    /// arm, a `catch` a `try` or `catch` arm, and a `delegate` a `try`.
    pub fn accepts(&self, effect: &Effect<'_>) -> bool {
        let kind = self.frames.last().map(|frame| frame.kind);
        match effect {
            Effect::Else => kind == Some(Kind::If),
            Effect::Catch { .. } => matches!(kind, Some(Kind::Try | Kind::Catch)),
            Effect::Delegate { .. } => kind == Some(Kind::Try),
            _ => true,
        }
    }
    /// Moves the innermost frame to its `else` or `catch` arm.
    pub fn enter_arm(&mut self, kind: Kind) {
        if let Some(frame) = self.frames.last_mut() {
            frame.kind = kind;
        }
        if let Some(label) = self.labels.last_mut() {
            label.kind = kind.label_kind();
        }
    }
    /// Declared `(pops, pushes)` of `op` with these frames open.
    pub fn arity(&self, op: &Operator<'_>, module: &ModuleTypes) -> Option<(u32, u32)> {
        arity(op, module, &self.labels)
    }
}

impl<S> Index<usize> for Control<S> {
    type Output = Frame<S>;
    fn index(&self, position: usize) -> &Frame<S> {
        &self.frames[position]
    }
}

impl<S> IndexMut<usize> for Control<S> {
    fn index_mut(&mut self, position: usize) -> &mut Frame<S> {
        &mut self.frames[position]
    }
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
                Payload::TagSection(reader) => {
                    for tag in reader {
                        module.add_tag(tag.unwrap().func_type_idx);
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

    #[test]
    fn frames_resolve_labels_arms_and_clauses() {
        let (module, _) = module_of(
            r#"(module (type $p (func (param i32 i64) (result f32))) (tag $e (param i32 i64))
                (type $s (struct)) (func))"#,
        );
        assert_eq!(module.block_arity(BlockType::FuncType(0)), Some((2, 1)));
        // A block type naming a struct type has no arity.
        assert_eq!(module.block_arity(BlockType::FuncType(1)), None);
        assert_eq!(module.tag_params(0), Some(2));
        assert_eq!(module.tag_params(1), None);
        assert_eq!(
            module.call_arity(Callee::Indirect {
                type_index: 0,
                table: 0
            }),
            Some((2, 1))
        );
        let mut control = Control::new(2, 0, ());
        control.push(Kind::Block, BlockType::Empty, (0, 0), 0, ());
        control.push(Kind::Loop, BlockType::FuncType(0), (2, 1), 0, ());
        assert_eq!(control.target(0), Some(2));
        assert_eq!(control.target(3), None);
        // A branch to the loop restarts it with its parameters.
        assert_eq!(control[2].branch_arity(), 2);
        assert_eq!(control[0].branch_arity(), 0);
        let catches = [
            Catch::One { tag: 0, label: 1 },
            Catch::AllRef { label: 0 },
            Catch::OneRef { tag: 7, label: 9 },
        ];
        let clauses: Vec<Clause> = catches
            .iter()
            .map(|catch| Clause::of(catch, &module, &control))
            .collect();
        assert_eq!((clauses[0].target, clauses[0].values), (Some(1), Some(2)));
        assert_eq!((clauses[1].target, clauses[1].values), (Some(2), Some(1)));
        assert_eq!((clauses[2].target, clauses[2].values), (None, None));
        control.pop();
        control.push(Kind::Try, BlockType::Empty, (0, 0), 0, ());
        assert!(control.accepts(&Effect::Catch { tag: None }));
        assert!(!control.accepts(&Effect::Else));
        assert_eq!(control.delegate_target(0), Some(1));
        control.enter_arm(Kind::Catch);
        assert!(control.accepts(&Effect::Catch { tag: Some(0) }));
        assert!(!control.accepts(&Effect::Delegate { depth: 0 }));
        assert_eq!(control.last().map(|frame| frame.opened), Some(Kind::Try));
    }

    #[test]
    fn every_transfer_ends_its_path() {
        let ends = |op: Operator<'_>| effect(&op).ends_path();
        assert!(ends(Operator::Unreachable));
        assert!(ends(Operator::Br { relative_depth: 0 }));
        assert!(!ends(Operator::BrIf { relative_depth: 0 }));
        assert!(ends(Operator::Return));
        assert!(ends(Operator::ReturnCall { function_index: 0 }));
        assert!(!ends(Operator::Call { function_index: 0 }));
        assert!(ends(Operator::ReturnCallRef { type_index: 0 }));
        assert!(ends(Operator::Throw { tag_index: 0 }));
        assert!(ends(Operator::ThrowRef));
        assert!(ends(Operator::Rethrow { relative_depth: 0 }));
        assert!(!ends(Operator::BrOnNull { relative_depth: 0 }));
        assert!(!ends(Operator::I32Add));
        assert!(effect(&Operator::Delegate { relative_depth: 0 }).is_structure());
        assert!(!effect(&Operator::Br { relative_depth: 0 }).is_structure());
    }
}
