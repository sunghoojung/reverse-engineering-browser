//! One parsed JavaScript artifact supplies structural sites and lexical proof.
//! Recovery remains independent; proof records can only remove its claims.
use super::{Classified, Kind, Memory, Meter, Repeats, Role, Site, Source, priority};
use oxc_allocator::Allocator;
use oxc_ast::{AstKind, ast::*};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_semantic::{Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::{node::NodeId, scope::ScopeId, symbol::SymbolId};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

const COLUMN_CHECKPOINT: usize = 4096;
const MAX_SITES: usize = 4096;
const PARSER_STACK: usize = 32 << 20;
const MAX_SYNTAX_DEPTH: usize = 8192;

#[cfg(test)]
thread_local! { static PARSER_ARENA: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn parser_arena_bytes() -> usize {
    PARSER_ARENA.get()
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
enum Refusal {
    Binding,
}
impl Refusal {
    fn reason(self) -> &'static str {
        "handler-binding-unproven"
    }
    fn detail(self) -> &'static str {
        AMBIGUOUS
    }
}
type Verdict = Result<Option<Role>, Refusal>;
const AMBIGUOUS: &str = "A handler table has no unique, stable lexical binding to an interpreter dispatch. Its entries are not claimed as guest opcodes.";
const PARSE_FAILED: &str =
    "JavaScript syntax or semantic analysis failed; recovered handlers have no binding proof.";

pub(crate) struct Proofs {
    // Exact original-byte starts of AST cases and object properties. No source
    // rescan is needed when base recovery asks whether a claim is justified.
    handlers: HashMap<(usize, bool), Verdict>,
    /// Array entries are keyed by position: the AST index of each element,
    /// counting holes, which a recovered handler index must equal.
    positions: HashMap<usize, u32>,
    failure: Option<String>,
    _memory: Memory,
}
impl Proofs {
    pub(crate) fn verdict(
        &self,
        offset: usize,
        table: bool,
        index: Option<u64>,
    ) -> Result<Option<Role>, &str> {
        if let Some(failure) = self.failure.as_deref() {
            return Err(failure);
        }
        if table
            && let Some(position) = self.positions.get(&offset)
            && index != Some(u64::from(*position))
        {
            return Err(Refusal::Binding.detail());
        }
        self.handlers
            .get(&(offset, table))
            .copied()
            .unwrap_or(Err(Refusal::Binding))
            .map_err(Refusal::detail)
    }
}

/// One-based line and character column of a byte offset. Continuation-byte
/// checkpoints keep a column lookup bounded even on one minified line.
pub(crate) struct Lines {
    starts: Vec<u32>,
    continuation: Vec<u32>,
    _memory: Memory,
}

impl Lines {
    pub fn new(source: &str, meter: &Meter) -> Self {
        let memory = Memory::new(meter);
        let mut starts = Vec::new();
        memory.push(&mut starts, 0);
        meter.charge(source.len() as u64 * 2);
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' && !memory.push(&mut starts, (index + 1) as u32) {
                break;
            }
        }
        let mut continuation = Vec::new();
        memory.push(&mut continuation, 0);
        let mut count = 0u32;
        for chunk in source.as_bytes().chunks(COLUMN_CHECKPOINT) {
            count += chunk.iter().filter(|byte| (**byte & 0xc0) == 0x80).count() as u32;
            if !memory.push(&mut continuation, count) {
                break;
            }
        }
        Self {
            starts,
            continuation,
            _memory: memory,
        }
    }

    fn continuation_before(&self, source: &str, offset: usize) -> usize {
        if self.continuation.last() == Some(&0) {
            return 0;
        }
        let checkpoint = offset / COLUMN_CHECKPOINT;
        self.continuation[checkpoint] as usize
            + source.as_bytes()[checkpoint * COLUMN_CHECKPOINT..offset]
                .iter()
                .filter(|byte| (**byte & 0xc0) == 0x80)
                .count()
    }

    /// Line, column, and the bytes counted to find them.
    fn locate(&self, source: &str, offset: usize) -> (usize, usize, u64) {
        let line = self
            .starts
            .partition_point(|start| *start as usize <= offset);
        let start = self.starts[line - 1] as usize;
        let characters = (offset - start)
            - (self.continuation_before(source, offset) - self.continuation_before(source, start));
        let scanned = if self.continuation.last() == Some(&0) {
            1
        } else {
            (offset % COLUMN_CHECKPOINT + start % COLUMN_CHECKPOINT) as u64 + 1
        };
        (line, characters + 1, scanned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key<'a> {
    Symbol(SymbolId),
    Member(SymbolId, &'a str),
    This(NodeId, &'a str),
    Slot(SymbolId, u64),
}
#[derive(Clone, Copy, Default)]
struct Context {
    function: Option<NodeId>,
    this: Option<NodeId>,
    loop_id: Option<NodeId>,
    parameter: bool,
}
#[derive(Clone, Copy)]
struct Definition<'a> {
    value: &'a Expression<'a>,
    at: u32,
    function: Option<NodeId>,
    /// The `this` owner and scope of the write, for resolving its value.
    this: Option<NodeId>,
    scope: ScopeId,
}
#[derive(Clone, Copy)]
struct Write {
    span: Span,
    function: Option<NodeId>,
    arithmetic: bool,
}
struct Candidate<'a> {
    node: NodeId,
    selector: &'a Expression<'a>,
    table: Option<Key<'a>>,
    kind: Kind,
    instruction: &'static str,
    arms: Option<u64>,
    strings: bool,
}
#[derive(Clone, Copy)]
struct Trace<'a> {
    source: Source,
    repeats: bool,
    anchor: Option<u32>,
    buffer: Option<Key<'a>>,
    buffer_kind: Option<&'static str>,
    lookup: bool,
    /// The selector is the value a statically bound helper returns.
    helper: bool,
}
/// A followed helper call and the function it resolves to. Its parameters
/// stand for the call's arguments.
type Frame<'a> = (&'a CallExpression<'a>, NodeId);
/// Nested helper calls followed for one selector.
const MAX_HELPER_FRAMES: usize = 4;
impl Trace<'_> {
    fn new(source: Source) -> Self {
        Self {
            source,
            repeats: false,
            anchor: None,
            buffer: None,
            buffer_kind: None,
            lookup: false,
            helper: false,
        }
    }
}
struct Query {
    left: u32,
    limited: bool,
}
impl Query {
    fn step(&mut self, meter: &Meter, depth: u8) -> bool {
        if self.left == 0 || depth > 16 {
            self.limited = true;
            return false;
        }
        self.left -= 1;
        meter.charge(1)
    }
}
struct Facts<'s, 'a> {
    semantic: &'s Semantic<'a>,
    meter: &'s Meter,
    contexts: Vec<Context>,
    opaque: Vec<bool>,
    definitions: HashMap<Key<'a>, Vec<Definition<'a>>>,
    constant_definitions: HashSet<(Key<'a>, Option<NodeId>, Option<NodeId>, u8)>,
    writes: HashMap<Key<'a>, Vec<Write>>,
    parameters: HashSet<SymbolId>,
    changed_symbols: HashSet<SymbolId>,
    symbol_write_counts: HashMap<SymbolId, usize>,
    loop_tables: HashMap<NodeId, HashSet<Key<'a>>>,
    invoked_loops: HashMap<NodeId, NodeId>,
    /// Each function stored directly in a table literal: the table's key
    /// and the literal node.
    table_functions: HashMap<NodeId, (Key<'a>, NodeId)>,
    /// The functions stored in each table, in AST order.
    table_members: HashMap<Key<'a>, Vec<NodeId>>,
    member_write_counts: HashMap<Key<'a>, usize>,
    /// Object and array table literals with the key they are bound to.
    objects: HashMap<NodeId, (Key<'a>, u32, ScopeId)>,
    /// Tables whose entries are written through a computed member, deleted
    /// or reordered in place: an entry's position no longer names its handler.
    element_writes: HashSet<Key<'a>>,
    /// Values each function returns, including concise arrow bodies.
    returns: HashMap<NodeId, Vec<&'a Expression<'a>>>,
    /// A simple parameter's function and position.
    parameter_positions: HashMap<SymbolId, (NodeId, usize)>,
    /// Statically bound helpers: unreassigned function declarations and
    /// variables bound once to a function.
    helpers: HashMap<SymbolId, NodeId>,
    /// `this` methods per class body or object literal; None when a name is
    /// defined more than once there or also as a field or accessor.
    methods: HashMap<(NodeId, &'a str), Option<NodeId>>,
    /// The class body or object literal defining each method function, and
    /// the class symbol a subclass could extend.
    method_owners: HashMap<NodeId, (NodeId, Option<SymbolId>)>,
    /// Static member names written anywhere, which can replace a method.
    member_names_written: HashSet<&'a str>,
    /// Classes extended by name, and whether any class extends an
    /// expression that could be any class.
    extended: HashSet<SymbolId>,
    opaque_extends: bool,
    this_computed_write: bool,
    candidates: Vec<Candidate<'a>>,
}
impl<'s, 'a> Facts<'s, 'a> {
    fn symbol(&self, id: &IdentifierReference<'a>) -> Option<SymbolId> {
        self.semantic
            .scoping()
            .get_reference(id.reference_id.get()?)
            .symbol_id()
    }
    fn key(&self, expression: &'a Expression<'a>, context: Context) -> Option<Key<'a>> {
        match expression.get_inner_expression() {
            Expression::Identifier(id) => self.symbol(id).map(Key::Symbol),
            Expression::StaticMemberExpression(member) => {
                self.member(&member.object, member.property.name.as_str(), context)
            }
            Expression::ComputedMemberExpression(member) => {
                let Expression::Identifier(id) = member.object.get_inner_expression() else {
                    return None;
                };
                let Expression::NumericLiteral(number) = member.expression.get_inner_expression()
                else {
                    return None;
                };
                self.symbol(id)
                    .map(|symbol| Key::Slot(symbol, number.value.to_bits()))
            }
            _ => None,
        }
    }
    fn member(
        &self,
        receiver: &'a Expression<'a>,
        name: &'a str,
        context: Context,
    ) -> Option<Key<'a>> {
        match receiver.get_inner_expression() {
            Expression::Identifier(id) => self.symbol(id).map(|symbol| Key::Member(symbol, name)),
            Expression::ThisExpression(_) => context.this.map(|owner| Key::This(owner, name)),
            _ => None,
        }
    }
    fn target(&self, target: &'a AssignmentTarget<'a>, context: Context) -> Option<Key<'a>> {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => self.symbol(id).map(Key::Symbol),
            AssignmentTarget::StaticMemberExpression(m) => {
                self.member(&m.object, m.property.name.as_str(), context)
            }
            _ => None,
        }
    }
    fn simple_target(
        &self,
        target: &'a SimpleAssignmentTarget<'a>,
        context: Context,
    ) -> Option<Key<'a>> {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
                self.symbol(id).map(Key::Symbol)
            }
            SimpleAssignmentTarget::StaticMemberExpression(m) => {
                self.member(&m.object, m.property.name.as_str(), context)
            }
            _ => None,
        }
    }
    fn scope_opaque(&self, scope: ScopeId) -> bool {
        self.opaque[scope.index()]
    }
    fn context(&self, node: NodeId) -> Context {
        self.contexts[node.index()]
    }
    fn object_owner(&self, object: NodeId) -> Option<(Key<'a>, u32, ScopeId)> {
        let nodes = self.semantic.nodes();
        let parent = nodes.parent_node(object);
        let context = self.context(parent.id());
        let key = match parent.kind() {
            AstKind::VariableDeclarator(d) => {
                let BindingPattern::BindingIdentifier(id) = &d.id else {
                    return None;
                };
                Key::Symbol(id.symbol_id.get()?)
            }
            AstKind::AssignmentExpression(a) => self.target(&a.left, context)?,
            _ => return None,
        };
        Some((key, parent.span().start, parent.scope_id()))
    }
    fn loop_id(&self, node: NodeId) -> Option<NodeId> {
        let context = self.context(node);
        context.loop_id.or_else(|| {
            context
                .function
                .and_then(|function| self.invoked_loops.get(&function).copied())
        })
    }
    fn loop_span(&self, node: NodeId) -> Option<Span> {
        self.loop_id(node)
            .map(|id| self.semantic.nodes().get_node(id).span())
    }
    fn executes_in_loop(
        &self,
        function: Option<NodeId>,
        span: Span,
        candidate: &Candidate<'a>,
    ) -> bool {
        self.loop_span(candidate.node)
            .is_some_and(|range| range.start <= span.start && span.end <= range.end)
            || function.is_some_and(|function| {
                self.invoked_loops.get(&function).copied() == self.loop_id(candidate.node)
            })
    }
    fn add_definition(
        &mut self,
        key: Key<'a>,
        value: &'a Expression<'a>,
        at: u32,
        context: Context,
        scope: ScopeId,
    ) {
        let literal = match value.get_inner_expression() {
            Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => Some(0),
            Expression::StringLiteral(_) => Some(1),
            _ => None,
        };
        if let Some(kind) = literal
            && !self
                .constant_definitions
                .insert((key, context.function, context.loop_id, kind))
        {
            return;
        }
        self.definitions.entry(key).or_default().push(Definition {
            value,
            at,
            function: context.function,
            this: context.this,
            scope,
        });
    }
    fn index(semantic: &'s Semantic<'a>, meter: &'s Meter) -> Self {
        let nodes = semantic.nodes();
        let scoping = semantic.scoping();
        let mut aliased = Vec::new();
        let mut facts = Self {
            semantic,
            meter,
            contexts: vec![Context::default(); nodes.len()],
            opaque: vec![false; scoping.scopes_len()],
            definitions: HashMap::new(),
            constant_definitions: HashSet::new(),
            writes: HashMap::new(),
            parameters: HashSet::new(),
            changed_symbols: HashSet::new(),
            symbol_write_counts: HashMap::new(),
            loop_tables: HashMap::new(),
            invoked_loops: HashMap::new(),
            table_functions: HashMap::new(),
            table_members: HashMap::new(),
            member_write_counts: HashMap::new(),
            objects: HashMap::new(),
            element_writes: HashSet::new(),
            returns: HashMap::new(),
            parameter_positions: HashMap::new(),
            helpers: HashMap::new(),
            methods: HashMap::new(),
            method_owners: HashMap::new(),
            member_names_written: HashSet::new(),
            extended: HashSet::new(),
            opaque_extends: false,
            this_computed_write: false,
            candidates: Vec::new(),
        };
        // Scope IDs and node IDs are preorder. Inherited facts take one lookup,
        // including at thousands of nested functions, never an ancestor walk.
        for scope in scoping.scope_descendants_from_root() {
            let flags = scoping.scope_flags(scope);
            facts.opaque[scope.index()] = flags.is_with()
                || scoping
                    .scope_parent_id(scope)
                    .is_some_and(|parent| facts.opaque[parent.index()]);
        }
        for node in nodes.iter() {
            let id = node.id();
            let mut context = if id.index() == 0 {
                Context::default()
            } else {
                facts.context(nodes.parent_id(id))
            };
            match node.kind() {
                AstKind::Function(_) => {
                    context.function = Some(id);
                    context.this = Some(id);
                    context.loop_id = None;
                    context.parameter = false;
                }
                AstKind::ArrowFunctionExpression(_) => {
                    context.function = Some(id);
                    context.loop_id = None;
                    context.parameter = false;
                }
                AstKind::Class(_) => {
                    context.this = None;
                    context.loop_id = None;
                }
                AstKind::FormalParameters(_) => context.parameter = true,
                AstKind::WhileStatement(_)
                | AstKind::ForStatement(_)
                | AstKind::DoWhileStatement(_)
                | AstKind::ForInStatement(_)
                | AstKind::ForOfStatement(_) => context.loop_id = Some(id),
                _ => (),
            }
            facts.contexts[id.index()] = context;
            if !meter.charge(8) {
                break;
            }
            match node.kind() {
                AstKind::IdentifierReference(reference) => {
                    if let Some(reference_id) = reference.reference_id.get() {
                        let reference = scoping.get_reference(reference_id);
                        if reference.is_write()
                            && let Some(symbol) = reference.symbol_id()
                        {
                            facts.changed_symbols.insert(symbol);
                            *facts.symbol_write_counts.entry(symbol).or_default() += 1;
                        }
                    }
                }
                AstKind::BindingIdentifier(binding) if context.parameter => {
                    if let Some(symbol) = binding.symbol_id.get() {
                        facts.parameters.insert(symbol);
                    }
                }
                AstKind::VariableDeclarator(d) => {
                    if let (BindingPattern::BindingIdentifier(binding), Some(value)) =
                        (&d.id, &d.init)
                        && let Some(symbol) = binding.symbol_id.get()
                    {
                        *facts.symbol_write_counts.entry(symbol).or_default() += 1;
                        facts.add_definition(
                            Key::Symbol(symbol),
                            value,
                            d.span.start,
                            context,
                            node.scope_id(),
                        );
                    }
                }
                AstKind::AssignmentExpression(a) => {
                    if let Some(key) = facts.target(&a.left, context) {
                        let arithmetic = a.operator.as_str() != "="
                            || matches!(a.right.get_inner_expression(), Expression::BinaryExpression(binary) if matches!(binary.operator.as_str(), "+" | "-") && facts.key(&binary.left, context) == Some(key));
                        facts.writes.entry(key).or_default().push(Write {
                            span: a.span,
                            function: context.function,
                            arithmetic,
                        });
                        if a.operator.as_str() == "=" {
                            facts.add_definition(
                                key,
                                &a.right,
                                a.span.start,
                                context,
                                node.scope_id(),
                            );
                        }
                    }
                }
                AstKind::UpdateExpression(update) => {
                    if let Some(key) = facts.simple_target(&update.argument, context) {
                        facts.writes.entry(key).or_default().push(Write {
                            span: update.span,
                            function: context.function,
                            arithmetic: true,
                        });
                    }
                }
                AstKind::ObjectExpression(object) => {
                    if let Some(owner) = facts.object_owner(id) {
                        facts.objects.insert(object.node_id.get(), owner);
                    }
                }
                AstKind::ArrayExpression(array) => {
                    if let Some(owner) = facts.object_owner(id) {
                        facts.objects.insert(array.node_id.get(), owner);
                    }
                }
                AstKind::CallExpression(call) => {
                    if let Expression::StaticMemberExpression(member) =
                        call.callee.get_inner_expression()
                        && matches!(
                            member.property.name.as_str(),
                            "splice"
                                | "shift"
                                | "unshift"
                                | "reverse"
                                | "sort"
                                | "copyWithin"
                                | "fill"
                        )
                        && let Some(key) = facts.key(&member.object, context)
                    {
                        facts.element_writes.insert(key);
                    }
                    let callee = match call.callee.get_inner_expression() {
                        Expression::StaticMemberExpression(member)
                            if matches!(member.property.name.as_str(), "call" | "apply") =>
                        {
                            member.object.get_inner_expression()
                        }
                        other => other,
                    };
                    if let Expression::ComputedMemberExpression(member) = callee {
                        facts.candidates.push(Candidate {
                            node: id,
                            selector: &member.expression,
                            table: facts.key(&member.object, context),
                            kind: Kind::HandlerTable,
                            instruction: "indexed call",
                            arms: None,
                            strings: false,
                        });
                    } else if let Expression::Identifier(callee) = callee
                        && let Some(symbol) = facts.symbol(callee)
                    {
                        aliased.push((id, symbol));
                    }
                }
                AstKind::ReturnStatement(statement) => {
                    if let (Some(value), Some(function)) = (&statement.argument, context.function) {
                        facts.returns.entry(function).or_default().push(value);
                    }
                }
                AstKind::ArrowFunctionExpression(arrow) => {
                    if let Some(value) = arrow.get_expression() {
                        facts.returns.entry(id).or_default().push(value);
                    }
                }
                AstKind::FormalParameters(parameters) => {
                    if let Some(function) = context.function {
                        for (position, parameter) in parameters.items.iter().enumerate() {
                            if let BindingPattern::BindingIdentifier(binding) = &parameter.pattern
                                && let Some(symbol) = binding.symbol_id.get()
                            {
                                facts
                                    .parameter_positions
                                    .insert(symbol, (function, position));
                            }
                        }
                    }
                }
                AstKind::Class(class) => {
                    if let Some(heritage) = &class.heritage {
                        match heritage.expression.get_inner_expression() {
                            Expression::Identifier(id) => {
                                if let Some(symbol) = facts.symbol(id) {
                                    facts.extended.insert(symbol);
                                }
                            }
                            _ => facts.opaque_extends = true,
                        }
                    }
                }
                AstKind::MethodDefinition(method) => {
                    let container = nodes.parent_id(id);
                    if let Some(std::borrow::Cow::Borrowed(name)) = method
                        .key
                        .static_name()
                        .and_then(|name| name.into_cow_str())
                        && !method.computed
                    {
                        let plain = method.kind == MethodDefinitionKind::Method && !method.r#static;
                        let class = match nodes.parent_kind(container) {
                            AstKind::Class(class) => class
                                .id
                                .as_ref()
                                .and_then(|id| id.symbol_id.get())
                                .or_else(|| match nodes.parent_kind(nodes.parent_id(container)) {
                                    AstKind::VariableDeclarator(declarator) => {
                                        match &declarator.id {
                                            BindingPattern::BindingIdentifier(id) => {
                                                id.symbol_id.get()
                                            }
                                            _ => None,
                                        }
                                    }
                                    _ => None,
                                }),
                            _ => None,
                        };
                        let function = method.value.node_id.get();
                        let defined = facts.methods.contains_key(&(container, name));
                        facts
                            .methods
                            .insert((container, name), (plain && !defined).then_some(function));
                        if plain {
                            facts.method_owners.insert(function, (container, class));
                        }
                    }
                }
                AstKind::ObjectProperty(property) => {
                    if !property.computed
                        && let Some(std::borrow::Cow::Borrowed(name)) = property
                            .key
                            .static_name()
                            .and_then(|name| name.into_cow_str())
                    {
                        let container = nodes.parent_id(id);
                        // An arrow's `this` is lexical, never the object.
                        let function = match &property.value {
                            Expression::FunctionExpression(function)
                                if property.kind == PropertyKind::Init =>
                            {
                                Some(function.node_id.get())
                            }
                            _ => None,
                        };
                        let defined = facts.methods.contains_key(&(container, name));
                        facts
                            .methods
                            .insert((container, name), function.filter(|_| !defined));
                        if let Some(function) = function {
                            facts.method_owners.insert(function, (container, None));
                        }
                    }
                }
                AstKind::PropertyDefinition(property) => {
                    // A field replaces a prototype method on every instance.
                    if let Some(std::borrow::Cow::Borrowed(name)) = property
                        .key
                        .static_name()
                        .and_then(|name| name.into_cow_str())
                    {
                        facts.methods.insert((nodes.parent_id(id), name), None);
                    }
                }
                AstKind::SwitchStatement(switch) => {
                    facts.candidates.push(Candidate {
                        node: id,
                        selector: &switch.discriminant,
                        table: None,
                        kind: Kind::SwitchOnValue,
                        instruction: "switch",
                        arms: Some(switch.cases.len() as u64),
                        strings: switch
                            .cases
                            .iter()
                            .any(|case| matches!(case.test, Some(Expression::StringLiteral(_)))),
                    });
                }
                _ => (),
            }
        }
        // Count only writes to this exact resolved receiver and static key.
        // This also includes destructuring, loop targets and deletes, whose
        // member targets are not direct AssignmentExpression children.
        for node in nodes.iter() {
            if !meter.charge(1) {
                break;
            }
            if let AstKind::ComputedMemberExpression(member) = node.kind()
                && matches!(
                    nodes.parent_kind(node.id()),
                    AstKind::AssignmentExpression(_)
                        | AstKind::UpdateExpression(_)
                        | AstKind::UnaryExpression(_)
                        | AstKind::ArrayAssignmentTarget(_)
                        | AstKind::AssignmentTargetRest(_)
                        | AstKind::AssignmentTargetWithDefault(_)
                        | AstKind::AssignmentTargetPropertyProperty(_)
                        | AstKind::ForInStatement(_)
                        | AstKind::ForOfStatement(_)
                )
                && let Some(key) = facts.key(&member.object, facts.context(node.id()))
            {
                let write = match nodes.parent_kind(node.id()) {
                    AstKind::AssignmentExpression(a) => a.left.span() == member.span,
                    AstKind::UnaryExpression(u) => u.operator.as_str() == "delete",
                    AstKind::ForInStatement(f) => f.left.span() == member.span,
                    AstKind::ForOfStatement(f) => f.left.span() == member.span,
                    _ => true,
                };
                if write {
                    facts.element_writes.insert(key);
                }
            }
            if let AstKind::ComputedMemberExpression(member) = node.kind()
                && matches!(
                    member.object.get_inner_expression(),
                    Expression::ThisExpression(_)
                )
                && match nodes.parent_kind(node.id()) {
                    AstKind::AssignmentExpression(a) => a.left.span() == member.span,
                    AstKind::UpdateExpression(_) => true,
                    AstKind::UnaryExpression(u) => u.operator.as_str() == "delete",
                    _ => false,
                }
            {
                facts.this_computed_write = true;
            }
            if let AstKind::StaticMemberExpression(member) = node.kind()
                && matches!(
                    nodes.parent_kind(node.id()),
                    AstKind::AssignmentExpression(_)
                        | AstKind::UpdateExpression(_)
                        | AstKind::UnaryExpression(_)
                        | AstKind::ArrayAssignmentTarget(_)
                        | AstKind::AssignmentTargetRest(_)
                        | AstKind::AssignmentTargetWithDefault(_)
                        | AstKind::AssignmentTargetPropertyProperty(_)
                        | AstKind::ForInStatement(_)
                        | AstKind::ForOfStatement(_)
                )
                && let Some(key) = facts.member(
                    &member.object,
                    member.property.name.as_str(),
                    facts.context(node.id()),
                )
            {
                // A member read on an assignment's right is not a write.
                let write = match nodes.parent_kind(node.id()) {
                    AstKind::AssignmentExpression(a) => a.left.span() == member.span,
                    AstKind::UnaryExpression(u) => u.operator.as_str() == "delete",
                    AstKind::ForInStatement(f) => f.left.span() == member.span,
                    AstKind::ForOfStatement(f) => f.left.span() == member.span,
                    _ => true,
                };
                if write {
                    *facts.member_write_counts.entry(key).or_default() += 1;
                }
            }
            if let AstKind::StaticMemberExpression(member) = node.kind()
                && match nodes.parent_kind(node.id()) {
                    AstKind::AssignmentExpression(a) => a.left.span() == member.span,
                    AstKind::UpdateExpression(_)
                    | AstKind::ArrayAssignmentTarget(_)
                    | AstKind::AssignmentTargetRest(_)
                    | AstKind::AssignmentTargetWithDefault(_)
                    | AstKind::AssignmentTargetPropertyProperty(_) => true,
                    AstKind::UnaryExpression(u) => u.operator.as_str() == "delete",
                    AstKind::ForInStatement(f) => f.left.span() == member.span,
                    AstKind::ForOfStatement(f) => f.left.span() == member.span,
                    _ => false,
                }
            {
                facts
                    .member_names_written
                    .insert(member.property.name.as_str());
            }
        }
        let mut comparisons = HashMap::<
            (Option<NodeId>, Option<NodeId>, SymbolId),
            (NodeId, &Expression<'a>, HashSet<u64>),
        >::new();
        for node in nodes.iter() {
            if !meter.charge(1) {
                break;
            }
            match node.kind() {
                AstKind::BinaryExpression(binary)
                    if matches!(binary.operator.as_str(), "==" | "===") =>
                {
                    let pair = match (
                        binary.left.get_inner_expression(),
                        binary.right.get_inner_expression(),
                    ) {
                        (Expression::Identifier(id), Expression::NumericLiteral(value)) => {
                            Some((id, &binary.left, value.value))
                        }
                        (Expression::NumericLiteral(value), Expression::Identifier(id)) => {
                            Some((id, &binary.right, value.value))
                        }
                        _ => None,
                    };
                    if let Some((id, expression, value)) = pair
                        && value.fract() == 0.0
                        && let Some(symbol) = facts.symbol(id)
                    {
                        let context = facts.context(node.id());
                        let group = comparisons
                            .entry((context.function, context.loop_id, symbol))
                            .or_insert_with(|| (node.id(), expression, HashSet::new()));
                        group.2.insert(value.to_bits());
                    }
                }
                AstKind::AssignmentExpression(assignment)
                    if assignment.operator.as_str() == "=" =>
                {
                    let context = facts.context(node.id());
                    if let Expression::CallExpression(call) =
                        assignment.right.get_inner_expression()
                        && let Some(key) = facts.target(&assignment.left, context)
                        && Some(key) == facts.key(&call.callee, context)
                    {
                        let table = facts.threaded_table(key, call);
                        facts.candidates.push(Candidate {
                            node: node.id(),
                            selector: &call.callee,
                            table,
                            kind: Kind::Threaded,
                            instruction: "self call",
                            arms: None,
                            strings: false,
                        });
                    }
                }
                _ => (),
            }
        }
        for (_, (node, selector, constants)) in comparisons {
            if constants.len() >= super::MIN_COMPARE_ARMS {
                facts.candidates.push(Candidate {
                    node,
                    selector,
                    table: None,
                    kind: Kind::CompareChain,
                    instruction: "if ladder",
                    arms: Some(constants.len() as u64),
                    strings: false,
                });
            }
        }
        // Annex B block functions can copy into an existing var binding at
        // runtime. Oxc resolves the block and outer references correctly, but
        // this implicit assignment has no IdentifierReference write node.
        // The hoist preflight bounds all ancestor work in this pass.
        for node in nodes.iter() {
            let AstKind::Function(function) = node.kind() else {
                continue;
            };
            if !function.is_declaration()
                || function.r#async
                || function.generator
                || scoping.scope_flags(node.scope_id()).is_strict_mode()
                || matches!(
                    nodes.parent_kind(node.id()),
                    AstKind::Program(_) | AstKind::FunctionBody(_)
                )
            {
                continue;
            }
            let Some(id) = &function.id else { continue };
            for scope in scoping.scope_ancestors(node.scope_id()) {
                if !meter.charge(1) {
                    break;
                }
                if scoping.scope_flags(scope).is_var() {
                    if let Some(symbol) = scoping.get_binding(scope, id.name)
                        && scoping
                            .symbol_flags(symbol)
                            .is_function_scoped_declaration()
                    {
                        facts.changed_symbols.insert(symbol);
                        *facts.symbol_write_counts.entry(symbol).or_default() += 1;
                    }
                    break;
                }
                // An intervening lexical declaration suppresses Annex B.
                if scope != node.scope_id() && scoping.get_binding(scope, id.name).is_some() {
                    break;
                }
            }
        }
        // A call through a temporary bound once to an indexed table read
        // (`const h = t[op]; h(s)`) dispatches that table like `t[op](s)`.
        // The read must be in the calling function, so its loop is the call's.
        for (node, symbol) in aliased {
            if !meter.charge(1) {
                break;
            }
            let key = Key::Symbol(symbol);
            let context = facts.context(node);
            let Some(&[definition]) = facts.definitions.get(&key).map(Vec::as_slice) else {
                continue;
            };
            if facts.symbol_write_counts.get(&symbol) != Some(&1)
                || facts.parameters.contains(&symbol)
                || definition.function != context.function
                || facts.scope_opaque(definition.scope)
            {
                continue;
            }
            let Expression::ComputedMemberExpression(member) =
                definition.value.get_inner_expression()
            else {
                continue;
            };
            let table = facts.key(
                &member.object,
                Context {
                    this: definition.this,
                    ..context
                },
            );
            facts.candidates.push(Candidate {
                node,
                selector: &member.expression,
                table,
                kind: Kind::HandlerTable,
                instruction: "aliased call",
                arms: None,
                strings: false,
            });
        }
        let resolved = facts
            .candidates
            .iter()
            .map(|candidate| candidate.table.map(|table| facts.resolve_table(table)))
            .collect::<Vec<_>>();
        for (candidate, table) in facts.candidates.iter_mut().zip(resolved) {
            candidate.table = table;
        }
        // Each function stored directly in a table is associated once. Writes
        // in these functions can advance that table's selector cursor.
        for node in nodes.iter() {
            if !meter.charge(1) {
                break;
            }
            if matches!(
                node.kind(),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            ) {
                let parent = nodes.parent_id(node.id());
                let literal = match nodes.kind(parent) {
                    AstKind::ObjectProperty(_) => nodes.parent_id(parent),
                    AstKind::ArrayExpression(_) => parent,
                    _ => continue,
                };
                if let Some(&(key, _, _)) = facts.objects.get(&literal) {
                    facts.table_functions.insert(node.id(), (key, literal));
                    facts.table_members.entry(key).or_default().push(node.id());
                }
            }
        }
        // Statically bound helpers: unreassigned function declarations, and
        // variables bound once to a function or arrow.
        for node in nodes.iter() {
            if !meter.charge(1) {
                break;
            }
            if let AstKind::Function(function) = node.kind()
                && let Some(id) = &function.id
                && let Some(symbol) = id.symbol_id.get()
                && !facts.changed_symbols.contains(&symbol)
            {
                facts.helpers.insert(symbol, node.id());
            }
        }
        let bound = facts
            .definitions
            .iter()
            .filter_map(|(key, definitions)| match (key, definitions.as_slice()) {
                (Key::Symbol(symbol), [definition])
                    if facts.symbol_write_counts.get(symbol) == Some(&1)
                        && !facts.scope_opaque(definition.scope)
                        && matches!(
                            definition.value.get_inner_expression(),
                            Expression::FunctionExpression(_)
                                | Expression::ArrowFunctionExpression(_)
                        ) =>
                {
                    Some((*symbol, definition.value.get_inner_expression().node_id()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        meter.charge(facts.definitions.len() as u64);
        facts.helpers.extend(bound);
        // Follow statically bound helper calls, at most 16 edges. This lets a
        // step function's dispatch, and a fetch helper's cursor writes,
        // inherit the invoking loop without rewalking bodies or following
        // unknown call targets.
        let mut calls = Vec::new();
        for node in nodes.iter() {
            if !meter.charge(1) {
                break;
            }
            if let AstKind::CallExpression(call) = node.kind()
                && let Some(function) = facts.helper(&call.callee, facts.context(node.id()))
            {
                calls.push((node.id(), function));
            }
        }
        // A table's own handler that dispatches it again outside any loop
        // threads to the next handler, directly or through a helper it calls
        // (a shared `next()`). The table literal is the cycle that repeats
        // it, so the handler, and through it that helper, inherit it as
        // their loop. A dispatch inside a loop is driven by that loop.
        let mut dispatching = HashMap::<NodeId, Vec<(usize, Key<'a>)>>::new();
        for (position, candidate) in facts.candidates.iter().enumerate() {
            let context = facts.context(candidate.node);
            if let (None, Some(function), Some(table)) =
                (context.loop_id, context.function, candidate.table)
            {
                dispatching
                    .entry(function)
                    .or_default()
                    .push((position, table));
            }
        }
        let mut threaded = Vec::new();
        let mut cycles = Vec::new();
        let mut enter = |function: NodeId, dispatcher: NodeId| {
            let Some(&(key, literal)) = facts.table_functions.get(&function) else {
                return;
            };
            for &(position, table) in dispatching.get(&dispatcher).into_iter().flatten() {
                if table == key {
                    threaded.push(position);
                    cycles.push((function, literal));
                }
            }
        };
        for &function in facts.table_functions.keys() {
            meter.charge(1);
            enter(function, function);
        }
        for &(call, helper) in &calls {
            meter.charge(1);
            if let Some(function) = facts.context(call).function {
                enter(function, helper);
            }
        }
        for position in threaded {
            facts.candidates[position].kind = Kind::Threaded;
        }
        for (function, literal) in cycles {
            facts.invoked_loops.entry(function).or_insert(literal);
        }
        for _ in 0..16 {
            let mut changed = false;
            for &(call, function) in &calls {
                if !meter.charge(1) {
                    break;
                }
                if let Some(loop_id) = facts.loop_id(call)
                    && let std::collections::hash_map::Entry::Vacant(entry) =
                        facts.invoked_loops.entry(function)
                {
                    entry.insert(loop_id);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for candidate in &facts.candidates {
            if let (Some(loop_id), Some(table)) = (facts.loop_id(candidate.node), candidate.table) {
                facts.loop_tables.entry(loop_id).or_default().insert(table);
            }
        }
        facts
    }
    /// The function a call statically resolves to: a bound helper, or a
    /// `this.m()` method defined once in the class body or object literal
    /// of the calling method. A name written as a member anywhere, a computed
    /// `this` write, or a subclass that could override it resolves nothing.
    fn helper(&self, callee: &'a Expression<'a>, context: Context) -> Option<NodeId> {
        match callee.get_inner_expression() {
            Expression::Identifier(id) => self.helpers.get(&self.symbol(id)?).copied(),
            Expression::StaticMemberExpression(member)
                if matches!(
                    member.object.get_inner_expression(),
                    Expression::ThisExpression(_)
                ) =>
            {
                let name = member.property.name.as_str();
                if self.this_computed_write || self.member_names_written.contains(name) {
                    return None;
                }
                let &(container, class) = self.method_owners.get(&context.this?)?;
                if class.is_some_and(|class| self.extended.contains(&class))
                    || (self.opaque_extends
                        && matches!(self.semantic.nodes().kind(container), AstKind::ClassBody(_)))
                {
                    return None;
                }
                *self.methods.get(&(container, name))?
            }
            _ => None,
        }
    }
    /// The table a self call `h = h(...)` threads through: a variable every
    /// other write of which reads one table (`h = ops[code[pc++]]`) or is a
    /// literal (`h = null`). A parameter, a compound write or a `with`
    /// scope leaves the chain untied, and its handlers unknown.
    fn threaded_table(&self, key: Key<'a>, call: &'a CallExpression<'a>) -> Option<Key<'a>> {
        let Key::Symbol(symbol) = key else {
            return None;
        };
        if self.parameters.contains(&symbol)
            || self
                .writes
                .get(&key)
                .is_some_and(|writes| writes.iter().any(|write| write.arithmetic))
        {
            return None;
        }
        let mut table = None;
        for definition in self.definitions.get(&key).into_iter().flatten() {
            if !self.meter.charge(1) || self.scope_opaque(definition.scope) {
                return None;
            }
            let context = Context {
                this: definition.this,
                ..self.context(definition.value.node_id())
            };
            match definition.value.get_inner_expression() {
                Expression::CallExpression(other) if std::ptr::eq(other.as_ref(), call) => (),
                Expression::NullLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NumericLiteral(_) => (),
                Expression::ComputedMemberExpression(member) => {
                    let read = self.resolve_table(self.key(&member.object, context)?);
                    if table.is_some_and(|table| table != read) {
                        return None;
                    }
                    table = Some(read);
                }
                _ => return None,
            }
        }
        table
    }
    /// The next-handler index of a self call `h = h(...)`. Untied, it is
    /// a chain of handler addresses. Tied to a table, each other write of
    /// the variable and each value a handler of the table returns is one
    /// alternative. A table read contributes its index; inside a handler, a
    /// parameter stands for the self call's argument, and a read repeats
    /// when the self call does.
    fn threaded(&self, candidate: &Candidate<'a>, query: &mut Query) -> Trace<'a> {
        let mut chain = Trace::new(Source::HandlerAddress);
        chain.repeats = self.loop_id(candidate.node).is_some();
        let (AstKind::AssignmentExpression(assignment), Some(table)) =
            (self.semantic.nodes().kind(candidate.node), candidate.table)
        else {
            return chain;
        };
        let Expression::CallExpression(call) = assignment.right.get_inner_expression() else {
            return chain;
        };
        let index = |value: &'a Expression<'a>| match value.get_inner_expression() {
            Expression::ComputedMemberExpression(member)
                if self
                    .key(&member.object, self.context(member.node_id()))
                    .map(|key| self.resolve_table(key))
                    == Some(table) =>
            {
                &member.expression
            }
            value => value,
        };
        let mut best = chain;
        let context = self.context(candidate.node);
        let key = self.key(candidate.selector, context);
        let writes = key
            .and_then(|key| self.definitions.get(&key))
            .into_iter()
            .flatten()
            .filter(|definition| {
                !matches!(definition.value.get_inner_expression(), Expression::CallExpression(other) if std::ptr::eq(other.as_ref(), call.as_ref()))
            })
            .map(|definition| (definition.value, None));
        let returns = self
            .table_members
            .get(&table)
            .into_iter()
            .flatten()
            .flat_map(|function| {
                self.returns
                    .get(function)
                    .into_iter()
                    .flatten()
                    .map(move |value| (*value, Some(*function)))
            });
        for (value, handler) in writes.chain(returns) {
            if !query.step(self.meter, 0) {
                break;
            }
            let frames = handler.map(|handler| (call.as_ref(), handler));
            let mut trace = self.trace(index(value), candidate, query, 1, frames.as_slice());
            if handler.is_none()
                && !self.executes_in_loop(context.function, value.span(), candidate)
            {
                trace.repeats = false;
            }
            if (trace.repeats, priority(trace.source)) > (best.repeats, priority(best.source)) {
                best = trace;
            }
        }
        best
    }
    /// A table key followed through aliases bound once (`var t = ops`), by
    /// Oxc symbol, at most 8 links. A link with any other write, a parameter
    /// or an ambiguous `with` scope ends the chain at that alias.
    fn resolve_table(&self, mut key: Key<'a>) -> Key<'a> {
        for _ in 0..8 {
            let Key::Symbol(symbol) = key else { break };
            let Some(&[definition]) = self.definitions.get(&key).map(Vec::as_slice) else {
                break;
            };
            if !self.meter.charge(1)
                || self.symbol_write_counts.get(&symbol) != Some(&1)
                || self.parameters.contains(&symbol)
                || self.scope_opaque(definition.scope)
            {
                break;
            }
            let context = Context {
                this: definition.this,
                ..Context::default()
            };
            match self.key(definition.value, context) {
                Some(next) if next != key => key = next,
                _ => break,
            }
        }
        key
    }
    fn index_key(
        &self,
        expression: &'a Expression<'a>,
        context: Context,
        depth: u8,
    ) -> Option<Key<'a>> {
        if depth > 16 {
            return None;
        }
        match expression.get_inner_expression() {
            Expression::UpdateExpression(update) => self.simple_target(&update.argument, context),
            Expression::BinaryExpression(binary)
                if matches!(
                    binary.right.get_inner_expression(),
                    Expression::NumericLiteral(_)
                ) =>
            {
                self.index_key(&binary.left, context, depth + 1)
            }
            expression => self.key(expression, context),
        }
    }
    fn advances(
        &self,
        key: Key<'a>,
        candidate: &Candidate<'a>,
        arithmetic: bool,
        query: &mut Query,
    ) -> bool {
        if self.loop_span(candidate.node).is_none() {
            return false;
        }
        let context = self.context(candidate.node);
        for write in self.writes.get(&key).into_iter().flatten() {
            if !query.step(self.meter, 0) {
                return false;
            }
            if arithmetic && !write.arithmetic {
                continue;
            }
            if !write.arithmetic
                && !self
                    .definitions
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .take(64)
                    .any(|definition| {
                        matches!(
                            definition.value.get_inner_expression(),
                            Expression::NumericLiteral(_)
                        )
                    })
            {
                continue;
            }
            if (write.function == context.function
                || write.function.is_some_and(|function| {
                    self.invoked_loops.get(&function).copied() == self.loop_id(candidate.node)
                }))
                && self.executes_in_loop(write.function, write.span, candidate)
            {
                return true;
            }
            if let Some((table, _)) = write
                .function
                .and_then(|function| self.table_functions.get(&function))
            {
                if candidate.table == Some(*table) {
                    return true;
                }
                // A switch's default/arms may dispatch the same table. The
                // table index is precomputed per loop rather than rescanned.
                if self
                    .loop_tables
                    .get(&self.loop_id(candidate.node).unwrap())
                    .is_some_and(|tables| tables.contains(table))
                {
                    return true;
                }
            }
        }
        false
    }
    /// The argument a followed helper call passes for a parameter, and the
    /// frames that remain outside that call.
    fn argument<'f>(
        &self,
        symbol: SymbolId,
        frames: &'f [Frame<'a>],
    ) -> Option<(&'a Expression<'a>, &'f [Frame<'a>])> {
        let &(function, position) = self.parameter_positions.get(&symbol)?;
        let at = frames.iter().rposition(|(_, frame)| *frame == function)?;
        let argument = frames[at].0.arguments.get(position)?.as_expression()?;
        Some((argument, &frames[..at]))
    }
    /// Whether a key read inside followed helpers advances in the loop. A
    /// parameter stands for its argument; a member reached through a
    /// parameter is shared with the caller, so the helper's own writes to it
    /// count too. A write to a plain parameter changes only the helper's copy.
    fn advances_through(
        &self,
        key: Key<'a>,
        candidate: &Candidate<'a>,
        arithmetic: bool,
        query: &mut Query,
        frames: &[Frame<'a>],
    ) -> Option<Key<'a>> {
        let substituted = self.substitute(key, frames);
        if let Some(caller) = substituted
            && self.advances(caller, candidate, arithmetic, query)
        {
            return Some(caller);
        }
        (matches!(key, Key::Member(..)) && substituted != Some(key))
            .then(|| self.advances(key, candidate, arithmetic, query))
            .filter(|advances| *advances)
            .map(|_| key)
    }
    /// A key read inside a followed helper, restated in its caller's terms
    /// when it names a parameter (`pc`, or `state.pc` for a `state` argument).
    fn substitute(&self, key: Key<'a>, frames: &[Frame<'a>]) -> Option<Key<'a>> {
        let (symbol, name) = match key {
            Key::Symbol(symbol) => (symbol, None),
            Key::Member(symbol, name) => (symbol, Some(name)),
            _ => return Some(key),
        };
        let Some((argument, outer)) = self.argument(symbol, frames) else {
            return Some(key);
        };
        let context = self.context(argument.node_id());
        let key = match name {
            None => self.index_key(argument, context, 0)?,
            Some(name) => self.member(argument, name, context)?,
        };
        self.substitute(key, outer)
    }
    fn trace(
        &self,
        expression: &'a Expression<'a>,
        candidate: &Candidate<'a>,
        query: &mut Query,
        depth: u8,
        frames: &[Frame<'a>],
    ) -> Trace<'a> {
        if !query.step(self.meter, depth) {
            return Trace::new(Source::Unknown);
        }
        let expression = expression.get_inner_expression();
        // Each expression resolves `this` and its function where it is
        // written, which inside a followed helper is the helper.
        let context = self.context(expression.node_id());
        match expression {
            Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => Trace::new(Source::Constant),
            Expression::Identifier(identifier) => {
                let Some(symbol) = self.symbol(identifier) else {
                    return Trace::new(Source::Unknown);
                };
                if let Some((argument, outer)) = self.argument(symbol, frames) {
                    return self.trace(argument, candidate, query, depth + 1, outer);
                }
                let mut best = Trace::new(if self.parameters.contains(&symbol) {
                    Source::CallArgument
                } else {
                    Source::Unknown
                });
                for definition in self
                    .definitions
                    .get(&Key::Symbol(symbol))
                    .into_iter()
                    .flatten()
                {
                    if !query.step(self.meter, depth) {
                        break;
                    }
                    // An in-place coercion keeps the parameter's source. A
                    // self reference is not another traversal of all writes.
                    if let Expression::BinaryExpression(binary) =
                        definition.value.get_inner_expression()
                        && self.key(&binary.left, context) == Some(Key::Symbol(symbol))
                    {
                        continue;
                    }
                    let mut trace =
                        self.trace(definition.value, candidate, query, depth + 1, frames);
                    trace.anchor = trace
                        .anchor
                        .filter(|_| trace.helper)
                        .or(Some(definition.at));
                    if !self.executes_in_loop(
                        definition.function,
                        definition.value.span(),
                        candidate,
                    ) || definition.function != context.function
                    {
                        trace.repeats = false;
                    }
                    if (trace.repeats, priority(trace.source))
                        > (best.repeats, priority(best.source))
                    {
                        best = trace;
                    }
                }
                best
            }
            Expression::ComputedMemberExpression(member) => self.read(
                &member.object,
                &member.expression,
                expression.span(),
                candidate,
                query,
                depth,
                None,
                frames,
            ),
            Expression::StaticMemberExpression(_) => {
                let mut trace = Trace::new(Source::FrameSlot);
                if let Some(key) = self.key(expression, context) {
                    trace.repeats = self
                        .advances_through(key, candidate, true, query, frames)
                        .is_some();
                }
                trace.anchor = Some(expression.span().start);
                trace
            }
            Expression::CallExpression(call) => {
                if let Expression::StaticMemberExpression(member) =
                    call.callee.get_inner_expression()
                    && matches!(
                        member.property.name.as_str(),
                        "charCodeAt"
                            | "charAt"
                            | "codePointAt"
                            | "getUint8"
                            | "getInt8"
                            | "getUint16"
                            | "getInt16"
                            | "getUint32"
                            | "at"
                    )
                    && let Some(index) = call.arguments.first().and_then(Argument::as_expression)
                {
                    let text = matches!(
                        member.property.name.as_str(),
                        "charCodeAt" | "charAt" | "codePointAt"
                    )
                    .then_some("string");
                    self.read(
                        &member.object,
                        index,
                        call.span,
                        candidate,
                        query,
                        depth,
                        text,
                        frames,
                    )
                } else if frames.len() < MAX_HELPER_FRAMES
                    && let Some(helper) = self.helper(&call.callee, context)
                {
                    // The value a statically bound helper returns. Each
                    // returned expression is one alternative, as each write
                    // of a variable is.
                    let mut inner = frames.to_vec();
                    inner.push((call, helper));
                    let mut best = Trace::new(Source::Unknown);
                    for value in self.returns.get(&helper).into_iter().flatten() {
                        if !query.step(self.meter, depth) {
                            break;
                        }
                        let mut trace = self.trace(value, candidate, query, depth + 1, &inner);
                        trace.helper = trace.source != Source::Unknown;
                        if (trace.repeats, priority(trace.source))
                            > (best.repeats, priority(best.source))
                        {
                            best = trace;
                        }
                    }
                    best
                } else {
                    Trace::new(Source::Unknown)
                }
            }
            Expression::BinaryExpression(binary) => {
                let left = self.trace(&binary.left, candidate, query, depth + 1, frames);
                let right = self.trace(&binary.right, candidate, query, depth + 1, frames);
                if (left.repeats, priority(left.source)) >= (right.repeats, priority(right.source))
                {
                    left
                } else {
                    right
                }
            }
            Expression::UnaryExpression(unary) => {
                self.trace(&unary.argument, candidate, query, depth + 1, frames)
            }
            Expression::AssignmentExpression(a) => {
                self.trace(&a.right, candidate, query, depth + 1, frames)
            }
            Expression::SequenceExpression(sequence) => sequence.expressions.last().map_or_else(
                || Trace::new(Source::Unknown),
                |value| self.trace(value, candidate, query, depth + 1, frames),
            ),
            Expression::UpdateExpression(update) => {
                let mut trace = Trace::new(Source::Constant);
                if let Some(key) = self.simple_target(&update.argument, context) {
                    trace.repeats = self
                        .advances_through(key, candidate, true, query, frames)
                        .is_some();
                }
                trace
            }
            _ => Trace::new(Source::Unknown),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        buffer: &'a Expression<'a>,
        index: &'a Expression<'a>,
        span: Span,
        candidate: &Candidate<'a>,
        query: &mut Query,
        depth: u8,
        buffer_kind: Option<&'static str>,
        frames: &[Frame<'a>],
    ) -> Trace<'a> {
        let context = self.context(index.node_id());
        if let Some(key) = self.index_key(index, context, 0).and_then(|key| {
            self.advances_through(
                key,
                candidate,
                !matches!(key, Key::Symbol(_)),
                query,
                frames,
            )
        }) {
            let mut trace = Trace::new(if matches!(key, Key::Symbol(_)) {
                Source::CursorIndex
            } else {
                Source::FrameSlot
            });
            // A read inside a followed helper repeats when the outermost
            // followed call does.
            trace.repeats = match frames.first() {
                Some((call, _)) => self.executes_in_loop(
                    self.context(call.node_id()).function,
                    call.span,
                    candidate,
                ),
                None => self.executes_in_loop(context.function, span, candidate),
            };
            trace.anchor = Some(span.start);
            let buffer = match buffer.get_inner_expression() {
                Expression::Identifier(id) => self
                    .symbol(id)
                    .and_then(|symbol| self.argument(symbol, frames))
                    .map_or(buffer, |(argument, _)| argument),
                _ => buffer,
            };
            let context = self.context(buffer.node_id());
            trace.buffer = self.key(buffer, context);
            trace.buffer_kind = buffer_kind.or_else(|| self.buffer_kind(buffer, context));
            return trace;
        }
        let mut trace = self.trace(index, candidate, query, depth + 1, frames);
        if trace.source.cursor_like() {
            trace.lookup = true;
        }
        trace
    }
    fn buffer_kind(&self, buffer: &'a Expression<'a>, context: Context) -> Option<&'static str> {
        if matches!(buffer.get_inner_expression(), Expression::Identifier(id) if id.name == "arguments")
        {
            return Some("arguments");
        }
        let kind = |value: &Expression<'a>| match value.get_inner_expression() {
            Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => "string",
            Expression::ArrayExpression(_) => "array",
            Expression::NewExpression(new) if matches!(new.callee.get_inner_expression(), Expression::Identifier(id) if matches!(id.name.as_str(), "Uint8Array" | "Int8Array" | "Uint8ClampedArray" | "Uint16Array" | "Int16Array" | "Uint32Array" | "Int32Array")) => {
                "typed-array"
            }
            _ => "unknown",
        };
        let direct = kind(buffer);
        if direct != "unknown" {
            return Some(direct);
        }
        let Some(key) = self.key(buffer, context) else {
            return Some("unknown");
        };
        let Some(definitions) = self.definitions.get(&key) else {
            return Some("unknown");
        };
        let mut value = None;
        for definition in definitions.iter().take(64) {
            self.meter.charge(1);
            let current = kind(definition.value);
            if value.is_some_and(|previous| previous != current) {
                return Some("unknown");
            }
            value = Some(current);
        }
        if definitions.len() > 64 {
            Some("unknown")
        } else {
            value.or(Some("unknown"))
        }
    }
    fn stable(&self, key: Key<'a>, at: u32, scope: ScopeId) -> Result<(), Refusal> {
        let single_definition = self
            .definitions
            .get(&key)
            .is_some_and(|definitions| definitions.len() == 1 && definitions[0].at == at);
        let single_write = match key {
            Key::Symbol(symbol) => self.symbol_write_counts.get(&symbol) == Some(&1),
            Key::Member(symbol, _) => {
                self.symbol_write_counts.get(&symbol).copied().unwrap_or(0) <= 1
                    && self.member_write_counts.get(&key) == Some(&1)
            }
            Key::This(owner, _) => {
                self.member_write_counts.get(&key) == Some(&1)
                    && self
                        .definitions
                        .get(&key)
                        .is_some_and(|definitions| definitions[0].function == Some(owner))
            }
            Key::Slot(_, _) => false,
        };
        if !self.scope_opaque(scope)
            && single_definition
            && single_write
            && !self.element_writes.contains(&key)
        {
            Ok(())
        } else {
            Err(Refusal::Binding)
        }
    }
    fn bounded(
        &self,
        expression: &'a Expression<'a>,
        candidate: &Candidate<'a>,
        depth: u8,
    ) -> bool {
        if depth > 8 || !self.meter.charge(1) {
            return false;
        }
        let context = self.context(candidate.node);
        let Some(loop_id) = self.loop_id(candidate.node) else {
            return false;
        };
        let test = match self.semantic.nodes().kind(loop_id) {
            AstKind::WhileStatement(node) => Some(&node.test),
            AstKind::DoWhileStatement(node) => Some(&node.test),
            AstKind::ForStatement(node) => node.test.as_ref(),
            _ => None,
        };
        let Some(Expression::BinaryExpression(test)) = test.map(Expression::get_inner_expression)
        else {
            return false;
        };
        let (cursor, length) = match test.operator.as_str() {
            "<" | "<=" => (&test.left, &test.right),
            ">" | ">=" => (&test.right, &test.left),
            _ => return false,
        };
        let Expression::StaticMemberExpression(length) = length.get_inner_expression() else {
            return false;
        };
        if length.property.name != "length" {
            return false;
        }
        let expression = expression.get_inner_expression();
        if let Expression::ComputedMemberExpression(read) = expression {
            return self.key(cursor, context).is_some()
                && self.key(cursor, context) == self.index_key(&read.expression, context, 0)
                && self.key(&read.object, context).is_some()
                && self.key(&read.object, context) == self.key(&length.object, context);
        }
        if let Expression::Identifier(identifier) = expression
            && let Some(key) = self.symbol(identifier).map(Key::Symbol)
        {
            return self
                .definitions
                .get(&key)
                .into_iter()
                .flatten()
                .take(4)
                .any(|definition| self.bounded(definition.value, candidate, depth + 1));
        }
        false
    }
}

fn parsed(
    source: &str,
    meter: &Meter,
    allocator: &Allocator,
    source_type: SourceType,
) -> Option<Classified> {
    let parse = Parser::new(allocator, source, source_type).parse();
    #[cfg(test)]
    PARSER_ARENA.set(PARSER_ARENA.get().max(allocator.capacity()));
    if !parse.diagnostics.is_empty() {
        return None;
    }
    // Oxc's binder expands a var declaration into each intervening block for
    // redeclaration checks. Bound that expansion before semantic allocation.
    // The same linear AST prepass bounds upstream ancestor walks.
    let mut hoists = SemanticAdmission::default();
    hoists.visit_program(&parse.program);
    if hoists.expansion > source.len() as u64 * 2 {
        return Some(unavailable(
            meter,
            "classification-work-limit",
            "JavaScript block-hoisting admission limit reached.",
        ));
    }
    // Syntax checks walk AST ancestors, resolution walks scope ancestors, and
    // parameter early resolution can revisit references in enclosing defaults.
    // AST depth upper-bounds scope depth. The sum is computed in one traversal.
    // Reserve headroom for valid code below 100 AST levels while rejecting
    // quadratic deep-scope inputs before calling unmodified upstream semantics.
    let semantic_work = hoists.ancestor_work.saturating_add(hoists.extra_work);
    if semantic_work > (source.len() as u64).saturating_mul(128)
        || !meter.charge(semantic_work + hoists.expansion)
    {
        return Some(unavailable(
            meter,
            "classification-work-limit",
            "JavaScript semantic ancestor-work admission limit reached.",
        ));
    }
    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .with_check_syntax_error(true)
        .build(&parse.program);
    if !semantic.diagnostics.is_empty() {
        return None;
    }
    #[cfg(test)]
    PARSER_ARENA.set(PARSER_ARENA.get().max(allocator.capacity()));
    let facts = Facts::index(&semantic.semantic, meter);
    let lines = Lines::new(source, meter);
    let strengths = facts
        .candidates
        .iter()
        .map(|candidate| {
            u8::from(facts.bounded(candidate.selector, candidate, 0)) * 4
                + u8::from(facts.loop_id(candidate.node).is_some()) * 2
                + u8::from(matches!(
                    candidate.selector.get_inner_expression(),
                    Expression::ComputedMemberExpression(_) | Expression::Identifier(_)
                ))
        })
        .collect::<Vec<_>>();
    // Eight structural buckets in AST order, including comparison groups
    // collected through a hash map. Scheduling is linear and deterministic.
    let mut by_node = vec![None; semantic.semantic.nodes().len()];
    for (index, candidate) in facts.candidates.iter().enumerate() {
        by_node[candidate.node.index()] = Some(index);
    }
    let mut order = Vec::with_capacity(facts.candidates.len());
    for strength in (0..8).rev() {
        order.extend(
            by_node
                .iter()
                .flatten()
                .copied()
                .filter(|index| strengths[*index] == strength),
        );
    }
    let mut sites = Vec::new();
    let mut roles = HashMap::new();
    let mut tables = HashMap::<Key<'_>, Vec<(NodeId, Role)>>::new();
    for (ordinal, index) in order.iter().enumerate() {
        if ordinal >= MAX_SITES || meter.exhausted() {
            meter.count_unclassified(1);
            continue;
        }
        let candidate = &facts.candidates[*index];
        let mut query = Query {
            left: 4096,
            limited: false,
        };
        let trace = if candidate.instruction == "self call" {
            facts.threaded(candidate, &mut query)
        } else {
            facts.trace(candidate.selector, candidate, &mut query, 0, &[])
        };
        let trace = if query.limited {
            Trace::new(Source::Unknown)
        } else {
            trace
        };
        meter.count_limited(query.limited);
        let node = semantic.semantic.nodes().get_node(candidate.node);
        let span = node.span();
        let (line, column, work) = lines.locate(source, span.start as usize);
        if !meter.charge(work) {
            meter.count_unclassified(1);
            continue;
        }
        let mut selector_end = candidate
            .selector
            .span()
            .end
            .min(candidate.selector.span().start.saturating_add(160))
            as usize;
        selector_end = source.floor_char_boundary(selector_end);
        let selector = &source[candidate.selector.span().start as usize..selector_end];
        let function = facts.context(candidate.node).function;
        let body_start = function
            .map(|id| match semantic.semantic.nodes().kind(id) {
                AstKind::Function(function) => function
                    .body
                    .as_ref()
                    .map_or(function.span.start, |body| body.span.start + 1),
                AstKind::ArrowFunctionExpression(function) => function.body.span().start + 1,
                _ => 0,
            })
            .unwrap_or(0);
        let site = Site {
            strength: strengths[*index],
            kind: candidate.kind,
            source: trace.source,
            repeats: if facts.loop_span(candidate.node).is_none() {
                Repeats::Once
            } else if trace.repeats {
                Repeats::Loop
            } else {
                Repeats::Unknown
            },
            instruction: candidate.instruction.into(),
            function_index: None,
            function_body_offset: Some(body_start as usize),
            byte_offset: span.start as usize,
            byte_size: (span.end - span.start) as usize,
            line: Some(line),
            column: Some(column),
            selector_expression: selector.to_owned(),
            selector_offset: trace.anchor.map(|at| at as usize),
            through_lookup: trace.lookup,
            through_helper: trace.helper,
            arm_count: candidate.arms,
            loop_range: facts
                .loop_span(candidate.node)
                .map(|span| (span.start as usize, span.end as usize)),
            buffer_kind: if candidate.strings {
                Some("string".into())
            } else {
                trace.buffer_kind.map(Into::into)
            },
            table: None,
        };
        if !meter.retain(site.retained_bytes()) {
            meter.count_unclassified(1);
            continue;
        }
        let role = site.role();
        roles.insert(candidate.node, role);
        if let Some(table) = candidate.table {
            tables
                .entry(table)
                .or_default()
                .push((candidate.node, role));
        }
        sites.push(site);
    }
    let memory = Memory::new(meter);
    let mut handlers = HashMap::new();
    let mut positions = HashMap::new();
    let mut refusals = std::collections::BTreeMap::<&str, (u64, &str)>::new();
    let nodes = semantic.semantic.nodes();
    // Prove each object once, not once per property times every dispatch.
    // Stability permits only one definition for a key, so each dispatch is
    // considered at most once across these object queries.
    let mut object_verdicts = HashMap::new();
    for (&object, &(key, at, scope)) in &facts.objects {
        if !meter.charge(1) {
            break;
        }
        let verdict = if let Err(reason) = facts.stable(key, at, scope) {
            Err(reason)
        } else {
            let mut verdict = None;
            for &(dispatch, role) in tables.get(&key).into_iter().flatten() {
                if !meter.charge(1) {
                    break;
                }
                let site = nodes.get_node(dispatch);
                if facts.scope_opaque(site.scope_id()) {
                    continue;
                }
                if matches!(key, Key::This(owner, _) if facts.context(dispatch).function != Some(owner))
                {
                    continue;
                }
                if verdict.is_none() || role == Role::InterpreterCandidate {
                    verdict = Some(role);
                }
            }
            if verdict.is_none() && tables.contains_key(&key) {
                Err(Refusal::Binding)
            } else {
                Ok(verdict)
            }
        };
        object_verdicts.insert(object, verdict);
    }
    for node in nodes.iter() {
        if !meter.charge(1) {
            break;
        }
        // An array entry's opcode is its position. Elements after a spread
        // have no static position and get no proof.
        if let AstKind::ArrayExpression(array) = node.kind()
            && let Some(verdict) = object_verdicts.get(&node.id()).copied()
        {
            for (position, element) in array.elements.iter().enumerate() {
                if !meter.charge(1) || !memory.keep(128) {
                    break;
                }
                if matches!(element, ArrayExpressionElement::SpreadElement(_)) {
                    break;
                }
                if !matches!(
                    element,
                    ArrayExpressionElement::FunctionExpression(_)
                        | ArrayExpressionElement::ArrowFunctionExpression(_)
                ) {
                    continue;
                }
                let offset = element.span().start as usize;
                if let Err(reason) = verdict {
                    let entry = refusals
                        .entry(reason.reason())
                        .or_insert((0, reason.detail()));
                    entry.0 += 1;
                }
                positions.insert(offset, position as u32);
                handlers.insert((offset, true), verdict);
            }
            continue;
        }
        let (offset, table, verdict) = match node.kind() {
            AstKind::SwitchCase(case) => (
                case.span.start as usize,
                false,
                Ok(roles.get(&nodes.parent_id(node.id())).copied()),
            ),
            AstKind::ObjectProperty(property) => {
                let verdict = object_verdicts
                    .get(&nodes.parent_id(node.id()))
                    .copied()
                    .unwrap_or(Err(Refusal::Binding));
                (property.span.start as usize, true, verdict)
            }
            _ => continue,
        };
        if !memory.keep(96) {
            break;
        }
        if let Err(reason) = verdict
            && matches!(node.kind(), AstKind::ObjectProperty(property)
                if matches!(property.value.get_inner_expression(), Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_))
                && property.key.static_name().is_some_and(|name| name.as_str().is_some_and(|name| name.parse::<u32>().is_ok())))
        {
            let entry = refusals
                .entry(reason.reason())
                .or_insert((0, reason.detail()));
            entry.0 += 1;
        }
        handlers.insert((offset, table), verdict);
    }
    let mut omissions = meter.omissions("JavaScript artifacts");
    omissions.extend(refusals.into_iter().map(|(reason, (count, detail))|
        json!({"reason": reason, "omitted_records": count, "detail": detail})));
    Some(Classified {
        sites,
        omissions,
        javascript: Some(Rc::new(Proofs {
            handlers,
            positions,
            failure: None,
            _memory: memory,
        })),
    })
}

#[derive(Default)]
struct SemanticAdmission<'a> {
    ast_depth: u64,
    ancestor_work: u64,
    extra_work: u64,
    class_elements: Vec<u64>,
    private_names: u64,
    redeclarations: HashMap<(u32, &'a str), u64>,
    scopes: Vec<u32>,
    next_scope: u32,
    depth: u64,
    functions: Vec<u64>,
    expansion: u64,
}
impl<'a> Visit<'a> for SemanticAdmission<'a> {
    fn enter_scope(
        &mut self,
        _: oxc_syntax::scope::ScopeFlags,
        _: &std::cell::Cell<Option<ScopeId>>,
    ) {
        self.scopes.push(self.next_scope);
        self.next_scope += 1;
    }
    fn leave_scope(&mut self) {
        self.scopes.pop();
    }

    fn enter_node(&mut self, kind: AstKind<'a>) {
        self.ast_depth += 1;
        self.ancestor_work = self.ancestor_work.saturating_add(self.ast_depth * 2);
        match kind {
            AstKind::Class(class) => {
                let names = class
                    .body
                    .body
                    .iter()
                    .map(|element| u64::from(element.span().size()))
                    .sum();
                self.class_elements.push(names);
                self.private_names += names;
            }
            AstKind::PrivateIdentifier(id) => {
                // Upstream suggests undeclared private names by comparing all
                // ancestor class elements (including edit-distance work).
                self.extra_work = self.extra_work.saturating_add(
                    self.private_names.saturating_mul(id.name.len() as u64 + 1) * 8,
                );
            }
            AstKind::Function(function) if function.is_declaration() => {
                // Only equal names in one scope can accumulate redeclarations.
                if let Some(id) = &function.id {
                    let count = self
                        .redeclarations
                        .entry((self.scopes.last().copied().unwrap_or(0), id.name.as_str()))
                        .or_default();
                    self.extra_work = self.extra_work.saturating_add(*count);
                    *count += 1;
                }
            }
            _ => (),
        }
        match kind {
            AstKind::Function(function) => {
                if function.is_declaration() {
                    self.expansion += self.depth;
                }
                self.functions.push(self.depth);
                self.depth = 0;
            }
            AstKind::ArrowFunctionExpression(_) => {
                self.functions.push(self.depth);
                self.depth = 0;
            }
            AstKind::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Var =>
            {
                // Pattern bytes upper-bound its number of bound names, even
                // for destructuring, without a second traversal of the pattern.
                self.expansion += declaration
                    .declarations
                    .iter()
                    .map(|d| u64::from(d.id.span().size()) * self.depth)
                    .sum::<u64>();
            }
            AstKind::BlockStatement(_)
            | AstKind::CatchClause(_)
            | AstKind::ForStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::SwitchStatement(_)
            | AstKind::WithStatement(_)
            | AstKind::StaticBlock(_) => self.depth += 1,
            _ => (),
        }
    }
    fn leave_node(&mut self, kind: AstKind<'a>) {
        self.ast_depth -= 1;
        if matches!(kind, AstKind::Class(_)) {
            self.private_names -= self.class_elements.pop().unwrap();
        }
        match kind {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                self.depth = self.functions.pop().unwrap();
            }
            AstKind::BlockStatement(_)
            | AstKind::CatchClause(_)
            | AstKind::ForStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::SwitchStatement(_)
            | AstKind::WithStatement(_)
            | AstKind::StaticBlock(_) => self.depth -= 1,
            _ => (),
        }
    }
}

fn unavailable(meter: &Meter, reason: &str, detail: &'static str) -> Classified {
    Classified {
        sites: Vec::new(),
        omissions: vec![json!({"reason": reason, "omitted_records": 1, "detail": detail})],
        javascript: Some(Rc::new(Proofs {
            handlers: HashMap::new(),
            positions: HashMap::new(),
            failure: Some(detail.to_owned()),
            _memory: Memory::new(meter),
        })),
    }
}

/// Iterative lexical admission. Literals/comments are single tokens; template
/// substitutions re-enter code. This pass only limits parser stack growth and
/// cannot authorize a site. Oxc still owns parsing and all semantic decisions.
fn syntax_stack(source: &str) -> Option<usize> {
    #[derive(Clone, Copy)]
    enum Delimiter {
        Plain,
        Control,
        Template,
    }
    let bytes = source.as_bytes();
    let mut delimiters = Vec::new();
    let mut index = 0;
    let mut chain = 0;
    let mut stack = PARSER_STACK;
    let mut operand = true;
    let mut control = false;
    let mut template = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if template {
            match byte {
                b'\\' => index = (index + 2).min(bytes.len()),
                b'`' => {
                    index += 1;
                    template = false;
                    operand = false;
                }
                b'$' if bytes.get(index + 1) == Some(&b'{') => {
                    delimiters.push((Delimiter::Template, chain));
                    chain = 0;
                    index += 2;
                    template = false;
                    operand = true;
                }
                _ => index += 1,
            }
        } else if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                index += 1;
            }
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    index += 2;
                    break;
                }
                index += 1;
            }
        } else if matches!(byte, b'\'' | b'"') {
            index += 1;
            while index < bytes.len() {
                let current = bytes[index];
                index += 1;
                if current == b'\\' {
                    index = (index + 1).min(bytes.len());
                } else if current == byte {
                    break;
                }
            }
            operand = false;
            control = false;
        } else if byte == b'`' {
            index += 1;
            template = true;
            control = false;
        } else if byte == b'/' && operand {
            // A regexp token ends at its unescaped slash outside a class.
            // Unterminated regexps are left for Oxc's syntax diagnostics.
            index += 1;
            let mut class = false;
            while index < bytes.len() {
                let current = bytes[index];
                index += 1;
                match current {
                    b'\\' => index = (index + 1).min(bytes.len()),
                    b'[' => class = true,
                    b']' => class = false,
                    b'/' if !class => break,
                    b'\n' | b'\r' => break,
                    _ => (),
                }
            }
            while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                index += 1;
            }
            operand = false;
            control = false;
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || byte >= 128 {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'$')
                    || bytes[index] >= 128)
            {
                index += 1;
            }
            let word = &bytes[start..index];
            control = matches!(
                word,
                b"if" | b"while" | b"for" | b"with" | b"switch" | b"catch"
            );
            operand = control
                || matches!(
                    word,
                    b"return"
                        | b"throw"
                        | b"case"
                        | b"else"
                        | b"new"
                        | b"typeof"
                        | b"void"
                        | b"delete"
                        | b"await"
                        | b"yield"
                        | b"in"
                        | b"instanceof"
                );
            if matches!(
                word,
                b"new" | b"typeof" | b"void" | b"delete" | b"await" | b"yield"
            ) {
                chain += 1;
            }
        } else {
            index += 1;
            match byte {
                b'(' | b'[' | b'{' => {
                    delimiters.push((
                        if byte == b'(' && control {
                            Delimiter::Control
                        } else {
                            Delimiter::Plain
                        },
                        chain,
                    ));
                    chain = 0;
                    operand = true;
                }
                b')' | b']' | b'}' => {
                    let (kind, parent_chain) = delimiters
                        .pop()
                        .map_or((None, 0), |(kind, chain)| (Some(kind), chain));
                    chain = parent_chain;
                    template = byte == b'}' && matches!(kind, Some(Delimiter::Template));
                    operand = byte == b'}' || matches!(kind, Some(Delimiter::Control));
                }
                _ => operand = true,
            }
            control = false;
            if matches!(byte, b';' | b',' | b':') {
                chain = 0;
            } else if b"=+-!~?&|*/%<>^.".contains(&byte) {
                chain += 1;
            }
        }
        if delimiters.len() > MAX_SYNTAX_DEPTH || chain > MAX_SYNTAX_DEPTH {
            return None;
        }
        if delimiters.len() > 1024 || chain > 1024 {
            stack = PARSER_STACK * 2;
        }
    }
    Some(stack)
}

fn classify_local(source: &str, meter: &Meter) -> Classified {
    #[cfg(test)]
    PARSER_ARENA.set(0);
    let mut failure = None;
    // Worker allocations are limited before they reach the system allocator.
    // Work admission covers parser passes; stack mappings are not retained heap.
    if !meter.charge(source.len() as u64 * 64) {
        meter.count_unexamined(1);
        failure = Some("JavaScript parser memory or work admission limit reached.");
    }
    let stack = match syntax_stack(source) {
        Some(stack) => stack,
        None => {
            failure = Some("JavaScript parser nesting or expression admission limit reached.");
            PARSER_STACK
        }
    };
    if failure.is_none() {
        let result = stacker::grow(stack, || {
            for source_type in [SourceType::mjs().with_script(true), SourceType::mjs()] {
                let allocator = Allocator::default();
                if let Some(result) = parsed(source, meter, &allocator, source_type) {
                    return Some(result);
                }
            }
            None
        });
        if let Some(result) = result {
            return result;
        }
    }
    let reason = if failure.is_some() {
        "classification-work-limit"
    } else {
        "parse-failed"
    };
    unavailable(meter, reason, failure.unwrap_or(PARSE_FAILED))
}

// The upstream parser and semantic builder use infallible allocations. Keep
// them unmodified, but isolate their allocations behind a hard, pre-allocation
// ceiling. Only compact site/proof records return; source never goes to disk.
const MAX_SOURCE: usize = 8 << 20;
const MAX_REPLY: usize = 64 << 20;

fn heap_limit(source_bytes: usize) -> u64 {
    // Small dense artifacts already analyzed by earlier versions need room
    // for arena chunk growth; this is a limit, never an eager reservation.
    (64 << 20) + source_bytes.min(MAX_SOURCE) as u64 * 80
}
const REPLY_MAGIC: &[u8; 8] = b"REBJS001";
const WORKER_FAILED: &str = "JavaScript analysis worker unavailable or refused its resource boundary; recovered handlers have no binding proof.";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReply {
    sites: Vec<Site>,
    omissions: Vec<serde_json::Value>,
    handlers: Vec<(usize, bool, Option<Role>, Option<Refusal>)>,
    positions: Vec<(usize, u32)>,
    failure: Option<String>,
    work: u64,
    retained_peak: u64,
    unclassified: u64,
    unexamined: u64,
    limited: u64,
    exhausted: bool,
    arena: usize,
}

/// Internal pipe protocol used by the analyzer's isolated worker mode.
/// This is not an API, does not execute JavaScript, and writes no source files.
#[doc(hidden)]
pub fn worker_main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut input = std::io::stdin().lock();
    let mut header = [0u8; 40];
    input.read_exact(&mut header)?;
    let number =
        |offset: usize| u64::from_le_bytes(header[offset + 8..offset + 16].try_into().unwrap());
    let (work, retained, heap, length) = (number(0), number(8), number(16), number(24));
    if &header[..8] != REPLY_MAGIC
        || length > MAX_SOURCE as u64
        || work > super::MAX_ARTIFACT_WORK
        || retained > super::MAX_RETAINED_BYTES
        || heap > heap_limit(length as usize)
    {
        return Err(std::io::Error::other("Invalid JavaScript worker limits"));
    }
    crate::js_worker_alloc::start(heap);
    let mut source = String::new();
    input.take(length).read_to_string(&mut source)?;
    if source.len() as u64 != length {
        return Err(std::io::Error::other("Incomplete JavaScript worker source"));
    }
    let meter = Meter::with_limits(work, retained);
    let result = classify_local(&source, &meter);
    let proofs = result.javascript.as_ref().unwrap();
    let reply = WorkerReply {
        sites: result.sites,
        omissions: result.omissions,
        handlers: proofs
            .handlers
            .iter()
            .map(|(&(offset, table), verdict)| {
                (offset, table, verdict.ok().flatten(), verdict.err())
            })
            .collect(),
        positions: proofs
            .positions
            .iter()
            .map(|(&offset, &position)| (offset, position))
            .collect(),
        failure: proofs.failure.clone(),
        work: meter.used.get(),
        retained_peak: meter.peak.get(),
        unclassified: meter.unclassified.get(),
        unexamined: meter.unexamined.get(),
        limited: meter.limited.get(),
        exhausted: meter.exhausted(),
        arena: {
            #[cfg(test)]
            {
                parser_arena_bytes()
            }
            #[cfg(not(test))]
            {
                0
            }
        },
    };
    // Serialize before the success marker: allocation refusal must not leave a
    // partial reply that could be mistaken for complete binding proof.
    let mut bytes = serde_json::to_vec(&reply)?;
    if bytes.len() > MAX_REPLY - 16 {
        return Err(std::io::Error::other(
            "JavaScript proof reply exceeds limit",
        ));
    }
    let peak = crate::js_worker_alloc::peak();
    let mut output = std::io::stdout().lock();
    output.write_all(REPLY_MAGIC)?;
    output.write_all(&peak.to_le_bytes())?;
    output.write_all(&bytes)?;
    bytes.clear();
    output.flush()
}

/// Enter before an application runtime or libtest worker starts analysis.
#[doc(hidden)]
pub fn worker_entry() {
    if std::env::args().nth(1).as_deref() != Some("--classify-javascript-worker")
        && std::env::var_os("REB_JS_TEST_WORKER").is_none()
    {
        return;
    }
    let result = crate::js_worker_alloc::contain().and_then(|()| {
        #[cfg(test)]
        match std::env::var("REB_JS_TEST_FAULT").as_deref() {
            Ok("timeout") => {
                unsafe { libc::raise(libc::SIGSTOP) };
            }
            Ok("crash") => {
                unsafe { libc::raise(libc::SIGKILL) };
            }
            Ok("protocol") => {
                print!("invalid worker reply");
                std::process::exit(0);
            }
            Ok("capabilities") => {
                assert!(
                    std::env::vars_os()
                        .all(|(key, _)| key == "REB_JS_TEST_WORKER" || key == "REB_JS_TEST_FAULT")
                );
                assert_eq!(unsafe { libc::fcntl(198, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::net::TcpStream::connect("127.0.0.1:9")
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
            _ => (),
        }
        worker_main()
    });
    std::process::exit(if result.is_ok() { 0 } else { 74 });
}

fn worker_command() -> std::io::Result<tokio::process::Command> {
    let current = std::env::current_exe()?;
    let harness = current
        .parent()
        .and_then(std::path::Path::file_name)
        .is_some_and(|name| name == "deps");
    let mut command = tokio::process::Command::new(current);
    command.env_clear();
    #[cfg(test)]
    if let Some(fault) = WORKER_FAULT.get() {
        if fault == "spawn" {
            return Err(std::io::Error::other("fixture spawn failure"));
        }
        command.env("REB_JS_TEST_FAULT", fault);
        if fault == "capabilities" {
            // SAFETY: this fixture hook uses only async-signal-safe syscalls.
            unsafe {
                command.pre_exec(|| {
                    let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let copied = libc::dup2(fd, 198);
                    libc::close(fd);
                    if copied < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
    if harness {
        command
            .args([
                "--ignored",
                "--exact",
                "__reb_javascript_worker",
                "--nocapture",
            ])
            .env("REB_JS_TEST_WORKER", "1");
    } else {
        command.arg("--classify-javascript-worker");
    }
    Ok(command)
}

fn worker_deadline(source_bytes: usize) -> std::time::Duration {
    #[cfg(test)]
    if WORKER_FAULT.get() == Some("timeout") {
        return std::time::Duration::from_millis(100);
    }
    // Deterministic metering owns admission. This is only a generous hang
    // backstop: five minutes plus one minute per started MiB (13 at the cap).
    std::time::Duration::from_secs(300 + 60 * source_bytes.div_ceil(1 << 20) as u64)
}

fn worker_failure(meter: &Meter, work: u64, detail: &'static str) -> Classified {
    meter.charge(work);
    unavailable(meter, "analysis-worker-failed", detail)
}

pub(crate) fn classify(source: &str, meter: &Meter) -> Classified {
    classify_with_heap(source, meter, heap_limit(source.len()))
}

fn classify_with_heap(source: &str, meter: &Meter, heap: u64) -> Classified {
    #[cfg(test)]
    PARSER_ARENA.set(0);
    if source.len() > MAX_SOURCE || meter.exhausted() {
        meter.count_unexamined(1);
        return unavailable(
            meter,
            "classification-work-limit",
            "JavaScript source exceeds the 8 MiB analysis ceiling or the artifact budget.",
        );
    }
    // Include IPC copies in the shared work meter; the worker receives only
    // the remainder, not a second artifact budget. Its peak heap is separate
    // from the 128 MiB of records retained by the caller.
    if !meter.charge(source.len() as u64 * 2) {
        meter.count_unexamined(1);
        return unavailable(meter, "classification-work-limit", WORKER_FAILED);
    }
    let work = meter.remaining_work().min(super::MAX_ARTIFACT_WORK);
    let retained = meter.remaining_memory().min(super::MAX_RETAINED_BYTES);
    #[cfg(test)]
    let fault = WORKER_FAULT.get();
    let output = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, || {
                #[cfg(test)]
                WORKER_FAULT.set(fault);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "spawn")?;
                let mut command = worker_command().map_err(|_| "spawn")?;
                let mut input = Vec::with_capacity(40 + source.len());
                input.extend_from_slice(REPLY_MAGIC);
                for number in [work, retained, heap, source.len() as u64] {
                    input.extend_from_slice(&number.to_le_bytes());
                }
                input.extend_from_slice(source.as_bytes());
                runtime
                    .block_on(crate::worker::run(
                        &mut command,
                        &input,
                        MAX_REPLY,
                        worker_deadline(source.len()),
                    ))
                    .map_err(|error| match error.reason.code {
                        crate::error::Code::Timeout => "timeout",
                        crate::error::Code::DependencyUnavailable => "spawn",
                        crate::error::Code::ResourceLimit | crate::error::Code::ProtocolError => {
                            "protocol"
                        }
                        _ => "crash",
                    })
            })
            .map_err(|_| "spawn")?
            .join()
            .map_err(|_| "crash")?
    });
    let output = match output {
        Ok(output) => output,
        Err(detail) => return worker_failure(meter, work, detail),
    };
    if !meter.charge(output.bytes.len() as u64) {
        meter.count_unexamined(1);
        return unavailable(meter, "classification-work-limit", WORKER_FAILED);
    }
    let marker = if output.bytes.starts_with(REPLY_MAGIC)
        || output.bytes.starts_with(crate::js_worker_alloc::REFUSED)
    {
        Some(0)
    } else if output.bytes.starts_with(b"\nrunning 1 test\n") {
        Some(b"\nrunning 1 test\n".len())
    } else {
        None
    };
    if let Some(at) = marker {
        let bytes = &output.bytes[at..];
        if bytes.len() >= 16 {
            meter.record_parser_peak(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
        }
        if bytes.starts_with(REPLY_MAGIC)
            && output.success
            && bytes.len() >= 16
            && let Ok(reply) = serde_json::from_slice::<WorkerReply>(&bytes[16..])
            && reply.work <= work
            && reply.retained_peak <= retained
            && u64::from_le_bytes(bytes[8..16].try_into().unwrap()) <= heap
            && reply
                .handlers
                .iter()
                .all(|handler| handler.0 < source.len())
            && reply.sites.len() <= MAX_SITES
        {
            meter.charge(reply.work);
            meter.peak.set(
                meter
                    .peak
                    .get()
                    .max(meter.retained.get() + reply.retained_peak),
            );
            meter.count_unclassified(reply.unclassified);
            meter.count_unexamined(reply.unexamined);
            meter.limited.set(meter.limited.get() + reply.limited);
            #[cfg(test)]
            PARSER_ARENA.set(reply.arena);
            let memory = Memory::new(meter);
            if !memory.keep(reply.handlers.len() as u64 * 96 + reply.positions.len() as u64 * 32) {
                meter.count_unexamined(1);
                return unavailable(meter, "classification-work-limit", WORKER_FAILED);
            }
            for site in &reply.sites {
                if !meter.retain(site.retained_bytes()) {
                    meter.count_unexamined(1);
                    return unavailable(meter, "classification-work-limit", WORKER_FAILED);
                }
            }
            meter.exhausted.set(reply.exhausted);
            return Classified {
                sites: reply.sites,
                omissions: reply.omissions,
                javascript: Some(Rc::new(Proofs {
                    handlers: reply
                        .handlers
                        .into_iter()
                        .map(|(at, table, role, ambiguous)| {
                            ((at, table), ambiguous.map_or(Ok(role), Err))
                        })
                        .collect(),
                    positions: reply.positions.into_iter().collect(),
                    failure: reply.failure,
                    _memory: memory,
                })),
            };
        }
        if bytes.starts_with(crate::js_worker_alloc::REFUSED)
            && bytes.len() == 24
            && output.exit_code == Some(75)
            && u64::from_le_bytes(bytes[8..16].try_into().unwrap()) <= heap
            && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) <= work
        {
            meter.charge(u64::from_le_bytes(bytes[16..24].try_into().unwrap()));
            meter.count_unexamined(1);
            return unavailable(
                meter,
                "classification-work-limit",
                "JavaScript parser/semantic allocation ceiling reached before allocation; binding proof omitted.",
            );
        }
    }
    worker_failure(
        meter,
        work,
        if output.success { "protocol" } else { "crash" },
    )
}

#[cfg(test)]
#[test]
fn allocation_refusal_is_counted_and_does_not_poison_the_next_artifact() {
    let source = "{}".repeat(50_000);
    let meter = Meter::new();
    let result = classify_with_heap(&source, &meter, 2 << 20);
    assert_eq!(result.omissions[0]["reason"], "classification-work-limit");
    assert!(
        result.omissions[0]["detail"]
            .as_str()
            .unwrap()
            .contains("allocation ceiling")
    );
    assert_eq!(result.omissions[0]["omitted_records"], 1);
    assert!(meter.parser_peak() <= 2 << 20);
    assert!(meter.parser_peak() > 0);
    let source = crate::vm::review_inputs::CONTROL_VM;
    let result = classify(source, &Meter::new());
    assert!(
        result
            .sites
            .iter()
            .any(|site| site.role() == Role::InterpreterCandidate)
    );
}

#[cfg(test)]
#[test]
fn oversized_source_is_refused_before_worker_allocation() {
    let source = " ".repeat(MAX_SOURCE + 1);
    let meter = Meter::new();
    let result = classify(&source, &meter);
    assert_eq!(result.omissions[0]["omitted_records"], 1);
    assert_eq!(result.omissions[0]["reason"], "classification-work-limit");
    assert_eq!(meter.parser_peak(), 0);
}

#[cfg(test)]
thread_local! { static WORKER_FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
#[test]
fn worker_failures_are_counted_not_saved_and_retry_without_input_changes() {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    let source = crate::vm::review_inputs::CONTROL_VM.as_bytes();
    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(source))
    };
    fs::create_dir(root.path().join("blobs")).unwrap();
    fs::write(root.path().join(format!("blobs/{hash}.bin")), source).unwrap();
    let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"dynamic_javascript","kind":"javascript","url":"fixture://worker-control.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
    fs::write(root.path().join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
    let events = root.path().join("events.jsonl");
    fs::write(&events, "").unwrap();
    for fault in ["timeout", "crash", "spawn", "protocol"] {
        WORKER_FAULT.set(Some(fault));
        let classified = classify(std::str::from_utf8(source).unwrap(), &Meter::new());
        assert_eq!(
            classified.omissions[0],
            json!({"reason":"analysis-worker-failed","omitted_records":1,"detail":fault})
        );
        let error = crate::vm::store(root.path(), &events).unwrap_err();
        assert_eq!(error.status, 503);
        assert!(error.message.contains(fault), "{error:?}");
        assert!(
            !root.path().join("analysis").exists(),
            "failed worker persisted evidence"
        );
        WORKER_FAULT.set(None);
        crate::vm::store(root.path(), &events).unwrap();
        let workspace: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            workspace["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        fs::remove_dir_all(root.path().join("analysis")).unwrap();
    }
}

#[cfg(test)]
#[test]
fn worker_drops_inherited_environment_descriptors_and_network() {
    WORKER_FAULT.set(Some("capabilities"));
    let result = classify(crate::vm::review_inputs::CONTROL_VM, &Meter::new());
    WORKER_FAULT.set(None);
    assert!(result.omissions.is_empty(), "{:?}", result.omissions);
    assert!(
        result
            .sites
            .iter()
            .any(|site| site.role() == Role::InterpreterCandidate)
    );
}
