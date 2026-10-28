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

pub(crate) type Verdict = Result<Option<Role>, &'static str>;
const AMBIGUOUS: &str = "A handler table has no unique, stable lexical binding to an interpreter dispatch. Its entries are not claimed as guest opcodes.";
const PARSE_FAILED: &str = "parse-failed: JavaScript syntax or semantic analysis failed; recovered handlers have no binding proof.";

pub(crate) struct Proofs {
    // Exact original-byte starts of AST cases and object properties. No source
    // rescan is needed when base recovery asks whether a claim is justified.
    handlers: HashMap<(usize, bool), Verdict>,
    failure: Option<String>,
    _memory: Memory,
}
impl Proofs {
    pub(crate) fn verdict(&self, offset: usize, table: bool) -> Result<Option<Role>, &str> {
        self.failure.as_deref().map_or_else(
            || {
                self.handlers
                    .get(&(offset, table))
                    .copied()
                    .unwrap_or(Err(AMBIGUOUS))
            },
            Err,
        )
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
}
impl Trace<'_> {
    fn new(source: Source) -> Self {
        Self {
            source,
            repeats: false,
            anchor: None,
            buffer: None,
            buffer_kind: None,
            lookup: false,
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
    loop_tables: HashMap<NodeId, HashSet<Key<'a>>>,
    invoked_loops: HashMap<NodeId, NodeId>,
    table_functions: HashMap<NodeId, Key<'a>>,
    property_writes: HashMap<&'a str, usize>,
    unknown_property_write: bool,
    objects: HashMap<NodeId, (Key<'a>, u32, ScopeId)>,
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
        });
    }
    fn index(semantic: &'s Semantic<'a>, meter: &'s Meter) -> Self {
        let nodes = semantic.nodes();
        let scoping = semantic.scoping();
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
            loop_tables: HashMap::new(),
            invoked_loops: HashMap::new(),
            table_functions: HashMap::new(),
            property_writes: HashMap::new(),
            unknown_property_write: false,
            objects: HashMap::new(),
            candidates: Vec::new(),
        };
        // Scope IDs and node IDs are preorder. Inherited facts take one lookup,
        // including at thousands of nested functions, never an ancestor walk.
        for scope in scoping.scope_descendants_from_root() {
            let flags = scoping.scope_flags(scope);
            facts.opaque[scope.index()] = flags.contains_direct_eval()
                || flags.is_with()
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
                    // Mutator functions can be extracted by destructuring or
                    // passed through aliases. Member proof does not try to
                    // model arbitrary Object/Reflect API data flow.
                    if matches!(reference.name.as_str(), "Object" | "Reflect") {
                        facts.unknown_property_write = true;
                    }
                    if let Some(reference_id) = reference.reference_id.get() {
                        let reference = scoping.get_reference(reference_id);
                        if reference.is_write()
                            && let Some(symbol) = reference.symbol_id()
                        {
                            facts.changed_symbols.insert(symbol);
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
                        facts.add_definition(Key::Symbol(symbol), value, d.span.start, context);
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
                            facts.add_definition(key, &a.right, a.span.start, context);
                        }
                    }
                    match &a.left {
                        AssignmentTarget::StaticMemberExpression(m) => {
                            *facts
                                .property_writes
                                .entry(m.property.name.as_str())
                                .or_default() += 1;
                        }
                        AssignmentTarget::AssignmentTargetIdentifier(_) => (),
                        // Destructuring may write a member several levels deep.
                        // No claim is made about arbitrary computed key values.
                        _ => facts.unknown_property_write = true,
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
                    match &update.argument {
                        SimpleAssignmentTarget::StaticMemberExpression(m) => {
                            *facts
                                .property_writes
                                .entry(m.property.name.as_str())
                                .or_default() += 1;
                        }
                        SimpleAssignmentTarget::AssignmentTargetIdentifier(_) => (),
                        _ => facts.unknown_property_write = true,
                    }
                }
                AstKind::UnaryExpression(unary) if unary.operator.as_str() == "delete" => {
                    facts.unknown_property_write = true
                }
                AstKind::StaticMemberExpression(member)
                    if matches!(
                        member.property.name.as_str(),
                        "assign" | "defineProperty" | "defineProperties" | "set"
                    ) =>
                {
                    facts.unknown_property_write = true
                }
                AstKind::ComputedMemberExpression(member) if matches!(member.object.get_inner_expression(), Expression::Identifier(id) if matches!(id.name.as_str(), "Object" | "Reflect")) => {
                    facts.unknown_property_write = true
                }
                AstKind::ObjectProperty(property) => {
                    if property.computed {
                        facts.unknown_property_write = true;
                    } else if let PropertyKey::StaticIdentifier(id) = &property.key {
                        *facts.property_writes.entry(id.name.as_str()).or_default() += 1;
                    } else if let PropertyKey::StringLiteral(key) = &property.key
                        && let Some(name) = key.value.as_str()
                    {
                        *facts.property_writes.entry(name).or_default() += 1;
                    }
                }
                AstKind::PropertyDefinition(property) => {
                    if property.computed {
                        facts.unknown_property_write = true;
                    } else if let PropertyKey::StaticIdentifier(id) = &property.key {
                        *facts.property_writes.entry(id.name.as_str()).or_default() += 1;
                    } else if let PropertyKey::StringLiteral(key) = &property.key
                        && let Some(name) = key.value.as_str()
                    {
                        *facts.property_writes.entry(name).or_default() += 1;
                    }
                }
                AstKind::MethodDefinition(method) => {
                    if method.computed {
                        facts.unknown_property_write = true;
                    } else if let PropertyKey::StaticIdentifier(id) = &method.key {
                        *facts.property_writes.entry(id.name.as_str()).or_default() += 1;
                    } else if let PropertyKey::StringLiteral(key) = &method.key
                        && let Some(name) = key.value.as_str()
                    {
                        *facts.property_writes.entry(name).or_default() += 1;
                    }
                }
                AstKind::SpreadElement(_) => facts.unknown_property_write = true,
                AstKind::ObjectExpression(object) => {
                    if let Some(owner) = facts.object_owner(id) {
                        facts.objects.insert(object.node_id.get(), owner);
                    }
                }
                AstKind::CallExpression(call) => {
                    if let Expression::StaticMemberExpression(member) =
                        call.callee.get_inner_expression()
                        && matches!(
                            member.property.name.as_str(),
                            "assign" | "defineProperty" | "defineProperties" | "set"
                        )
                    {
                        facts.unknown_property_write = true;
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
                        && facts.target(&assignment.left, context).is_some()
                        && facts.target(&assignment.left, context)
                            == facts.key(&call.callee, context)
                    {
                        facts.candidates.push(Candidate {
                            node: node.id(),
                            selector: &call.callee,
                            table: None,
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
                    }
                    break;
                }
                // An intervening lexical declaration suppresses Annex B.
                if scope != node.scope_id() && scoping.get_binding(scope, id.name).is_some() {
                    break;
                }
            }
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
                if matches!(nodes.kind(parent), AstKind::ObjectProperty(_))
                    && let Some((key, _, _)) = facts.objects.get(&nodes.parent_id(parent))
                {
                    facts.table_functions.insert(node.id(), *key);
                }
            }
        }
        // Follow statically bound direct helper calls, at most 16 edges. This
        // lets a step function's dispatch inherit the invoking loop without
        // rewalking its body or following unknown call targets.
        let mut functions = HashMap::new();
        let mut calls = Vec::new();
        for node in nodes.iter() {
            match node.kind() {
                AstKind::Function(function) => {
                    if let Some(id) = &function.id
                        && let Some(symbol) = id.symbol_id.get()
                        && !facts.changed_symbols.contains(&symbol)
                    {
                        functions.insert(symbol, node.id());
                    }
                }
                AstKind::CallExpression(call) => {
                    if let Expression::Identifier(id) = call.callee.get_inner_expression()
                        && let Some(symbol) = facts.symbol(id)
                    {
                        calls.push((node.id(), symbol));
                    }
                }
                _ => (),
            }
        }
        for _ in 0..16 {
            let mut changed = false;
            for &(call, symbol) in &calls {
                if !meter.charge(1) {
                    break;
                }
                if let (Some(&function), Some(loop_id)) =
                    (functions.get(&symbol), facts.loop_id(call))
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
            if let Some(table) = write
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
    fn trace(
        &self,
        expression: &'a Expression<'a>,
        candidate: &Candidate<'a>,
        query: &mut Query,
        depth: u8,
    ) -> Trace<'a> {
        if !query.step(self.meter, depth) {
            return Trace::new(Source::Unknown);
        }
        let context = self.context(candidate.node);
        let expression = expression.get_inner_expression();
        match expression {
            Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => Trace::new(Source::Constant),
            Expression::Identifier(identifier) => {
                let Some(symbol) = self.symbol(identifier) else {
                    return Trace::new(Source::Unknown);
                };
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
                    let mut trace = self.trace(definition.value, candidate, query, depth + 1);
                    trace.anchor = Some(definition.at);
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
            ),
            Expression::StaticMemberExpression(_) => {
                let mut trace = Trace::new(Source::FrameSlot);
                if let Some(key) = self.key(expression, context) {
                    trace.repeats = self.advances(key, candidate, true, query);
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
                    )
                } else {
                    Trace::new(Source::Unknown)
                }
            }
            Expression::BinaryExpression(binary) => {
                let left = self.trace(&binary.left, candidate, query, depth + 1);
                let right = self.trace(&binary.right, candidate, query, depth + 1);
                if (left.repeats, priority(left.source)) >= (right.repeats, priority(right.source))
                {
                    left
                } else {
                    right
                }
            }
            Expression::UnaryExpression(unary) => {
                self.trace(&unary.argument, candidate, query, depth + 1)
            }
            Expression::AssignmentExpression(a) => {
                self.trace(&a.right, candidate, query, depth + 1)
            }
            Expression::SequenceExpression(sequence) => sequence.expressions.last().map_or_else(
                || Trace::new(Source::Unknown),
                |value| self.trace(value, candidate, query, depth + 1),
            ),
            Expression::UpdateExpression(update) => {
                let mut trace = Trace::new(Source::Constant);
                if let Some(key) = self.simple_target(&update.argument, context) {
                    trace.repeats = self.advances(key, candidate, true, query);
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
    ) -> Trace<'a> {
        let context = self.context(candidate.node);
        if let Some(key) = self.index_key(index, context, 0)
            && self.advances(key, candidate, !matches!(key, Key::Symbol(_)), query)
        {
            let mut trace = Trace::new(if matches!(key, Key::Symbol(_)) {
                Source::CursorIndex
            } else {
                Source::FrameSlot
            });
            trace.repeats = self.executes_in_loop(context.function, span, candidate);
            trace.anchor = Some(span.start);
            trace.buffer = self.key(buffer, context);
            trace.buffer_kind = buffer_kind.or_else(|| self.buffer_kind(buffer, context));
            return trace;
        }
        let mut trace = self.trace(index, candidate, query, depth + 1);
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
    fn stable(&self, key: Key<'a>, at: u32, scope: ScopeId) -> bool {
        if self.scope_opaque(scope) {
            return false;
        }
        match key {
            Key::Symbol(symbol) => {
                !self.changed_symbols.contains(&symbol)
                    && self.definitions.get(&key).is_some_and(|definitions| {
                        definitions.len() == 1 && definitions[0].at == at
                    })
            }
            Key::Member(symbol, name) => {
                !self.changed_symbols.contains(&symbol)
                    && self
                        .definitions
                        .get(&Key::Symbol(symbol))
                        .is_none_or(|definitions| definitions.len() <= 1)
                    && !self.unknown_property_write
                    && self.property_writes.get(name) == Some(&1)
            }
            Key::This(_, name) => {
                !self.unknown_property_write && self.property_writes.get(name) == Some(&1)
            }
            Key::Slot(_, _) => false,
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
        let trace = if candidate.kind == Kind::Threaded {
            let mut trace = Trace::new(Source::HandlerAddress);
            trace.repeats = facts.loop_id(candidate.node).is_some();
            trace
        } else {
            facts.trace(candidate.selector, candidate, &mut query, 0)
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
    let nodes = semantic.semantic.nodes();
    // Prove each object once, not once per property times every dispatch.
    // Stability permits only one definition for a key, so each dispatch is
    // considered at most once across these object queries.
    let mut object_verdicts = HashMap::new();
    for (&object, &(key, at, scope)) in &facts.objects {
        if !meter.charge(1) {
            break;
        }
        let verdict = if !facts.stable(key, at, scope) {
            Err(AMBIGUOUS)
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
                // This assignments must precede the whole dispatch loop.
                let before = if matches!(key, Key::This(..)) {
                    facts
                        .loop_span(dispatch)
                        .is_some_and(|range| at < range.start)
                } else {
                    at < site.span().start
                };
                if before && (verdict.is_none() || role == Role::InterpreterCandidate) {
                    verdict = Some(role);
                }
            }
            Ok(verdict)
        };
        object_verdicts.insert(object, verdict);
    }
    for node in nodes.iter() {
        if !meter.charge(1) {
            break;
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
                    .unwrap_or(Err(AMBIGUOUS));
                (property.span.start as usize, true, verdict)
            }
            _ => continue,
        };
        if !memory.keep(96) {
            break;
        }
        handlers.insert((offset, table), verdict);
    }
    Some(Classified {
        sites,
        omissions: meter.omissions("JavaScript artifacts"),
        javascript: Some(Rc::new(Proofs {
            handlers,
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
            failure: Some(detail.to_owned()),
            _memory: Memory::new(meter),
        })),
    }
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
    // Conservative syntax-complexity admission, not a lexer or classifier.
    // Counting raw punctuation may refuse a huge literal/comment, but never
    // creates a claim from it. It bounds recursive parser/semantic stack use.
    let mut depth = 0usize;
    let mut chain = 0usize;
    let mut stack = PARSER_STACK;
    if failure.is_none() {
        let mut word_start = 0;
        for (index, byte) in source.bytes().enumerate() {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')) {
                if matches!(
                    &source.as_bytes()[word_start..index],
                    b"new" | b"typeof" | b"void" | b"delete" | b"await" | b"yield"
                ) {
                    chain += 1;
                }
                word_start = index + 1;
            }
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => (),
            }
            if b";{}".contains(&byte) {
                chain = 0;
            } else if b"=+-!~?&|*/%<>^:.()[]".contains(&byte) {
                chain += 1;
            }
            if depth > MAX_SYNTAX_DEPTH || chain > MAX_SYNTAX_DEPTH {
                failure = Some("JavaScript parser nesting or expression admission limit reached.");
                break;
            }
            if depth > 1024 || chain > 1024 {
                stack = PARSER_STACK * 2;
            }
        }
    }
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
struct WorkerReply {
    sites: Vec<Site>,
    omissions: Vec<serde_json::Value>,
    handlers: Vec<(usize, bool, Option<Role>, bool)>,
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
                (offset, table, verdict.ok().flatten(), verdict.is_err())
            })
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

fn worker_command() -> std::io::Result<tokio::process::Command> {
    let current = std::env::current_exe()?;
    #[cfg(test)]
    {
        let mut command = tokio::process::Command::new(current);
        command
            .args([
                "--ignored",
                "--exact",
                "vm::dispatch_shape::javascript::worker_process",
                "--nocapture",
            ])
            .env("REB_JS_TEST_WORKER", "1");
        Ok(command)
    }
    #[cfg(not(test))]
    {
        let directory = current
            .parent()
            .ok_or_else(|| std::io::Error::other("No executable directory"))?;
        let mut candidates = vec![
            directory.join("origin-trace-vm"),
            directory.join("OriginTraceVMAnalyzer"),
        ];
        // Cargo integration tests and examples live one directory below bins.
        if directory
            .file_name()
            .is_some_and(|name| name == "deps" || name == "examples")
        {
            candidates.push(directory.parent().unwrap().join("origin-trace-vm"));
        }
        let path = candidates
            .into_iter()
            .find(|path| crate::worker::executable(path))
            .ok_or_else(|| std::io::Error::other("JavaScript analyzer executable unavailable"))?;
        let mut command = tokio::process::Command::new(path);
        command.arg("--classify-javascript-worker");
        Ok(command)
    }
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
    let output = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                let mut command = worker_command().ok()?;
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
                        std::time::Duration::from_secs(30),
                    ))
                    .ok()
            })
            .ok()?
            .join()
            .ok()
            .flatten()
    });
    let Some(output) = output else {
        // With no telemetry, charge the remaining work allowance. A killed or
        // unavailable worker never leaves uncharged work or permits claims.
        meter.charge(work);
        meter.count_unexamined(1);
        return unavailable(meter, "classification-work-limit", WORKER_FAILED);
    };
    if !meter.charge(output.bytes.len() as u64) {
        meter.count_unexamined(1);
        return unavailable(meter, "classification-work-limit", WORKER_FAILED);
    }
    let marker = output
        .bytes
        .windows(8)
        .position(|bytes| bytes == REPLY_MAGIC || bytes == crate::js_worker_alloc::REFUSED);
    if let Some(at) = marker {
        let bytes = &output.bytes[at..];
        if bytes.len() >= 16 {
            meter.record_parser_peak(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
        }
        if bytes.starts_with(REPLY_MAGIC)
            && output.success
            && bytes.len() >= 16
            && let Ok(reply) = serde_json::from_slice::<WorkerReply>(&bytes[16..])
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
            if !memory.keep(reply.handlers.len() as u64 * 96) {
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
                            (
                                (at, table),
                                if ambiguous { Err(AMBIGUOUS) } else { Ok(role) },
                            )
                        })
                        .collect(),
                    failure: reply.failure,
                    _memory: memory,
                })),
            };
        }
        if bytes.starts_with(crate::js_worker_alloc::REFUSED) && bytes.len() >= 24 {
            meter.charge(u64::from_le_bytes(bytes[16..24].try_into().unwrap()));
            meter.count_unexamined(1);
            return unavailable(
                meter,
                "classification-work-limit",
                "JavaScript parser/semantic allocation ceiling reached before allocation; binding proof omitted.",
            );
        }
    }
    meter.charge(work);
    meter.count_unexamined(1);
    unavailable(meter, "classification-work-limit", WORKER_FAILED)
}

// Unit tests use their own executable, so `cargo test --lib` exercises the
// identical isolation/allocator boundary without a stale or unbuilt helper.
#[cfg(test)]
#[test]
#[ignore]
fn worker_process() {
    if std::env::var_os("REB_JS_TEST_WORKER").is_some() {
        let code = if worker_main().is_ok() { 0 } else { 74 };
        std::process::exit(code);
    }
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
    let source = include_str!("../../../tools/fixtures/dispatch-retention/owned/control.js");
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
