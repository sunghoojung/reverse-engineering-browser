//! Source-anchored, inert lexical/evaluation facts. These are not a CFG, runtime
//! trace, reaching definitions, call-target proof, or a JavaScript interpreter.
use oxc_allocator::Allocator;
use oxc_ast::{AstKind, ast::*};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::{ScopeFlags, ScopeId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

// The bounded preflight admits at most `preflight::MAX_TREE_NODES` tree-sitter
// nodes, so this budget is no longer the first limit an admitted source meets.
// It stays fixed rather than caller-supplied: a per-request budget would make
// two reports of the same bytes disagree. Larger sources are addressed with a
// region instead, which is now reachable for the dense minified bundles that
// the preflight node bound used to refuse before this budget was consulted.
const MAX_AST_NODES: usize = 262_144;
const MAX_FACTS: usize = 16_384;
const MAX_FRONTIERS: usize = 256;
const MAX_BINDING_CANDIDATES: usize = 64;

/// Half-open original-byte window carried from `region_start_byte` and
/// `region_end_byte`. The worker never derives one from text, a name or a
/// previous report.
#[derive(Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub start: u32,
    pub end: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: String,
    pub source: String,
    #[serde(default)]
    pub region: Option<Region>,
}
/// Facts outside `coverage.analyzed_range` are not produced; this is scoping,
/// not budget loss, so it never sets `truncated`.
const SCOPED: &str =
    "analysis covered coverage.analyzed_range only; omitted syntax remains unknown";
const WHOLE: &str =
    "the requested region is not inside a callable body; the whole program was analyzed";
const NARROW: &str =
    "request region_start_byte and region_end_byte to analyze one callable body instead";

/// A node is analyzed when it overlaps the analyzed window. Every enclosing
/// node overlaps, so the real scope chain above a selected callable body is
/// retained while its siblings are skipped.
fn analyzing(window: Option<Span>, span: Span) -> bool {
    window.is_none_or(|w| span.start < w.end && span.end > w.start)
}
fn contains(outer: Span, inner: Span) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}
fn range(span: Span) -> Value {
    json!({"start":span.start,"end":span.end})
}
fn key(cell: &Cell<Option<ScopeId>>) -> usize {
    cell as *const _ as usize
}
fn response(bytes: usize) -> Value {
    json!({"schema":"reb-javascript-source-facts-v1","profile":"lexical-effects-v1",
        "offset_unit":"utf-8-byte","source_bytes":bytes,"ok":true,
        "scopes":[],"bindings":[],"callables":[],"regions":[],"operations":[],
        "coverage":{"status":"complete","truncated":false,"diagnostics":[],"frontiers":[],
        "analyzed_range":{"start":0,"end":bytes}},
        "limits":{"max_source_bytes":crate::MAX_SOURCE_BYTES,"max_ast_nodes":MAX_AST_NODES,
        "max_facts":MAX_FACTS,"max_frontiers":MAX_FRONTIERS,"max_binding_candidates":MAX_BINDING_CANDIDATES,
        // Reported from the guard's own constants so a declared limit cannot
        // drift from the bound that actually decided admission.
        "preflight_depth":crate::preflight::MAX_TREE_DEPTH,
        "preflight_nodes":crate::preflight::MAX_TREE_NODES,
        "preflight_parse_heap_bytes":crate::preflight::MAX_PARSE_HEAP_BYTES}})
}
pub fn invalid(message: &str, bytes: usize) -> Value {
    let mut out = response(bytes);
    out["ok"] = json!(false);
    out["coverage"]["status"] = json!("unavailable");
    out["coverage"]["diagnostics"] = json!([message]);
    out
}
pub fn analyze(request: Request) -> Value {
    let source = &request.source;
    if request.operation != "source_facts" {
        return invalid("invalid operation", source.len());
    }
    if source.len() > crate::MAX_SOURCE_BYTES {
        return invalid("source byte limit exceeded", source.len());
    }
    let requested = match request.region {
        None => None,
        Some(region) => {
            let (start, end) = (region.start as usize, region.end as usize);
            if start > end
                || end > source.len()
                || !source.is_char_boundary(start)
                || !source.is_char_boundary(end)
            {
                return invalid(
                    "requested region is not an original byte range",
                    source.len(),
                );
            }
            Some(Span::new(region.start, region.end))
        }
    };
    if let Err(error) = crate::preflight::check(source) {
        return invalid(error, source.len());
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::unambiguous()).parse();
    if !parsed.diagnostics.is_empty() {
        // Diagnostics are deliberately stable and bounded; callers can retain
        // the original bytes without copying parser excerpts into logs.
        return invalid(
            "Oxc found malformed or unsupported JavaScript",
            source.len(),
        );
    }
    // Select the analysis unit inside the real parse of the complete source. A
    // requested byte range is never parsed on its own: its meaning depends on
    // the scope chain, strictness and syntactic position of the bytes around it.
    let window = requested.and_then(|want| {
        let mut select = Select { want, body: None };
        select.visit_program(&parsed.program);
        select.body
    });
    let analyzed = window.unwrap_or(parsed.program.span);
    let mut out = response(source.len());
    out["coverage"]["analyzed_range"] = range(analyzed);
    let mut count = Count { nodes: 0, window };
    count.visit_program(&parsed.program);
    if count.nodes > MAX_AST_NODES {
        return exhausted(
            out,
            "AST node budget exceeded; no lexical resolutions produced",
            requested,
            window,
        );
    }
    let mut declarations = Declarations {
        window,
        ..Default::default()
    };
    declarations.visit_program(&parsed.program);
    let base =
        declarations.scopes.len() + declarations.bindings.len() + declarations.callables.len();
    if base >= MAX_FACTS {
        return exhausted(
            out,
            "declaration budget exceeded; no lexical resolutions produced",
            requested,
            window,
        );
    }
    let mut effects = Effects::new(&declarations, base);
    effects.visit_program(&parsed.program);
    out["scopes"] = json!(
        declarations
            .scopes
            .iter()
            .map(|s| &s.fact)
            .collect::<Vec<_>>()
    );
    out["bindings"] = json!(declarations.bindings);
    out["callables"] = json!(declarations.callables);
    out["regions"] = json!(effects.regions);
    out["operations"] = json!(effects.operations);
    let mut diagnostics = Vec::new();
    if effects.truncated {
        diagnostics.push("fact or frontier budget exceeded; omitted syntax remains unknown");
    }
    if window.is_some() {
        diagnostics.push(SCOPED);
    }
    out["coverage"] = json!({"status":if effects.frontiers.is_empty() && diagnostics.is_empty() {"complete"} else {"partial"},
        "truncated":effects.truncated,"diagnostics":diagnostics,
        "frontiers":effects.frontiers,"analyzed_range":range(analyzed)});
    out
}
/// A reached budget keeps empty fact tables: resolving references against an
/// incomplete declaration table would be a guess. The note says which narrower
/// request can still produce facts, and `analyzed_range` says what was tried.
fn exhausted(
    mut out: Value,
    message: &str,
    requested: Option<Span>,
    window: Option<Span>,
) -> Value {
    let note = match (requested, window) {
        (_, Some(_)) => SCOPED,
        (Some(_), None) => WHOLE,
        (None, None) => NARROW,
    };
    out["coverage"]["status"] = json!("partial");
    out["coverage"]["truncated"] = json!(true);
    out["coverage"]["diagnostics"] = json!([message, note]);
    out
}
/// Resolve the innermost callable body containing the requested window. A body
/// is the analysis unit because its own declaration table stays closed: nothing
/// inside it is skipped. A window no callable body contains analyzes the whole
/// program rather than a syntactic fragment of one.
struct Select {
    want: Span,
    body: Option<Span>,
}
impl<'a> Visit<'a> for Select {
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if contains(it.span(), self.want) {
            walk::walk_statement(self, it);
        }
    }
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if contains(it.span(), self.want) {
            walk::walk_expression(self, it);
        }
    }
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if !contains(it.span, self.want) {
            return;
        }
        if let Some(body) = &it.body
            && contains(body.span, self.want)
        {
            self.body = Some(body.span);
        }
        walk::walk_function(self, it, flags);
    }
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if !contains(it.span, self.want) {
            return;
        }
        if contains(it.body.span(), self.want) {
            self.body = Some(it.body.span());
        }
        walk::walk_arrow_function_expression(self, it);
    }
}
struct Count {
    nodes: usize,
    window: Option<Span>,
}
impl<'a> Visit<'a> for Count {
    fn enter_node(&mut self, _: AstKind<'a>) {
        self.nodes += 1;
    }
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.nodes <= MAX_AST_NODES && analyzing(self.window, it.span()) {
            walk::walk_expression(self, it);
        }
    }
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.nodes <= MAX_AST_NODES && analyzing(self.window, it.span()) {
            walk::walk_statement(self, it);
        }
    }
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if self.nodes <= MAX_AST_NODES && analyzing(self.window, it.span) {
            walk::walk_function(self, it, flags);
        }
    }
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if self.nodes <= MAX_AST_NODES && analyzing(self.window, it.span) {
            walk::walk_arrow_function_expression(self, it);
        }
    }
}
struct Scope {
    fact: Value,
    parent: Option<usize>,
    flags: ScopeFlags,
    names: BTreeMap<String, Vec<usize>>,
}
#[derive(Default)]
struct Declarations {
    scopes: Vec<Scope>,
    bindings: Vec<Value>,
    callables: Vec<Value>,
    binding_map: BTreeMap<(u32, u32), usize>,
    scope_map: BTreeMap<usize, usize>,
    callable_map: BTreeMap<(u32, u32), usize>,
    scope_stack: Vec<usize>,
    node_stack: Vec<Span>,
    kind: &'static str,
    ignored: BTreeSet<(u32, u32)>,
    uncertain: BTreeSet<usize>,
    /// Scopes that own syntax this report did not analyze. Their declaration
    /// tables are open sets, so neither a hit nor a miss in one is a fact.
    incomplete: BTreeSet<usize>,
    window: Option<Span>,
    dynamic: bool,
}
impl Declarations {
    fn current(&self) -> usize {
        *self.scope_stack.last().unwrap()
    }
    fn var_scope(&self) -> usize {
        *self
            .scope_stack
            .iter()
            .rev()
            .find(|&&i| self.scopes[i].flags.is_var())
            .unwrap()
    }
    /// Syntax owned by the current scope chain was skipped. A lexical
    /// declaration would have bound in the current scope and a `var` in the
    /// nearest var scope, so exactly those two tables stop being closed.
    /// Scopes inside the skipped syntax are not in this report at all.
    fn skipped(&mut self) {
        let current = self.current();
        self.incomplete.insert(current);
        let var = self.var_scope();
        self.incomplete.insert(var);
    }
    fn add(&mut self, id: &BindingIdentifier<'_>, kind: &'static str, scope: usize) {
        let index = self.bindings.len();
        self.binding_map.insert((id.span.start, id.span.end), index);
        self.bindings.push(json!({"id":index,"scope_id":scope,"name":id.name.as_str(),"range":range(id.span),"kind":kind}));
        self.scopes[scope]
            .names
            .entry(id.name.to_string())
            .or_default()
            .push(index);
    }
    fn callable(
        &mut self,
        span: Span,
        body: Span,
        kind: &str,
        asynchronous: bool,
        generator: bool,
        params: &FormalParameters<'_>,
    ) {
        let scope = self.scopes.len();
        let id = self.callables.len();
        self.callable_map.insert((span.start, span.end), id);
        self.callables.push(json!({"id":id,"scope_id":scope,"range":range(span),"body_range":range(body),"kind":kind,"async":asynchronous,"generator":generator}));
        if params.rest.is_some()
            || params.items.iter().any(|p| {
                !matches!(p.pattern, BindingPattern::BindingIdentifier(_))
                    || p.initializer.is_some()
            })
        {
            // Parameter environments/default expressions and body var bindings
            // need distinct environments; don't pretend this profile models them.
            self.uncertain.insert(scope);
        }
    }
    fn resolve(&self, name: &str, scope: usize) -> Value {
        if self.dynamic {
            return json!({"kind":"unresolved","binding_ids":[],"resolution":"dynamic-scope","name":name});
        }
        let mut at = Some(scope);
        while let Some(index) = at {
            if self.incomplete.contains(&index) {
                // A pruned sibling could declare or duplicate this name here,
                // so a candidate set from this scope would be a guess and a
                // miss would wrongly look external.
                return json!({"kind":"unresolved","binding_ids":[],"resolution":"outside-analyzed-region","name":name});
            }
            if self.uncertain.contains(&index) {
                return json!({"kind":"unresolved","binding_ids":[],"resolution":"unsupported-environment","name":name});
            }
            if name == "arguments"
                && self.scopes[index].flags.is_function()
                && !self.scopes[index].flags.is_arrow()
                && self.scopes[index].names.get(name).is_none_or(|ids| {
                    ids.iter()
                        .all(|&id| self.bindings[id]["kind"] == "function-name")
                })
            {
                return json!({"kind":"unresolved","binding_ids":[],"resolution":"implicit-arguments-environment","name":name});
            }
            if let Some(ids) = self.scopes[index].names.get(name) {
                if ids.len() > MAX_BINDING_CANDIDATES {
                    return json!({"kind":"unresolved","binding_ids":[],"resolution":"binding-candidate-limit","name":name});
                }
                return json!({"kind":if ids.len()==1 {"binding"} else {"ambiguous"},"binding_ids":ids,
                    "resolution":if ids.len()==1 {"lexical-only"} else {"duplicate-declarations"},"name":name});
            }
            at = self.scopes[index].parent;
        }
        json!({"kind":"unresolved","binding_ids":[],"resolution":"external-or-implicit","name":name})
    }
}
impl<'a> Visit<'a> for Declarations {
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if analyzing(self.window, it.span()) {
            walk::walk_statement(self, it);
        } else {
            self.skipped();
        }
    }
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if analyzing(self.window, it.span()) {
            walk::walk_expression(self, it);
        } else {
            self.skipped();
        }
    }
    fn enter_node(&mut self, it: AstKind<'a>) {
        self.node_stack.push(it.span());
    }
    fn leave_node(&mut self, _: AstKind<'a>) {
        self.node_stack.pop();
    }
    fn enter_scope(&mut self, flags: ScopeFlags, cell: &Cell<Option<ScopeId>>) {
        let id = self.scopes.len();
        let parent = self.scope_stack.last().copied();
        let kind = if flags.is_top() {
            "program"
        } else if flags.is_function() {
            "function"
        } else if flags.is_catch_clause() {
            "catch"
        } else if flags.is_with() {
            "with"
        } else {
            "block"
        };
        self.scopes.push(Scope {fact:json!({"id":id,"parent_id":parent,"range":range(*self.node_stack.last().unwrap()),"kind":kind}),parent,flags,names:BTreeMap::new()});
        self.scope_map.insert(key(cell), id);
        self.scope_stack.push(id);
    }
    fn leave_scope(&mut self) {
        self.scope_stack.pop();
    }
    fn visit_binding_identifier(&mut self, it: &BindingIdentifier<'a>) {
        if !self.ignored.contains(&(it.span.start, it.span.end)) {
            self.add(
                it,
                if self.kind.is_empty() {
                    "lexical"
                } else {
                    self.kind
                },
                if self.kind == "var" {
                    self.var_scope()
                } else {
                    self.current()
                },
            );
        }
    }
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        let old = self.kind;
        self.kind = it.kind.as_str();
        walk::walk_variable_declaration(self, it);
        self.kind = old;
    }
    fn visit_formal_parameters(&mut self, it: &FormalParameters<'a>) {
        let old = self.kind;
        self.kind = "parameter";
        walk::walk_formal_parameters(self, it);
        self.kind = old;
    }
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let old = self.kind;
        self.kind = "import";
        walk::walk_import_declaration(self, it);
        self.kind = old;
    }
    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        let old = self.kind;
        self.kind = "catch";
        walk::walk_catch_clause(self, it);
        self.kind = old;
    }
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if !analyzing(self.window, it.span) {
            self.skipped();
            return;
        }
        if it.r#type == FunctionType::FunctionDeclaration {
            if let Some(id) = &it.id {
                self.add(id, "function", self.current());
                self.ignored.insert((id.span.start, id.span.end));
            }
            if !self.scopes[self.current()].flags.is_var() {
                self.uncertain.insert(self.var_scope());
            }
        }
        self.callable(
            it.span,
            it.body.as_ref().map_or(it.span, |b| b.span),
            "function",
            it.r#async,
            it.generator,
            &it.params,
        );
        let old = self.kind;
        self.kind = "function-name";
        walk::walk_function(self, it, flags);
        self.kind = old;
    }
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if !analyzing(self.window, it.span) {
            self.skipped();
            return;
        }
        self.callable(
            it.span,
            it.body.span(),
            "arrow",
            it.r#async,
            false,
            &it.params,
        );
        let old = self.kind;
        self.kind = "lexical";
        walk::walk_arrow_function_expression(self, it);
        self.kind = old;
    }
    fn visit_class(&mut self, it: &Class<'a>) {
        if it.r#type == ClassType::ClassDeclaration
            && let Some(id) = &it.id
        {
            self.add(id, "class", self.current());
            self.ignored.insert((id.span.start, id.span.end));
        }
        let old = self.kind;
        self.kind = "class-name";
        walk::walk_class(self, it);
        self.kind = old;
    }
    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.dynamic = true;
        walk::walk_with_statement(self, it);
    }
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if it.callee.get_inner_expression().is_specific_id("eval") {
            self.dynamic = true;
        }
        walk::walk_call_expression(self, it);
    }
}

struct Effects<'d> {
    declarations: &'d Declarations,
    scopes: Vec<usize>,
    regions: Vec<Value>,
    operations: Vec<Value>,
    frontiers: Vec<Value>,
    current_region: usize,
    callable: Option<usize>,
    orders: Vec<usize>,
    base: usize,
    truncated: bool,
}
impl<'d> Effects<'d> {
    fn new(declarations: &'d Declarations, base: usize) -> Self {
        Self {
            declarations,
            scopes: vec![],
            regions: vec![],
            operations: vec![],
            frontiers: vec![],
            current_region: 0,
            callable: None,
            orders: vec![],
            base,
            truncated: false,
        }
    }
    fn analyzed(&self, span: Span) -> bool {
        analyzing(self.declarations.window, span)
    }
    fn available(&mut self) -> bool {
        if self.base + self.regions.len() + self.operations.len() >= MAX_FACTS {
            self.truncated = true;
            false
        } else {
            true
        }
    }
    fn next(&mut self) -> usize {
        let n = self.orders[self.current_region];
        self.orders[self.current_region] += 1;
        n
    }
    fn region(&mut self, span: Span, kind: &str, action: impl FnOnce(&mut Self)) {
        if !self.available() {
            return;
        }
        let parent = if self.regions.is_empty() {
            None
        } else {
            Some(self.current_region)
        };
        let order = if parent.is_some() { self.next() } else { 0 };
        let old = self.current_region;
        self.current_region = self.regions.len();
        self.regions.push(json!({"id":self.current_region,"parent_id":parent,"callable_id":self.callable,"range":range(span),"kind":kind,"entry_order":order}));
        self.orders.push(0);
        action(self);
        self.current_region = old;
    }
    fn op(&mut self, span: Span, kind: &str, detail: Value) {
        if !self.available() {
            return;
        }
        let order = self.next();
        self.operations.push(json!({"id":self.operations.len(),"region_id":self.current_region,"order":order,"range":range(span),"kind":kind,"detail":detail}));
    }
    fn frontier(&mut self, span: Span, reason: &str) {
        if self.frontiers.len() < MAX_FRONTIERS {
            self.frontiers
                .push(json!({"range":range(span),"reason":reason}));
        } else {
            self.truncated = true;
        }
    }
    fn target(&mut self, id: &IdentifierReference<'_>) -> Value {
        let target = self
            .declarations
            .resolve(id.name.as_str(), *self.scopes.last().unwrap());
        if target["resolution"] == "binding-candidate-limit" {
            self.truncated = true;
        }
        if target["kind"] != "binding" {
            self.frontier(id.span, target["resolution"].as_str().unwrap());
        }
        target
    }
    fn binding_target(&self, id: &BindingIdentifier<'_>) -> Value {
        let ids = [self.declarations.binding_map[&(id.span.start, id.span.end)]];
        json!({"kind":"binding","binding_ids":ids,"resolution":"declaration","name":id.name.as_str()})
    }
    fn reference<'a>(
        &mut self,
        target: &SimpleAssignmentTarget<'a>,
        enclosing: Span,
    ) -> Option<Value> {
        if target
            .as_member_expression()
            .is_some_and(|m| matches!(m.object(), Expression::Super(_)))
        {
            self.frontier(enclosing, "super-reference-effects");
            return None;
        }
        let result = match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => self.target(id),
            SimpleAssignmentTarget::StaticMemberExpression(member) => {
                self.visit_expression(&member.object);
                json!({"kind":"property","object_range":range(member.object.span()),"key_range":range(member.property.span),"computed":false})
            }
            SimpleAssignmentTarget::ComputedMemberExpression(member) => {
                self.visit_expression(&member.object);
                self.visit_expression(&member.expression);
                self.frontier(member.expression.span(), "property-key-coercion");
                json!({"kind":"property","object_range":range(member.object.span()),"key_range":range(member.expression.span()),"computed":true})
            }
            _ => {
                self.frontier(enclosing, "unsupported-assignment-target");
                return None;
            }
        };
        self.op(target.span(), "reference", json!({"target":result}));
        Some(result)
    }
    fn read(&mut self, span: Span, target: &Value) {
        self.op(span, "read", json!({"target":target}));
        if target["kind"] == "property" {
            self.frontier(span, "property-read-getter-proxy-or-throw");
        }
    }
    fn write(&mut self, span: Span, target: &Value, detail: Value) {
        self.op(span, "write", json!({"target":target,"value":detail}));
        if target["kind"] == "property" {
            self.frontier(span, "property-write-setter-proxy-or-throw");
        }
    }
    fn member<'a>(&mut self, member: &MemberExpression<'a>) {
        if matches!(member.object(), Expression::Super(_)) {
            self.frontier(member.span(), "super-reference-effects");
            return;
        }
        if member.optional() {
            self.frontier(member.span(), "optional-chain-effects");
            return;
        }
        let target = match member {
            MemberExpression::StaticMemberExpression(m) => {
                self.visit_expression(&m.object);
                json!({"kind":"property","object_range":range(m.object.span()),"key_range":range(m.property.span),"computed":false})
            }
            MemberExpression::ComputedMemberExpression(m) => {
                self.visit_expression(&m.object);
                self.visit_expression(&m.expression);
                self.frontier(m.expression.span(), "property-key-coercion");
                json!({"kind":"property","object_range":range(m.object.span()),"key_range":range(m.expression.span()),"computed":true})
            }
            _ => {
                self.frontier(member.span(), "private-property-effects");
                return;
            }
        };
        self.op(member.span(), "reference", json!({"target":target}));
        self.read(member.span(), &target);
    }
    fn call<'a>(
        &mut self,
        span: Span,
        callee: &Expression<'a>,
        arguments: &[Argument<'a>],
        construct: bool,
    ) {
        if callee
            .get_inner_expression()
            .as_member_expression()
            .is_some_and(|m| matches!(m.object(), Expression::Super(_)))
        {
            self.frontier(span, "super-reference-effects");
            return;
        }
        self.visit_expression(callee);
        for argument in arguments {
            self.region(argument.span(), "eager-argument", |this| match argument {
                Argument::SpreadElement(spread) => {
                    this.visit_expression(&spread.argument);
                    this.frontier(spread.span, "spread-iterator-effects");
                }
                _ => this.visit_expression(argument.to_expression()),
            });
        }
        let inner = callee.get_inner_expression();
        let receiver = if construct {
            json!({"kind":"constructor"})
        } else if let Some(member) = inner.as_member_expression() {
            json!({"kind":"method","range":range(member.object().span())})
        } else {
            json!({"kind":"detached"})
        };
        let target = if let Expression::Identifier(id) = inner {
            Some(self.target(id))
        } else {
            None
        };
        self.op(span,if construct {"construct"} else {"call"},json!({"callee_range":range(callee.span()),"argument_ranges":arguments.iter().map(|a|range(a.span())).collect::<Vec<_>>(),"receiver":receiver,"target":target,"call_target":"unknown","argument_policy":"eager-left-to-right"}));
        self.frontier(span, "unknown-call-mutation-or-throw");
    }
}
impl<'a> Visit<'a> for Effects<'_> {
    fn enter_scope(&mut self, _: ScopeFlags, cell: &Cell<Option<ScopeId>>) {
        self.scopes.push(self.declarations.scope_map[&key(cell)]);
    }
    fn leave_scope(&mut self) {
        self.scopes.pop();
    }
    fn visit_program(&mut self, it: &Program<'a>) {
        self.region(it.span, "program", |this| {
            if let Some(window) = this.declarations.window {
                for span in [
                    Span::new(it.span.start, window.start),
                    Span::new(window.end, it.span.end),
                ] {
                    if span.start < span.end {
                        this.frontier(span, "outside-analyzed-region");
                    }
                }
            }
            if this.declarations.dynamic {
                this.frontier(it.span, "dynamic-scope");
            }
            for &scope in &this.declarations.uncertain {
                this.frontier(
                    Span::new(
                        this.declarations.scopes[scope].fact["range"]["start"]
                            .as_u64()
                            .unwrap() as u32,
                        this.declarations.scopes[scope].fact["range"]["end"]
                            .as_u64()
                            .unwrap() as u32,
                    ),
                    "unsupported-binding-environment",
                );
            }
            walk::walk_program(this, it);
        });
    }
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if !self.available() || !self.analyzed(it.span) {
            return;
        }
        let old = self.callable;
        self.callable = Some(self.declarations.callable_map[&(it.span.start, it.span.end)]);
        self.region(
            it.body.as_ref().map_or(it.span, |b| b.span),
            "callable-body",
            |this| {
                if it.r#async || it.generator {
                    this.frontier(it.span, "async-or-generator-execution");
                } else {
                    walk::walk_function(this, it, flags);
                }
            },
        );
        self.callable = old;
        self.op(
            it.span,
            "function-value",
            json!({"callable_id":self.declarations.callable_map[&(it.span.start,it.span.end)]}),
        );
    }
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if !self.available() || !self.analyzed(it.span) {
            return;
        }
        let old = self.callable;
        self.callable = Some(self.declarations.callable_map[&(it.span.start, it.span.end)]);
        self.region(it.body.span(), "callable-body", |this| {
            if it.r#async {
                this.frontier(it.span, "async-or-generator-execution");
            } else {
                walk::walk_arrow_function_expression(this, it);
            }
        });
        self.callable = old;
        self.op(
            it.span,
            "function-value",
            json!({"callable_id":self.declarations.callable_map[&(it.span.start,it.span.end)]}),
        );
    }
    fn visit_class(&mut self, it: &Class<'a>) {
        self.frontier(it.span, "class-initialization-effects");
    }
    fn visit_formal_parameters(&mut self, it: &FormalParameters<'a>) {
        if it.rest.is_some()
            || it.items.iter().any(|p| {
                !matches!(p.pattern, BindingPattern::BindingIdentifier(_))
                    || p.initializer.is_some()
            })
        {
            self.frontier(it.span, "parameter-default-or-destructuring-effects");
        }
    }
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind.is_using() {
            self.frontier(it.span, "resource-disposal-effects");
        }
        walk::walk_variable_declaration(self, it);
    }
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            self.visit_expression(init);
        }
        if let BindingPattern::BindingIdentifier(id) = &it.id {
            // `var x;` is not an assignment and cannot erase an earlier value.
            if it.init.is_some()
                || self.declarations.bindings
                    [self.declarations.binding_map[&(id.span.start, id.span.end)]]["kind"]
                    != "var"
            {
                let target = self.binding_target(id);
                self.write(id.span,&target,json!({"kind":"initialize","value_range":it.init.as_ref().map(|v|range(v.span()))}));
            }
        } else {
            self.frontier(it.span, "destructuring-binding-effects");
        }
    }
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if !self.available() || !self.analyzed(it.span()) {
            return;
        }
        match it {
            Statement::IfStatement(s) => {
                self.visit_expression(&s.test);
                self.region(s.consequent.span(), "conditional-then", |t| {
                    t.visit_statement(&s.consequent)
                });
                if let Some(a) = &s.alternate {
                    self.region(a.span(), "conditional-else", |t| t.visit_statement(a));
                }
            }
            Statement::WhileStatement(s) => {
                self.region(s.test.span(), "repeated-test", |t| {
                    t.visit_expression(&s.test)
                });
                self.region(s.body.span(), "repeated-body", |t| {
                    t.visit_statement(&s.body)
                });
            }
            Statement::DoWhileStatement(s) => {
                self.region(s.body.span(), "repeated-body", |t| {
                    t.visit_statement(&s.body)
                });
                self.region(s.test.span(), "repeated-test", |t| {
                    t.visit_expression(&s.test)
                });
            }
            Statement::ForStatement(s) => {
                self.enter_scope(ScopeFlags::empty(), &s.scope_id);
                if let Some(init) = &s.init {
                    self.visit_for_statement_init(init);
                }
                if let Some(test) = &s.test {
                    self.region(test.span(), "repeated-test", |t| t.visit_expression(test));
                }
                self.region(s.body.span(), "repeated-body", |t| {
                    t.visit_statement(&s.body)
                });
                if let Some(update) = &s.update {
                    self.region(update.span(), "repeated-update", |t| {
                        t.visit_expression(update)
                    });
                }
                self.leave_scope();
            }
            Statement::ReturnStatement(s) => {
                if let Some(arg) = &s.argument {
                    self.visit_expression(arg);
                }
                self.op(
                    s.span,
                    "return",
                    json!({"value_range":s.argument.as_ref().map(|a|range(a.span()))}),
                );
                self.frontier(s.span, "abrupt-completion-no-cfg");
            }
            Statement::ThrowStatement(s) => {
                self.visit_expression(&s.argument);
                self.op(
                    s.span,
                    "throw",
                    json!({"value_range":range(s.argument.span())}),
                );
                self.frontier(s.span, "exception-flow");
            }
            Statement::BreakStatement(_) | Statement::ContinueStatement(_) => {
                self.op(it.span(), "control", json!({"flow":"unresolved"}));
                self.frontier(it.span(), "abrupt-completion-no-cfg");
            }
            Statement::TryStatement(_) => self.frontier(it.span(), "try-catch-finally-effects"),
            Statement::SwitchStatement(_) => {
                self.frontier(it.span(), "switch-selection-and-fallthrough")
            }
            Statement::WithStatement(_) => self.frontier(it.span(), "dynamic-scope"),
            Statement::ForInStatement(_) | Statement::ForOfStatement(_) => {
                self.frontier(it.span(), "enumeration-or-iterator-effects")
            }
            Statement::ClassDeclaration(_) => {
                self.frontier(it.span(), "class-initialization-effects")
            }
            Statement::LabeledStatement(_) => self.frontier(it.span(), "labeled-control-flow"),
            Statement::ImportDeclaration(_) => {
                self.frontier(it.span(), "module-linking-and-evaluation")
            }
            Statement::ExportAllDeclaration(_) => {
                self.frontier(it.span(), "module-linking-and-evaluation")
            }
            Statement::ExportDefaultDeclaration(e) => {
                self.frontier(it.span(), "module-linking-and-evaluation");
                walk::walk_export_default_declaration(self, e);
            }
            Statement::ExportNamedDeclaration(e) => {
                self.frontier(it.span(), "module-linking-and-evaluation");
                walk::walk_export_named_declaration(self, e);
            }
            _ => walk::walk_statement(self, it),
        }
    }
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !self.available() || !self.analyzed(it.span()) {
            return;
        }
        match it {
            Expression::Identifier(id) => {
                let target = self.target(id);
                self.op(id.span, "reference", json!({"target":target}));
                self.read(id.span, &target);
            }
            Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::StringLiteral(_) => {
                self.op(it.span(), "literal", json!({"identity":"original-bytes"}))
            }
            Expression::ThisExpression(_) => {
                self.op(it.span(),"read",json!({"target":{"kind":"unresolved","binding_ids":[],"resolution":"this-environment"}}));
                self.frontier(it.span(), "this-environment");
            }
            Expression::ParenthesizedExpression(e) => self.visit_expression(&e.expression),
            Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => self.member(it.to_member_expression()),
            Expression::FunctionExpression(f) => self.visit_function(f, ScopeFlags::Function),
            Expression::ArrowFunctionExpression(f) => self.visit_arrow_function_expression(f),
            Expression::CallExpression(c) => {
                if c.optional
                    || matches!(
                        c.callee.get_inner_expression(),
                        Expression::ChainExpression(_)
                    )
                {
                    self.frontier(c.span, "optional-chain-effects");
                } else {
                    self.call(c.span, &c.callee, &c.arguments, false);
                }
            }
            Expression::NewExpression(c) => self.call(c.span, &c.callee, &c.arguments, true),
            Expression::LogicalExpression(e) => {
                self.visit_expression(&e.left);
                self.region(e.right.span(), "short-circuit-right", |t| {
                    t.visit_expression(&e.right)
                });
                self.op(
                    e.span,
                    "operator",
                    json!({"operator":e.operator.as_str(),"conditional":true}),
                );
            }
            Expression::ConditionalExpression(e) => {
                self.visit_expression(&e.test);
                self.region(e.consequent.span(), "conditional-then", |t| {
                    t.visit_expression(&e.consequent)
                });
                self.region(e.alternate.span(), "conditional-else", |t| {
                    t.visit_expression(&e.alternate)
                });
            }
            Expression::SequenceExpression(e) => {
                for e in &e.expressions {
                    self.visit_expression(e);
                }
            }
            Expression::BinaryExpression(e) => {
                self.visit_expression(&e.left);
                self.visit_expression(&e.right);
                self.op(e.span, "operator", json!({"operator":e.operator.as_str()}));
                self.frontier(e.span, "operator-coercion-or-throw");
            }
            Expression::UnaryExpression(e) => {
                if e.operator.as_str() == "delete" {
                    self.frontier(e.span, "delete-reference-effects");
                } else {
                    self.visit_expression(&e.argument);
                    self.op(e.span, "operator", json!({"operator":e.operator.as_str()}));
                    if matches!(e.operator.as_str(), "+" | "-" | "~") {
                        self.frontier(e.span, "operator-coercion-or-throw");
                    }
                }
            }
            Expression::UpdateExpression(e) => {
                if let Some(target) = self.reference(&e.argument, e.span) {
                    self.read(e.argument.span(), &target);
                    self.op(e.span,"operator",json!({"operator":e.operator.as_str(),"value_result":if e.prefix{"new"}else{"old"}}));
                    self.frontier(e.span, "update-numeric-coercion-or-throw");
                    self.write(e.argument.span(),&target,json!({"kind":"update","operator":e.operator.as_str(),"stored_value":"new","expression_result":if e.prefix{"new"}else{"old"}}));
                }
            }
            Expression::AssignmentExpression(e) => {
                if let Some(simple) = e.left.as_simple_assignment_target() {
                    if let Some(target) = self.reference(simple, e.span) {
                        if !e.operator.is_assign() {
                            self.read(e.left.span(), &target);
                        }
                        let assign = |t: &mut Self| {
                            t.visit_expression(&e.right);
                            if !e.operator.is_assign() && !e.operator.is_logical() {
                                t.op(e.span, "operator", json!({"operator":e.operator.as_str()}));
                                t.frontier(e.span, "operator-coercion-or-throw");
                            }
                            t.write(e.left.span(),&target,json!({"kind":"assign","operator":e.operator.as_str(),"value_range":range(e.right.span())}));
                        };
                        if e.operator.is_logical() {
                            self.region(e.span, "short-circuit-right", assign);
                        } else {
                            assign(self);
                        }
                    }
                } else {
                    self.frontier(e.span, "destructuring-assignment-effects");
                }
            }
            Expression::ArrayExpression(e) => {
                for item in &e.elements {
                    match item {
                        ArrayExpressionElement::Elision(_) => {}
                        ArrayExpressionElement::SpreadElement(s) => {
                            self.visit_expression(&s.argument);
                            self.frontier(s.span, "spread-iterator-effects");
                        }
                        _ => self.visit_expression(item.to_expression()),
                    }
                }
                self.op(e.span, "array", json!({}));
            }
            Expression::ObjectExpression(e) => {
                for property in &e.properties {
                    match property {
                        ObjectPropertyKind::SpreadProperty(s) => {
                            self.visit_expression(&s.argument);
                            self.frontier(s.span, "spread-property-getter-or-proxy");
                        }
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if p.computed
                                && let Some(k) = p.key.as_expression()
                            {
                                self.visit_expression(k);
                                self.frontier(k.span(), "property-key-coercion");
                            }
                            self.visit_expression(&p.value);
                        }
                    }
                }
                self.op(e.span, "object", json!({}));
            }
            Expression::TemplateLiteral(e) => {
                for item in &e.expressions {
                    self.visit_expression(item);
                    self.frontier(item.span(), "template-substitution-coercion");
                }
                self.op(
                    e.span,
                    "template",
                    json!({"identity":"original-raw-and-cooked-syntax"}),
                );
            }
            Expression::ChainExpression(_) => self.frontier(it.span(), "optional-chain-effects"),
            Expression::TaggedTemplateExpression(_) => {
                self.frontier(it.span(), "tagged-template-call-effects")
            }
            Expression::AwaitExpression(_) | Expression::YieldExpression(_) => {
                self.frontier(it.span(), "async-or-generator-execution")
            }
            Expression::ClassExpression(_) => {
                self.frontier(it.span(), "class-initialization-effects")
            }
            _ => self.frontier(it.span(), "unsupported-expression-effects"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn facts(source: &str) -> Value {
        analyze(Request {
            operation: "source_facts".into(),
            source: source.into(),
            region: None,
        })
    }
    fn region_facts(source: &str, start: u32, end: u32) -> Value {
        analyze(Request {
            operation: "source_facts".into(),
            source: source.into(),
            region: Some(Region { start, end }),
        })
    }
    fn ops(v: &Value, kind: &str) -> Vec<Value> {
        v["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["kind"] == kind)
            .cloned()
            .collect()
    }
    fn slice<'a>(source: &'a str, v: &Value) -> &'a str {
        &source[v["start"].as_u64().unwrap() as usize..v["end"].as_u64().unwrap() as usize]
    }
    fn reasons(v: &Value) -> Vec<&str> {
        v["coverage"]["frontiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["reason"].as_str().unwrap())
            .collect()
    }
    #[test]
    fn super_assignment_frontiers_cover_omitted_keys_and_rhs() {
        let source = "const o={m(){super.x=rhs(); super.x++; super[key()]+=rhs();}};";
        let out = facts(source);
        assert!(ops(&out, "call").is_empty());
        assert!(
            ops(&out, "write")
                .iter()
                .all(|op| op["detail"]["target"]["kind"] != "property")
        );
        let frontier_texts = out["coverage"]["frontiers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["reason"] == "super-reference-effects")
            .map(|f| slice(source, &f["range"]))
            .collect::<Vec<_>>();
        assert_eq!(
            frontier_texts,
            vec!["super.x=rhs()", "super.x++", "super[key()]+=rhs()"]
        );
    }
    #[test]
    fn super_calls_are_not_ordinary_method_receivers() {
        let out = facts("const o={m(){super.m();}};");
        assert!(ops(&out, "call").is_empty());
        assert!(reasons(&out).contains(&"super-reference-effects"));
    }
    #[test]
    fn duplicate_candidate_lists_are_bounded_before_serializing() {
        let source = format!("{}{}", "var x;".repeat(300), "x;".repeat(300));
        let out = facts(&source);
        assert_eq!(out["coverage"]["truncated"], true);
        assert!(reasons(&out).contains(&"binding-candidate-limit"));
        assert!(ops(&out, "read").iter().all(|o| {
            o["detail"]["target"]["binding_ids"]
                .as_array()
                .unwrap()
                .is_empty()
        }));
        assert!(serde_json::to_vec(&out).unwrap().len() < 400_000);
    }
    #[test]
    fn module_exports_keep_local_callable_facts_without_linking_claims() {
        let out = facts(
            "import input from 'external'; export function f(x){ return x + input; } export default (y) => f(y);",
        );
        assert_eq!(out["ok"], true);
        assert_eq!(out["callables"].as_array().unwrap().len(), 2);
        assert!(
            ops(&out, "read")
                .iter()
                .any(|o| o["detail"]["target"]["name"] == "input"
                    && o["detail"]["target"]["kind"] == "binding")
        );
        assert_eq!(ops(&out, "call").len(), 1);
        assert!(reasons(&out).contains(&"module-linking-and-evaluation"));
    }
    #[test]
    fn implicit_arguments_shadows_outer_bindings_but_arrows_inherit() {
        let out = facts(
            "let arguments=1; function f(){ arguments; return () => arguments; } const a=()=>arguments; function g(arguments){ return arguments; }",
        );
        let reads = ops(&out, "read")
            .into_iter()
            .filter(|o| o["detail"]["target"]["name"] == "arguments")
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 4);
        assert_eq!(
            reads[0]["detail"]["target"]["resolution"],
            "implicit-arguments-environment"
        );
        assert_eq!(
            reads[1]["detail"]["target"]["resolution"],
            "implicit-arguments-environment"
        );
        assert_eq!(reads[2]["detail"]["target"]["binding_ids"][0], 0);
        assert_eq!(reads[3]["detail"]["target"]["kind"], "binding");
    }
    #[test]
    fn resolves_hoisting_shadows_and_closures_without_value_claims() {
        let source =
            "let x = 0; function f(a) { x; var y; { let x = 1; x++; } return () => x + y + a; }";
        let out = facts(source);
        assert_eq!(out["ok"], true);
        let xs = out["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["name"] == "x")
            .collect::<Vec<_>>();
        assert_eq!(xs.len(), 2);
        assert_ne!(xs[0]["scope_id"], xs[1]["scope_id"]);
        let reads = ops(&out, "read")
            .into_iter()
            .filter(|o| o["detail"]["target"]["name"] == "x")
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 3);
        assert_eq!(reads[0]["detail"]["target"]["binding_ids"][0], xs[0]["id"]);
        assert_eq!(reads[1]["detail"]["target"]["binding_ids"][0], xs[1]["id"]);
        assert_eq!(reads[2]["detail"]["target"]["binding_ids"][0], xs[0]["id"]);
        assert_eq!(out["callables"].as_array().unwrap().len(), 2);
        assert!(
            ops(&out, "write")
                .iter()
                .all(|o| slice(source, &o["range"]) != "y")
        );
    }
    #[test]
    fn parameters_names_and_forward_var_refs_have_distinct_identities() {
        let source =
            "var a; function f(a) { y; var y = a; return function inner(a) { return inner(a); }; }";
        let out = facts(source);
        let ys = ops(&out, "read")
            .into_iter()
            .find(|o| o["detail"]["target"]["name"] == "y")
            .unwrap();
        assert_eq!(ys["detail"]["target"]["kind"], "binding");
        let bindings = out["bindings"].as_array().unwrap();
        assert_eq!(bindings.iter().filter(|b| b["name"] == "a").count(), 3);
        let call = ops(&out, "call").pop().unwrap();
        assert_eq!(call["detail"]["target"]["kind"], "binding");
        assert_eq!(call["detail"]["call_target"], "unknown");
    }
    #[test]
    fn duplicate_and_dynamic_environments_remain_unresolved() {
        let duplicate = facts("var x; var x; x;");
        let read = ops(&duplicate, "read").pop().unwrap();
        assert_eq!(read["detail"]["target"]["kind"], "ambiguous");
        assert_eq!(
            read["detail"]["target"]["binding_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        for source in [
            "var x; function f(){ eval(''); x; } x;",
            "var x; with(obj) { x; } x;",
        ] {
            let out = facts(source);
            assert!(reasons(&out).contains(&"dynamic-scope"));
            assert!(
                ops(&out, "read")
                    .iter()
                    .filter(|o| o["detail"]["target"]["name"] == "x")
                    .all(|o| o["detail"]["target"]["kind"] == "unresolved")
            );
        }
        let params = facts("let x; function f(a = x) { var x; return x; }");
        assert!(reasons(&params).contains(&"parameter-default-or-destructuring-effects"));
        assert!(
            ops(&params, "read")
                .iter()
                .filter(|o| o["detail"]["target"]["name"] == "x")
                .all(|o| o["detail"]["target"]["resolution"] == "unsupported-environment")
        );
        let block = facts("if (flag) { function f() {} } f();");
        assert!(reasons(&block).contains(&"unsupported-binding-environment"));
    }
    #[test]
    fn property_assignment_and_postfix_preserve_reference_value_order() {
        let source = "let i = 0; obj[key()] += rhs(); array[i++]; ++i;";
        let out = facts(source);
        let operations = out["operations"].as_array().unwrap();
        let index = |kind: &str, text: &str| {
            operations
                .iter()
                .position(|o| o["kind"] == kind && slice(source, &o["range"]) == text)
                .unwrap()
        };
        assert!(index("read", "obj") < index("call", "key()"));
        assert!(index("call", "key()") < index("read", "obj[key()]"));
        assert!(index("read", "obj[key()]") < index("call", "rhs()"));
        assert!(index("call", "rhs()") < index("write", "obj[key()]"));
        let updates = ops(&out, "write")
            .into_iter()
            .filter(|o| o["detail"]["value"]["kind"] == "update")
            .collect::<Vec<_>>();
        assert_eq!(updates[0]["detail"]["value"]["expression_result"], "old");
        assert_eq!(updates[1]["detail"]["value"]["expression_result"], "new");
        assert!(reasons(&out).contains(&"property-read-getter-proxy-or-throw"));
    }
    #[test]
    fn eager_arguments_are_distinct_from_conditional_regions_and_receivers() {
        let source = "function f(a,b){return a && b;} f(false, mark()); false && mark(); obj.m(); (0,obj.m)(); (obj.m)();";
        let out = facts(source);
        let calls = ops(&out, "call");
        let marks = calls
            .iter()
            .filter(|o| slice(source, &o["range"]) == "mark()")
            .collect::<Vec<_>>();
        assert_eq!(marks.len(), 2);
        let region_kind = |op: &Value| {
            out["regions"][op["region_id"].as_u64().unwrap() as usize]["kind"]
                .as_str()
                .unwrap()
        };
        assert_eq!(region_kind(marks[0]), "eager-argument");
        assert_eq!(region_kind(marks[1]), "short-circuit-right");
        let receiver = |text: &str| {
            calls
                .iter()
                .find(|o| slice(source, &o["range"]) == text)
                .unwrap()["detail"]["receiver"]["kind"]
                .as_str()
                .unwrap()
        };
        assert_eq!(receiver("obj.m()"), "method");
        assert_eq!(receiver("(0,obj.m)()"), "detached");
        assert_eq!(receiver("(obj.m)()"), "method");
    }
    #[test]
    fn logical_assignment_write_is_conditional_and_for_update_repeats() {
        let out = facts("let x; x &&= rhs(); for (let i=0; i<3; i++) { x=i; continue; }");
        let writes = ops(&out, "write");
        let assignment = writes
            .iter()
            .find(|o| o["detail"]["value"]["operator"] == "&&=")
            .unwrap();
        assert_eq!(
            out["regions"][assignment["region_id"].as_u64().unwrap() as usize]["kind"],
            "short-circuit-right"
        );
        for kind in ["repeated-test", "repeated-body", "repeated-update"] {
            assert!(
                out["regions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["kind"] == kind)
            );
        }
        assert!(reasons(&out).contains(&"abrupt-completion-no-cfg"));
    }
    #[test]
    fn unsupported_constructs_are_frontiers_not_eager_facts() {
        let out = facts(
            "let x; obj?.[side()]?.(arg()); try { x=1; } finally { x=2; } async function f(){await g();} function* h(){yield 1;} const a = tag`raw`; for (x of xs) run(x);",
        );
        for reason in [
            "optional-chain-effects",
            "try-catch-finally-effects",
            "async-or-generator-execution",
            "tagged-template-call-effects",
            "enumeration-or-iterator-effects",
        ] {
            assert!(reasons(&out).contains(&reason), "{reason}");
        }
        assert!(ops(&out, "call").is_empty());
        assert_eq!(out["coverage"]["status"], "partial");
    }
    #[test]
    fn comments_regex_and_template_text_are_inert_with_utf8_ranges() {
        let source = "// function fake(){eval('x')}\nconst 雪='😀'; const regex=/call\\(vm\\)/; const value=`eval('fake') ${雪}`; function 真(参){ return 参; }";
        let out = facts(source);
        assert_eq!(out["ok"], true);
        assert_eq!(out["callables"].as_array().unwrap().len(), 1);
        assert!(ops(&out, "call").is_empty());
        for key in ["scopes", "bindings", "callables", "regions", "operations"] {
            for fact in out[key].as_array().unwrap() {
                let r = &fact["range"];
                let start = r["start"].as_u64().unwrap() as usize;
                let end = r["end"].as_u64().unwrap() as usize;
                assert!(
                    start <= end
                        && end <= source.len()
                        && source.is_char_boundary(start)
                        && source.is_char_boundary(end)
                );
            }
        }
        assert_eq!(
            ops(&out, "read")
                .iter()
                .filter(|o| o["detail"]["target"]["name"] == "雪")
                .count(),
            1
        );
    }
    /// A minified bundle shape: one glue IIFE whose declarations alone exhaust
    /// the fact budget, with one named callable to select inside it.
    fn bundle() -> String {
        let mut glue = String::new();
        for i in 0..4200 {
            glue.push_str(&format!("function pad{i}(){{var p{i}=1;return p{i};}}"));
        }
        format!(
            "(function(){{var shared=1;{glue}function target(seed){{var local=seed+shared;return local;}}}})();"
        )
    }
    #[test]
    fn region_scope_produces_callable_facts_where_the_whole_bundle_produces_none() {
        let source = bundle();
        let whole = facts(&source);
        assert_eq!(whole["coverage"]["status"], "partial");
        assert_eq!(whole["coverage"]["truncated"], true);
        assert_eq!(
            whole["coverage"]["diagnostics"],
            json!([
                "declaration budget exceeded; no lexical resolutions produced",
                NARROW
            ])
        );
        assert_eq!(
            whole["coverage"]["analyzed_range"],
            json!({"start":0,"end":source.len()})
        );
        for table in ["scopes", "bindings", "callables", "regions", "operations"] {
            assert!(whole[table].as_array().unwrap().is_empty());
        }

        let cursor = source.find("var local").unwrap() as u32;
        let out = region_facts(&source, cursor, cursor);
        assert_eq!(out["ok"], true);
        assert_eq!(out["coverage"]["status"], "partial");
        // Scoping is not budget loss.
        assert_eq!(out["coverage"]["truncated"], false);
        assert!(
            out["coverage"]["diagnostics"]
                .as_array()
                .unwrap()
                .contains(&json!(SCOPED))
        );
        let analyzed = slice(&source, &out["coverage"]["analyzed_range"]);
        assert_eq!(analyzed, "{var local=seed+shared;return local;}");
        assert!(reasons(&out).contains(&"outside-analyzed-region"));
        let names = out["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"local") && names.contains(&"seed"));
        assert!(!names.iter().any(|name| name.starts_with("pad")));
        let resolutions = |name: &str| {
            ops(&out, "read")
                .iter()
                .filter(|o| o["detail"]["target"]["name"] == name)
                .map(|o| {
                    o["detail"]["target"]["resolution"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>()
        };
        // The selected body owns a closed table, so its own names resolve.
        assert_eq!(resolutions("seed"), vec!["lexical-only"]);
        assert_eq!(resolutions("local"), vec!["lexical-only"]);
        // `shared` is declared in the skipped part of the glue scope.
        assert_eq!(resolutions("shared"), vec!["outside-analyzed-region"]);
        // Every emitted region or operation nests with the analysis unit: it is
        // either inside it or one of the enclosing nodes that reaches it. A
        // skipped sibling can never contribute one.
        let bounds = |row: &Value| (row["start"].as_u64().unwrap(), row["end"].as_u64().unwrap());
        let unit = bounds(&out["coverage"]["analyzed_range"]);
        let nested = |row: &Value| {
            let range = bounds(&row["range"]);
            (range.0 >= unit.0 && range.1 <= unit.1) || (range.0 <= unit.0 && range.1 >= unit.1)
        };
        assert!(
            out["operations"]
                .as_array()
                .unwrap()
                .iter()
                .chain(out["regions"].as_array().unwrap())
                .all(nested)
        );
    }
    /// Dense minified glue at real minifier density, large enough that the
    /// preflight node bound refused it outright before that bound was derived
    /// from the source byte cap. The point of this fixture is admission, not
    /// the fact budget: `bundle()` above already covers the declaration budget.
    fn dense_bundle() -> String {
        let mut glue = String::new();
        let mut index = 0usize;
        while glue.len() < 600 * 1024 {
            glue.push_str(&format!(
                "function p{index}(a,b){{var c=(a|0)+(b>>>2),d=a?b:c;\
                 return c>3?(a+b)*c-d:({{k:a,v:[b,c,a&b]}}).v[(c%3)|0];}}"
            ));
            index += 1;
        }
        format!(
            "(function(){{var shared=1;{glue}\
             function target(seed){{var local=seed+shared;return local;}}}})();"
        )
    }

    #[test]
    fn a_dense_minified_bundle_is_admitted_and_still_reports_what_it_covered() {
        let source = dense_bundle();
        let whole = facts(&source);
        // Before the preflight node bound was derived from the byte cap this
        // was `unavailable` with "JavaScript preflight exceeded its complexity
        // budget": no analysis budget was ever consulted, and no region could
        // be requested either, because admission is shared by both paths.
        assert_eq!(whole["ok"], true);
        assert_ne!(whole["coverage"]["status"], "unavailable");
        // Admission is not coverage. A bundle this size still reaches a whole
        // program budget and still refuses to resolve anything against the
        // incomplete table, naming the narrower request that can answer.
        assert_eq!(whole["coverage"]["status"], "partial");
        assert_eq!(whole["coverage"]["truncated"], true);
        assert_eq!(
            whole["coverage"]["diagnostics"],
            json!([
                "AST node budget exceeded; no lexical resolutions produced",
                NARROW
            ])
        );
        for table in ["scopes", "bindings", "callables", "regions", "operations"] {
            assert!(whole[table].as_array().unwrap().is_empty());
        }
        assert_eq!(
            whole["limits"]["preflight_nodes"],
            json!(crate::preflight::MAX_TREE_NODES)
        );

        // What admission buys: the region path now reaches these bytes.
        let cursor = source.find("var local").unwrap() as u32;
        let out = region_facts(&source, cursor, cursor);
        assert_eq!(out["ok"], true);
        assert_eq!(out["coverage"]["status"], "partial");
        assert_eq!(out["coverage"]["truncated"], false);
        assert_eq!(
            slice(&source, &out["coverage"]["analyzed_range"]),
            "{var local=seed+shared;return local;}"
        );
        let names = out["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"local") && names.contains(&"seed"));
        assert!(!names.iter().any(|name| name.starts_with('p')));
        // The glue's own declarations stay unknown rather than guessed at.
        assert!(reasons(&out).contains(&"outside-analyzed-region"));
    }

    #[test]
    fn a_region_whose_callable_still_exceeds_a_budget_fails_closed() {
        let source = bundle();
        let cursor = source.find("var shared").unwrap() as u32;
        let out = region_facts(&source, cursor, cursor);
        assert_eq!(out["coverage"]["status"], "partial");
        assert_eq!(out["coverage"]["truncated"], true);
        assert_eq!(
            out["coverage"]["diagnostics"],
            json!([
                "declaration budget exceeded; no lexical resolutions produced",
                SCOPED
            ])
        );
        // The analysis unit is reported even when it produced nothing.
        assert!(slice(&source, &out["coverage"]["analyzed_range"]).starts_with("{var shared=1;"));
        for table in ["scopes", "bindings", "callables", "regions", "operations"] {
            assert!(out[table].as_array().unwrap().is_empty());
        }
    }
    #[test]
    fn an_open_declaration_table_never_resolves_or_looks_external() {
        let source = "var outer=1; function target(p){ return p + outer + globalThis; }";
        let cursor = source.find("outer +").unwrap() as u32;
        let out = region_facts(source, cursor, cursor);
        let target = |name: &str| {
            ops(&out, "read")
                .iter()
                .find(|o| o["detail"]["target"]["name"] == name)
                .unwrap()["detail"]["target"]
                .clone()
        };
        assert_eq!(target("p")["kind"], "binding");
        assert_eq!(target("p")["resolution"], "lexical-only");
        assert_eq!(target("outer")["kind"], "unresolved");
        assert_eq!(target("outer")["resolution"], "outside-analyzed-region");
        // An unanalyzed sibling could declare any name, so a miss in an open
        // scope is not reported as an external or implicit global either.
        assert_eq!(
            target("globalThis")["resolution"],
            "outside-analyzed-region"
        );
        assert!(
            out["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|b| b["name"] != "outer")
        );
        let frontiers = out["coverage"]["frontiers"].as_array().unwrap().clone();
        let outside = frontiers
            .iter()
            .filter(|f| f["reason"] == "outside-analyzed-region")
            .map(|f| slice(source, &f["range"]))
            .collect::<Vec<_>>();
        // The skipped prefix is one frontier; the selected body reaches the end
        // of the source, so there is no suffix frontier to report.
        assert_eq!(
            outside,
            vec!["var outer=1; function target(p)", "outer", "globalThis"]
        );
        // Unscoped, the same bytes keep the stronger distinction: a closed table
        // resolves `outer` and names the remaining global as external.
        let whole = facts(source);
        let resolution = |out: &Value, name: &str| {
            ops(out, "read")
                .iter()
                .find(|o| o["detail"]["target"]["name"] == name)
                .unwrap()["detail"]["target"]["resolution"]
                .clone()
        };
        assert_eq!(resolution(&whole, "outer"), "lexical-only");
        assert_eq!(resolution(&whole, "globalThis"), "external-or-implicit");
        assert_eq!(
            whole["coverage"]["analyzed_range"],
            json!({"start":0,"end":source.len()})
        );
    }
    #[test]
    fn selecting_one_method_skips_its_siblings_in_the_same_class() {
        // A class body is not a statement or expression position, so callables
        // are gated there too; otherwise an enclosing class would contribute
        // every sibling method's declarations to a selected method's report.
        let source = "class C { chosen(a){ return a; } other(b){ return b; } }";
        let cursor = source.find("return a").unwrap() as u32;
        let out = region_facts(source, cursor, cursor);
        assert_eq!(
            slice(source, &out["coverage"]["analyzed_range"]),
            "{ return a; }"
        );
        assert_eq!(
            out["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["C", "a"]
        );
        let callables = out["callables"].as_array().unwrap();
        assert_eq!(callables.len(), 1);
        assert_eq!(slice(source, &callables[0]["body_range"]), "{ return a; }");
        // Class evaluation stays the frontier it already was.
        assert!(reasons(&out).contains(&"class-initialization-effects"));
    }
    #[test]
    fn a_region_outside_every_callable_analyzes_the_whole_program() {
        let source = "var a=1; a;";
        let out = region_facts(source, 0, 1);
        assert_eq!(out["coverage"]["status"], "complete");
        assert_eq!(out["coverage"]["diagnostics"], json!([]));
        assert_eq!(
            out["coverage"]["analyzed_range"],
            json!({"start":0,"end":source.len()})
        );
        assert_eq!(
            ops(&out, "read")[0]["detail"]["target"]["resolution"],
            "lexical-only"
        );
        assert_eq!(out, facts(source));
    }
    #[test]
    fn every_cursor_offset_keeps_one_consistent_report() {
        // Region selection and the three pruned traversals index the same span
        // maps. Sweeping every admissible cursor over awkward syntax proves they
        // cannot disagree about which nodes a report contains.
        for source in [
            "class C { m(a){ try { return a; } catch (e) { return e; } } }",
            "var a=1; function f(b){ return (c) => { for (var d of [b,c]) a+=d; return a; }; } f(a)(2);",
            "const o={m(){return this.x;},get g(){return 1;}}; async function* h(){ yield o.m(); }",
            "var x; with(obj) { x; } function g(){ eval(''); return x; } g();",
            "let 雪 = () => { const t = `${雪}`; return t?.length; };",
        ] {
            for cursor in 0..=source.len() {
                if !source.is_char_boundary(cursor) {
                    continue;
                }
                let out = region_facts(source, cursor as u32, cursor as u32);
                assert_eq!(out["ok"], true, "{source} at {cursor}");
                let unit = &out["coverage"]["analyzed_range"];
                let (start, end) = (
                    unit["start"].as_u64().unwrap(),
                    unit["end"].as_u64().unwrap(),
                );
                assert!(start <= cursor as u64 && end >= cursor as u64);
                assert!(end <= source.len() as u64);
                assert!(source.is_char_boundary(start as usize));
                assert!(source.is_char_boundary(end as usize));
                if (start, end) != (0, source.len() as u64) {
                    assert_ne!(out["coverage"]["status"], "complete");
                }
                // Enclosing structure that reaches the unit keeps its own facts,
                // so a fact range outside the unit is expected. Ownership is
                // what must hold: a region is inside its parent and an
                // operation is inside the region that owns it.
                let regions = out["regions"].as_array().unwrap();
                let bounds =
                    |row: &Value| (row["start"].as_u64().unwrap(), row["end"].as_u64().unwrap());
                for (index, region) in regions.iter().enumerate() {
                    let range = bounds(&region["range"]);
                    match region["parent_id"].as_u64() {
                        None => assert_eq!(range, (0, source.len() as u64)),
                        Some(parent) => {
                            assert!((parent as usize) < index, "{source} at {cursor}");
                            let outer = bounds(&regions[parent as usize]["range"]);
                            assert!(
                                outer.0 <= range.0 && outer.1 >= range.1,
                                "{source} at {cursor}"
                            );
                        }
                    }
                }
                for operation in out["operations"].as_array().unwrap() {
                    let owner = operation["region_id"].as_u64().unwrap() as usize;
                    let outer = bounds(&regions[owner]["range"]);
                    let range = bounds(&operation["range"]);
                    assert!(
                        outer.0 <= range.0 && outer.1 >= range.1,
                        "{source} at {cursor}"
                    );
                }
                // A narrower unit is one real callable body in these facts. Its
                // effect region can still be absent, because a class or an
                // async body is a declared frontier in this profile.
                if (start, end) != (0, source.len() as u64) {
                    assert_eq!(
                        out["callables"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|callable| bounds(&callable["body_range"]) == (start, end))
                            .count(),
                        1,
                        "{source} at {cursor}"
                    );
                }
            }
        }
    }
    #[test]
    fn a_region_is_admitted_only_as_an_original_byte_range() {
        let source = "let 雪=1; function f(){ return 雪; }";
        for (start, end) in [(6, 2), (0, 99), (5, 6), (4, 5)] {
            let out = region_facts(source, start, end);
            assert_eq!(out["coverage"]["status"], "unavailable");
            assert_eq!(out["ok"], false);
            assert_eq!(
                out["coverage"]["diagnostics"],
                json!(["requested region is not an original byte range"])
            );
        }
        let inside = source.find("return").unwrap() as u32;
        let out = region_facts(source, inside, inside + 6);
        assert_eq!(out["ok"], true);
        assert_eq!(
            slice(source, &out["coverage"]["analyzed_range"]),
            "{ return 雪; }"
        );
    }
    #[test]
    fn parser_and_output_limits_fail_closed_and_are_deterministic() {
        assert_eq!(facts("let = ;")["coverage"]["status"], "unavailable");
        let oversized = facts(&" ".repeat(crate::MAX_SOURCE_BYTES + 1));
        assert_eq!(oversized["source_bytes"], crate::MAX_SOURCE_BYTES + 1);
        assert_eq!(oversized["coverage"]["status"], "unavailable");
        assert_eq!(facts(&format!("{}0", "!".repeat(129)))["ok"], false);
        // Two Oxc nodes per statement exceeds the node budget while staying
        // inside the preflight's own tree-sitter node bound.
        let too_large = facts(&"0;".repeat(MAX_AST_NODES / 2 + 16));
        assert_eq!(too_large["coverage"]["truncated"], true);
        assert_eq!(
            too_large["coverage"]["diagnostics"],
            json!([
                "AST node budget exceeded; no lexical resolutions produced",
                NARROW
            ])
        );
        assert!(too_large["bindings"].as_array().unwrap().is_empty());
        let source = "let x=0; x++;".repeat(1500);
        let out = facts(&source);
        let total = ["scopes", "bindings", "callables", "regions", "operations"]
            .into_iter()
            .map(|k| out[k].as_array().unwrap().len())
            .sum::<usize>();
        assert!(total <= MAX_FACTS);
        assert!(out["coverage"]["frontiers"].as_array().unwrap().len() <= MAX_FRONTIERS);
        assert_eq!(out["coverage"]["truncated"], true);
        let small = "let a=1; function f(x){return x+a;} f(a);";
        assert_eq!(facts(small), facts(small));
        // The parse heap ceiling is shared, so it reaches this operation too,
        // and the limit it decided by is the one reported. Nested sequence
        // expressions are the shape that used to be paid for in full and only
        // then refused.
        let mut nested = "(a,".repeat(196_608);
        nested.push('a');
        nested.push_str(&")".repeat(196_608));
        nested.push(';');
        let refused = facts(&nested);
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["coverage"]["status"], "unavailable");
        assert_eq!(
            refused["coverage"]["diagnostics"],
            json!(["JavaScript preflight exceeded its parse memory budget"])
        );
        assert_eq!(
            refused["limits"]["preflight_parse_heap_bytes"],
            json!(crate::preflight::MAX_PARSE_HEAP_BYTES)
        );
    }
    #[test]
    fn rejected_source_facts_do_not_desynchronize_the_worker() {
        let requests = [
            json!({"operation":"source_facts","source":"let x=;"}),
            json!({"operation":"source_facts","source":"let 雪=1; 雪++;"}),
            json!({"source":"const n=1+2;"}),
        ];
        let input = requests
            .into_iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        crate::serve(&mut std::io::Cursor::new(input), &mut output).unwrap();
        let rows = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str::<Value>(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["ok"], false);
        assert_eq!(rows[1]["ok"], true);
        assert_eq!(rows[2]["ok"], true);
        assert_eq!(rows[2]["schema"], "reb-deobfuscator-worker-v1");
    }
}
