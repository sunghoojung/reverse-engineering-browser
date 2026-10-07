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

const MAX_AST_NODES: usize = 32_768;
const MAX_FACTS: usize = 16_384;
const MAX_FRONTIERS: usize = 256;
const MAX_BINDING_CANDIDATES: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: String,
    pub source: String,
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
        "coverage":{"status":"complete","truncated":false,"diagnostics":[],"frontiers":[]},
        "limits":{"max_source_bytes":crate::MAX_SOURCE_BYTES,"max_ast_nodes":MAX_AST_NODES,
        "max_facts":MAX_FACTS,"max_frontiers":MAX_FRONTIERS,"max_binding_candidates":MAX_BINDING_CANDIDATES,"preflight_depth":128,"preflight_nodes":500000}})
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
    let mut out = response(source.len());
    let mut count = Count(0);
    count.visit_program(&parsed.program);
    if count.0 > MAX_AST_NODES {
        out["coverage"] = json!({"status":"partial","truncated":true,
            "diagnostics":["AST node budget exceeded; no lexical resolutions produced"],"frontiers":[]});
        return out;
    }
    let mut declarations = Declarations::default();
    declarations.visit_program(&parsed.program);
    let base =
        declarations.scopes.len() + declarations.bindings.len() + declarations.callables.len();
    if base >= MAX_FACTS {
        out["coverage"] = json!({"status":"partial","truncated":true,
            "diagnostics":["declaration budget exceeded; no lexical resolutions produced"],"frontiers":[]});
        return out;
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
    out["coverage"] = json!({"status":if effects.frontiers.is_empty() && !effects.truncated {"complete"} else {"partial"},
        "truncated":effects.truncated,"diagnostics":if effects.truncated {vec!["fact or frontier budget exceeded; omitted syntax remains unknown"]} else {vec![]},
        "frontiers":effects.frontiers});
    out
}
struct Count(usize);
impl<'a> Visit<'a> for Count {
    fn enter_node(&mut self, _: AstKind<'a>) {
        self.0 += 1;
    }
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.0 <= MAX_AST_NODES {
            walk::walk_expression(self, it);
        }
    }
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.0 <= MAX_AST_NODES {
            walk::walk_statement(self, it);
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
        if !self.available() {
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
        if !self.available() {
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
        if !self.available() {
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
        if !self.available() {
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
    #[test]
    fn parser_and_output_limits_fail_closed_and_are_deterministic() {
        assert_eq!(facts("let = ;")["coverage"]["status"], "unavailable");
        let oversized = facts(&" ".repeat(crate::MAX_SOURCE_BYTES + 1));
        assert_eq!(oversized["source_bytes"], crate::MAX_SOURCE_BYTES + 1);
        assert_eq!(oversized["coverage"]["status"], "unavailable");
        assert_eq!(facts(&format!("{}0", "!".repeat(129)))["ok"], false);
        let too_large = facts(&";".repeat(MAX_AST_NODES + 1));
        assert_eq!(too_large["coverage"]["truncated"], true);
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
