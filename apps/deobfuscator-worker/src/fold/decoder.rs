//! Bounded interpretation of closed decoder bodies. No calls into a JS runtime.
use super::{Folder, MAX_DEPTH, MAX_STEPS, Value, int32};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_syntax::operator::{AssignmentOperator as A, UpdateOperator};
use std::collections::HashSet;

enum Flow {
    Next,
    Break,
    Continue,
    Return(Value),
}

impl Folder<'_> {
    pub(super) fn decoder(&mut self, body: &str, depth: usize) -> Option<Value> {
        let source = format!("function __decoder(){body}");
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, &source, SourceType::unambiguous()).parse();
        if !parsed.diagnostics.is_empty() {
            return None;
        }
        let Statement::FunctionDeclaration(function) = parsed.program.body.first()? else {
            return None;
        };
        let body = function.body.as_ref()?;
        let mut locals = Locals::default();
        locals.visit_function_body(body);
        if locals.invalid || locals.names.len() + self.constants.len() > 64 {
            return None;
        }
        for name in locals.names {
            self.constants.entry(name).or_insert(Value::Undefined);
        }
        for statement in &body.statements {
            match self.statement(statement, depth)? {
                Flow::Return(value) => return Some(value),
                Flow::Next => (),
                _ => return None,
            }
        }
        Some(Value::Undefined)
    }

    fn statement(&mut self, statement: &Statement<'_>, depth: usize) -> Option<Flow> {
        if depth >= MAX_DEPTH || self.steps >= MAX_STEPS {
            self.truncated = true;
            return None;
        }
        self.steps += 1;
        let next = depth + 1;
        match statement {
            Statement::VariableDeclaration(declaration) => self.declaration(declaration, next)?,
            Statement::ExpressionStatement(s) => self.effect(&s.expression, next)?,
            Statement::ReturnStatement(s) => {
                return Some(Flow::Return(match &s.argument {
                    Some(e) => self.eval(e, next)?,
                    None => Value::Undefined,
                }));
            }
            Statement::BlockStatement(block) => {
                for statement in &block.body {
                    if let result @ (Flow::Return(_) | Flow::Break | Flow::Continue) =
                        self.statement(statement, next)?
                    {
                        return Some(result);
                    }
                }
            }
            Statement::IfStatement(s) => {
                if self.eval(&s.test, next)?.truthy() {
                    return self.statement(&s.consequent, next);
                }
                if let Some(alternate) = &s.alternate {
                    return self.statement(alternate, next);
                }
            }
            Statement::ForStatement(s) => {
                if let Some(init) = &s.init {
                    match init {
                        ForStatementInit::VariableDeclaration(d) => self.declaration(d, next)?,
                        init => self.effect(init.as_expression()?, next)?,
                    }
                }
                for _ in 0..4096 {
                    if let Some(test) = &s.test {
                        if !self.eval(test, next)?.truthy() {
                            return Some(Flow::Next);
                        }
                    }
                    match self.statement(&s.body, next)? {
                        result @ Flow::Return(_) => return Some(result),
                        Flow::Break => return Some(Flow::Next),
                        Flow::Next | Flow::Continue => (),
                    }
                    if let Some(update) = &s.update {
                        self.effect(update, next)?;
                    }
                }
                self.truncated = true;
                return None;
            }
            Statement::BreakStatement(s) if s.label.is_none() => return Some(Flow::Break),
            Statement::ContinueStatement(s) if s.label.is_none() => return Some(Flow::Continue),
            Statement::WhileStatement(s) => {
                for _ in 0..4096 {
                    if !self.eval(&s.test, next)?.truthy() {
                        return Some(Flow::Next);
                    }
                    match self.statement(&s.body, next)? {
                        result @ Flow::Return(_) => return Some(result),
                        Flow::Break => return Some(Flow::Next),
                        Flow::Next | Flow::Continue => (),
                    }
                }
                self.truncated = true;
                return None;
            }
            Statement::DoWhileStatement(s) => {
                for _ in 0..4096 {
                    match self.statement(&s.body, next)? {
                        result @ Flow::Return(_) => return Some(result),
                        Flow::Break => return Some(Flow::Next),
                        Flow::Next | Flow::Continue => (),
                    }
                    if !self.eval(&s.test, next)?.truthy() {
                        return Some(Flow::Next);
                    }
                }
                self.truncated = true;
                return None;
            }
            Statement::SwitchStatement(s) => {
                let value = self.eval(&s.discriminant, next)?;
                if !value.is_primitive() {
                    return None;
                }
                let mut start = None;
                for (index, case) in s.cases.iter().enumerate() {
                    if let Some(test) = &case.test {
                        let test = self.eval(test, next)?;
                        if !test.is_primitive() {
                            return None;
                        }
                        if value == test {
                            start = Some(index);
                            break;
                        }
                    } else {
                        start = Some(index);
                    }
                }
                if let Some(start) = start {
                    for case in s.cases.iter().skip(start) {
                        for statement in &case.consequent {
                            match self.statement(statement, next)? {
                                Flow::Break => return Some(Flow::Next),
                                Flow::Next => (),
                                result => return Some(result),
                            }
                        }
                    }
                }
            }
            Statement::EmptyStatement(_) => (),
            _ => return None,
        }
        Some(Flow::Next)
    }

    fn declaration(&mut self, declaration: &VariableDeclaration<'_>, depth: usize) -> Option<()> {
        if declaration.kind != VariableDeclarationKind::Var {
            return None;
        }
        for d in &declaration.declarations {
            let BindingPattern::BindingIdentifier(id) = &d.id else {
                return None;
            };
            if let Some(init) = &d.init {
                let value = self.eval(init, depth)?;
                self.constants.insert(id.name.to_string(), value);
            }
        }
        Some(())
    }

    fn effect(&mut self, expression: &Expression<'_>, depth: usize) -> Option<()> {
        self.eval(expression, depth).map(|_| ())
    }

    pub(super) fn local_effect(
        &mut self,
        expression: &Expression<'_>,
        depth: usize,
    ) -> Option<Value> {
        match expression {
            Expression::AssignmentExpression(e) => {
                let AssignmentTarget::AssignmentTargetIdentifier(id) = &e.left else {
                    return None;
                };
                let old = self.constants.get(id.name.as_str())?.clone();
                let value = self.eval(&e.right, depth)?;
                let result = match e.operator {
                    A::Assign => value,
                    A::Addition => match old.add(&value) {
                        Some(value) => value,
                        None => {
                            self.truncated = true;
                            return None;
                        }
                    },
                    A::Subtraction => Value::Number(old.number()? - value.number()?),
                    A::BitwiseXOR => {
                        Value::Number(f64::from(int32(old.number()?) ^ int32(value.number()?)))
                    }
                    A::BitwiseOR => {
                        Value::Number(f64::from(int32(old.number()?) | int32(value.number()?)))
                    }
                    _ => return None,
                };
                if matches!(&result, Value::Number(n) if !n.is_finite()) {
                    return None;
                }
                self.constants.insert(id.name.to_string(), result.clone());
                Some(result)
            }
            Expression::UpdateExpression(e) => {
                let SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = &e.argument else {
                    return None;
                };
                let n = self.constants.get(id.name.as_str())?.number()?;
                let old = n;
                let n = n + if e.operator == UpdateOperator::Increment {
                    1.0
                } else {
                    -1.0
                };
                if !n.is_finite() {
                    return None;
                }
                self.constants.insert(id.name.to_string(), Value::Number(n));
                Some(Value::Number(if e.prefix { n } else { old }))
            }
            Expression::SequenceExpression(e) => {
                let mut result = Value::Undefined;
                for expression in &e.expressions {
                    result = self.eval(expression, depth)?;
                }
                Some(result)
            }
            _ => None,
        }
    }

    pub(super) fn intrinsic(&mut self, call: &CallExpression<'_>, depth: usize) -> Option<Value> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        let from_char_code = matches!(&member.object, Expression::Identifier(id) if id.name == "String")
            && !self.constants.contains_key("String")
            && member.property.name == "fromCharCode";
        // Evaluate the receiver before arguments, including local updates.
        let receiver = if from_char_code {
            None
        } else {
            Some(self.eval(&member.object, depth)?)
        };
        let mut args = Vec::new();
        if call.arguments.len() > 256 {
            return None;
        }
        for argument in &call.arguments {
            args.push(self.eval(argument.as_expression()?, depth)?);
        }
        if from_char_code {
            let units: Option<Vec<_>> = args
                .iter()
                .map(|v| Some(int32(v.number()?) as u16))
                .collect();
            return Some(Value::String(String::from_utf16(&units?).ok()?));
        }
        let Value::String(text) = receiver? else {
            return None;
        };
        match member.property.name.as_str() {
            "charCodeAt" | "charAt" if args.len() == 1 => {
                let index = args[0].number()?;
                if index < 0.0 || index.fract() != 0.0 {
                    return None;
                }
                let unit = text.encode_utf16().nth(index as usize);
                if member.property.name == "charAt" {
                    return Some(Value::String(match unit {
                        None => String::new(),
                        Some(unit) => char::from_u32(u32::from(unit))?.to_string(),
                    }));
                }
                Some(Value::Number(f64::from(unit?)))
            }
            "split" if args.len() == 1 => {
                let Value::String(separator) = &args[0] else {
                    return None;
                };
                let parts: Vec<String> = if separator.is_empty() {
                    text.encode_utf16()
                        .take(257)
                        .map(|unit| char::from_u32(u32::from(unit)).map(|c| c.to_string()))
                        .collect::<Option<Vec<_>>>()?
                } else {
                    text.split(separator)
                        .take(257)
                        .map(str::to_string)
                        .collect()
                };
                if parts.len() > 256 {
                    self.truncated = true;
                    return None;
                }
                Some(Value::Array(
                    parts.into_iter().map(|s| Some(Value::String(s))).collect(),
                ))
            }
            "indexOf" if args.len() == 1 => {
                let Value::String(needle) = &args[0] else {
                    return None;
                };
                Some(Value::Number(text.find(needle).map_or(-1.0, |offset| {
                    text[..offset].encode_utf16().count() as f64
                })))
            }
            _ => None,
        }
    }
}

#[derive(Default)]
struct Locals {
    names: HashSet<String>,
    invalid: bool,
}
impl<'a> Visit<'a> for Locals {
    fn visit_variable_declaration(&mut self, d: &VariableDeclaration<'a>) {
        if d.kind != VariableDeclarationKind::Var {
            self.invalid = true;
        }
        for declaration in &d.declarations {
            if let BindingPattern::BindingIdentifier(id) = &declaration.id {
                self.names.insert(id.name.to_string());
            } else {
                self.invalid = true;
            }
        }
        walk::walk_variable_declaration(self, d);
    }
    fn visit_function(&mut self, _: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
        self.invalid = true;
    }
    fn visit_class(&mut self, _: &Class<'a>) {
        // Class bindings introduce lexical scope and temporal dead zones, even
        // when execution returns before reaching the declaration.
        self.invalid = true;
    }
    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {
        self.invalid = true;
    }
}
