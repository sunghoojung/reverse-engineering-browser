//! Closed, bounded abstract evaluation. Never call JavaScript or object coercion hooks.
use std::collections::{HashMap, HashSet};

use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, Span};
use oxc_syntax::operator::{BinaryOperator as B, LogicalOperator as L, UnaryOperator as U};

use crate::{MAX_TRANSFORMATIONS, Transformation};

const MAX_DEPTH: usize = 64;
const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_STEPS: usize = 250_000;
const MAX_REPLACEMENT_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Number(f64),
    String(String),
    Bool(bool),
    Null,
    Undefined,
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Self::Number(n) => *n != 0.0 && !n.is_nan(),
            Self::String(s) => !s.is_empty(),
            Self::Bool(b) => *b,
            Self::Null | Self::Undefined => false,
        }
    }
    fn number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Bool(b) => Some(f64::from(u8::from(*b))),
            Self::Null => Some(0.0),
            // StringNumericLiteral has different rules from Rust's float parser.
            // Leave it unresolved rather than accepting a subtly different grammar.
            _ => None,
        }
    }
    fn code(&self) -> String {
        match self {
            Self::Number(n) if *n == 0.0 && n.is_sign_negative() => "-0".into(),
            Self::Number(n) => n.to_string(),
            Self::String(s) => serde_json::to_string(s).unwrap(),
            Self::Bool(b) => b.to_string(),
            Self::Null => "null".into(),
            Self::Undefined => "void 0".into(),
        }
    }
}

fn int32(n: f64) -> i32 {
    if !n.is_finite() || n == 0.0 {
        return 0;
    }
    n.trunc().rem_euclid(4294967296.0) as u32 as i32
}

pub struct Folder<'s> {
    source: &'s str,
    pub rewrites: Vec<Transformation>,
    pub truncated: bool,
    steps: usize,
    // Only preceding primitive const bindings in the SAME straight-line list.
    // Nested execution/scope boundaries never inherit these bindings.
    constants: HashMap<String, Value>,
    tables: HashMap<String, Vec<Value>>,
    table_uses: TableUses,
    replacement_bytes: usize,
    list_depth: usize,
}

impl<'s> Folder<'s> {
    pub fn new(source: &'s str, program: &Program<'_>) -> Self {
        let mut table_uses = TableUses::default();
        table_uses.visit_program(program);
        Self {
            source,
            rewrites: vec![],
            truncated: false,
            steps: 0,
            constants: HashMap::new(),
            tables: HashMap::new(),
            table_uses,
            replacement_bytes: 0,
            list_depth: 0,
        }
    }
    fn eval(&mut self, expression: &Expression<'_>, depth: usize) -> Option<Value> {
        if depth >= MAX_DEPTH || self.steps >= MAX_STEPS {
            self.truncated = true;
            return None;
        }
        self.steps += 1;
        let next = depth + 1;
        let value = match expression {
            Expression::ParenthesizedExpression(e) => self.eval(&e.expression, next)?,
            Expression::NumericLiteral(n) => Value::Number(n.value),
            Expression::StringLiteral(s)
                if !s.lone_surrogates && s.value.len() <= MAX_VALUE_BYTES =>
            {
                Value::String(s.value.to_string())
            }
            Expression::BooleanLiteral(b) => Value::Bool(b.value),
            Expression::NullLiteral(_) => Value::Null,
            Expression::Identifier(id) => self.constants.get(id.name.as_str())?.clone(),
            Expression::UnaryExpression(e) => {
                // Even void must prove its argument free of effects and exceptions.
                let v = self.eval(&e.argument, next)?;
                match e.operator {
                    U::UnaryPlus => Value::Number(v.number()?),
                    U::UnaryNegation => Value::Number(-v.number()?),
                    U::LogicalNot => Value::Bool(!v.truthy()),
                    U::BitwiseNot => Value::Number(f64::from(!int32(v.number()?))),
                    U::Void => Value::Undefined,
                    U::Typeof => Value::String(
                        match v {
                            Value::Number(_) => "number",
                            Value::String(_) => "string",
                            Value::Bool(_) => "boolean",
                            Value::Null => "object",
                            Value::Undefined => "undefined",
                        }
                        .into(),
                    ),
                    _ => return None,
                }
            }
            Expression::BinaryExpression(e) => {
                let left = self.eval(&e.left, next)?;
                let right = self.eval(&e.right, next)?;
                match e.operator {
                    B::Addition
                        if matches!((&left, &right), (Value::String(_), Value::String(_))) =>
                    {
                        let (Value::String(mut a), Value::String(b)) = (left, right) else {
                            unreachable!()
                        };
                        if a.len() + b.len() > MAX_VALUE_BYTES {
                            self.truncated = true;
                            return None;
                        }
                        a.push_str(&b);
                        Value::String(a)
                    }
                    B::StrictEquality | B::StrictInequality => {
                        Value::Bool((left == right) == (e.operator == B::StrictEquality))
                    }
                    B::Equality | B::Inequality
                        if std::mem::discriminant(&left) == std::mem::discriminant(&right) =>
                    {
                        Value::Bool((left == right) == (e.operator == B::Equality))
                    }
                    B::LessThan | B::LessEqualThan | B::GreaterThan | B::GreaterEqualThan
                        if matches!((&left, &right), (Value::String(_), Value::String(_))) =>
                    {
                        let (Value::String(a), Value::String(b)) = (left, right) else {
                            unreachable!()
                        };
                        let order = a.encode_utf16().cmp(b.encode_utf16());
                        Value::Bool(match e.operator {
                            B::LessThan => order.is_lt(),
                            B::LessEqualThan => !order.is_gt(),
                            B::GreaterThan => order.is_gt(),
                            _ => !order.is_lt(),
                        })
                    }
                    op => {
                        let (a, b) = (left.number()?, right.number()?);
                        match op {
                            B::Addition => Value::Number(a + b),
                            B::Subtraction => Value::Number(a - b),
                            B::Multiplication => Value::Number(a * b),
                            B::Division => Value::Number(a / b),
                            B::Remainder => Value::Number(a % b),
                            // Floating-point pow implementations need not agree across JS engines.
                            // Only exact small integer powers are reduced here.
                            B::Exponential
                                if a.fract() == 0.0
                                    && b.fract() == 0.0
                                    && (0.0..=31.0).contains(&b)
                                    && a.abs() <= 1024.0 =>
                            {
                                let n = a.powi(b as i32);
                                if n.abs() > 9007199254740991.0 {
                                    return None;
                                }
                                Value::Number(n)
                            }
                            B::BitwiseXOR => Value::Number(f64::from(int32(a) ^ int32(b))),
                            B::BitwiseAnd => Value::Number(f64::from(int32(a) & int32(b))),
                            B::BitwiseOR => Value::Number(f64::from(int32(a) | int32(b))),
                            B::ShiftLeft => Value::Number(f64::from(
                                int32(a).wrapping_shl((int32(b) as u32) & 31),
                            )),
                            B::ShiftRight => {
                                Value::Number(f64::from(int32(a) >> ((int32(b) as u32) & 31)))
                            }
                            B::ShiftRightZeroFill => Value::Number(f64::from(
                                (int32(a) as u32) >> ((int32(b) as u32) & 31),
                            )),
                            B::LessThan => Value::Bool(a < b),
                            B::LessEqualThan => Value::Bool(a <= b),
                            B::GreaterThan => Value::Bool(a > b),
                            B::GreaterEqualThan => Value::Bool(a >= b),
                            _ => return None,
                        }
                    }
                }
            }
            Expression::LogicalExpression(e) => {
                let left = self.eval(&e.left, next)?;
                let use_right = match e.operator {
                    L::And => left.truthy(),
                    L::Or => !left.truthy(),
                    L::Coalesce => matches!(left, Value::Null | Value::Undefined),
                };
                if use_right {
                    self.eval(&e.right, next)?
                } else {
                    left
                }
            }
            Expression::ConditionalExpression(e) => {
                let test = self.eval(&e.test, next)?;
                self.eval(
                    if test.truthy() {
                        &e.consequent
                    } else {
                        &e.alternate
                    },
                    next,
                )?
            }
            Expression::ComputedMemberExpression(e) if !e.optional => {
                // Only own, present indices. No prototype lookup, holes, getters,
                // user objects, spreads or bindings that could alias a mutable array.
                let Value::Number(index) = self.eval(&e.expression, next)? else {
                    return None;
                };
                if index < 0.0 || index.fract() != 0.0 {
                    return None;
                }
                match &e.object {
                    Expression::ArrayExpression(array) if index < array.elements.len() as f64 => {
                        let mut result = None;
                        for (i, element) in array.elements.iter().enumerate() {
                            let value = self.eval(element.as_expression()?, next)?;
                            if i == index as usize {
                                result = Some(value);
                            }
                        }
                        result?
                    }
                    Expression::Identifier(id) => self
                        .tables
                        .get(id.name.as_str())?
                        .get(index as usize)?
                        .clone(),
                    Expression::StringLiteral(s) if !s.lone_surrogates => {
                        let unit = s.value.encode_utf16().nth(index as usize)?;
                        Value::String(char::from_u32(u32::from(unit))?.to_string())
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };
        if matches!(&value, Value::Number(n) if !n.is_finite()) {
            return None;
        }
        Some(value)
    }
    fn rewrite(&mut self, span: Span, replacement: String, kind: &'static str) -> bool {
        if self.rewrites.len() >= MAX_TRANSFORMATIONS
            || self.replacement_bytes + replacement.len() > MAX_REPLACEMENT_BYTES
        {
            self.truncated = true;
            return false;
        }
        if self.source[span.start as usize..span.end as usize] == replacement {
            return false;
        }
        self.replacement_bytes += replacement.len();
        self.rewrites.push(Transformation {
            kind,
            original_start: span.start,
            original_end: span.end,
            replacement,
        });
        true
    }
}

impl<'a> Visit<'a> for Folder<'_> {
    fn visit_statements(&mut self, statements: &oxc_allocator::Vec<'a, Statement<'a>>) {
        let outer = std::mem::take(&mut self.constants);
        let outer_tables = std::mem::take(&mut self.tables);
        self.list_depth += 1;
        for statement in statements {
            match statement {
                Statement::VariableDeclaration(declaration) => {
                    for declarator in &declaration.declarations {
                        if let Some(init) = &declarator.init {
                            self.visit_expression(init);
                            if declaration.kind == VariableDeclarationKind::Const {
                                if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                                    if let Some(value) = self.eval(init, 0) {
                                        if self.constants.len() < 64 {
                                            self.constants.insert(id.name.to_string(), value);
                                        }
                                    }
                                    if let Expression::ArrayExpression(array) = init {
                                        let name = id.name.as_str();
                                        if self.list_depth > 1
                                            && self.tables.len() < 16
                                            && array.elements.len() <= 256
                                            && self.table_uses.safe(name, array.elements.len())
                                        {
                                            let values: Option<Vec<_>> = array
                                                .elements
                                                .iter()
                                                .map(|e| self.eval(e.as_expression()?, 0))
                                                .collect();
                                            if let Some(values) = values {
                                                if values
                                                    .iter()
                                                    .map(|v| v.code().len())
                                                    .sum::<usize>()
                                                    <= MAX_VALUE_BYTES
                                                {
                                                    self.tables.insert(name.to_string(), values);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Destructuring defaults and computed keys can have effects.
                        // Don't propagate across a non-simple declaration.
                        if !matches!(&declarator.id, BindingPattern::BindingIdentifier(_)) {
                            self.constants.clear();
                        }
                    }
                }
                Statement::ExpressionStatement(s) => self.visit_expression(&s.expression),
                Statement::ReturnStatement(s) => {
                    if let Some(argument) = &s.argument {
                        self.visit_expression(argument);
                    }
                }
                Statement::ThrowStatement(s) => self.visit_expression(&s.argument),
                _ => {
                    let local = std::mem::take(&mut self.constants);
                    let local_tables = std::mem::take(&mut self.tables);
                    self.visit_statement(statement);
                    self.constants = local;
                    self.tables = local_tables;
                }
            }
        }
        self.constants = outer;
        self.tables = outer_tables;
        self.list_depth -= 1;
    }
    fn visit_function(&mut self, function: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        let outer = std::mem::take(&mut self.constants);
        let tables = std::mem::take(&mut self.tables);
        walk::walk_function(self, function, flags);
        self.constants = outer;
        self.tables = tables;
    }
    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let outer = std::mem::take(&mut self.constants);
        let tables = std::mem::take(&mut self.tables);
        walk::walk_arrow_function_expression(self, function);
        self.constants = outer;
        self.tables = tables;
    }
    fn visit_class(&mut self, class: &Class<'a>) {
        let outer = std::mem::take(&mut self.constants);
        let tables = std::mem::take(&mut self.tables);
        walk::walk_class(self, class);
        self.constants = outer;
        self.tables = tables;
    }
    fn visit_if_statement(&mut self, statement: &IfStatement<'a>) {
        if let Some(test) = self.eval(&statement.test, 0) {
            let (chosen, discarded) = if test.truthy() {
                (Some(&statement.consequent), statement.alternate.as_ref())
            } else {
                (statement.alternate.as_ref(), Some(&statement.consequent))
            };
            let mut declarations = Declarations::default();
            if let Some(discarded) = discarded {
                declarations.visit_statement(discarded);
            }
            // Annex B function declarations in either arm also have surrounding
            // scope effects. Keep those if statements intact.
            if let Some(chosen) = chosen {
                declarations.visit_statement(chosen);
            }
            if !declarations.found {
                let body = chosen.map_or("", |node| {
                    let span = node.span();
                    &self.source[span.start as usize..span.end as usize]
                });
                if self.rewrite(statement.span, format!("{{void 0; {body}}}"), "dead-branch") {
                    return;
                }
            }
        }
        walk::walk_if_statement(self, statement);
    }
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        let eligible = !matches!(
            expression,
            Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
        );
        if eligible {
            if let Some(value) = self.eval(expression, 0) {
                let kind = match expression {
                    Expression::Identifier(_) => "constant-propagation",
                    Expression::StringLiteral(_) => "literal-normalization",
                    Expression::ComputedMemberExpression(_) => "literal-index",
                    Expression::ConditionalExpression(_) | Expression::LogicalExpression(_) => {
                        "dead-expression"
                    }
                    _ => "constant-fold",
                };
                // Parentheses preserve grammar, directive prologues, exponentiation,
                // numeric member access, and short-circuit reference semantics.
                let code = value.code();
                if let Expression::StringLiteral(s) = expression {
                    if !self.source[s.span.start as usize..s.span.end as usize].contains('\\') {
                        return;
                    }
                }
                if self.rewrite(expression.span(), format!("({code})"), kind) {
                    return;
                }
            }
        }
        // `delete name` is a Reference operation, not a value computation.
        if matches!(expression, Expression::UnaryExpression(e) if e.operator == U::Delete) {
            return;
        }
        walk::walk_expression(self, expression);
    }
    fn visit_computed_member_expression(&mut self, member: &ComputedMemberExpression<'a>) {
        self.visit_expression(&member.object);
        if let Expression::StringLiteral(property) = &member.expression {
            let name = property.value.as_str();
            if !property.lone_surrogates
                && !name.is_empty()
                && name.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_alphabetic()
                        || b == b'_'
                        || b == b'$'
                        || (i > 0 && b.is_ascii_digit())
                })
            {
                // Keep brackets around numeric receivers: `1.toString` is invalid.
                if !matches!(member.object, Expression::NumericLiteral(_)) {
                    self.rewrite(
                        Span::new(member.object.span().end, member.span.end),
                        format!("{}{}", if member.optional { "?." } else { "." }, name),
                        "member-normalization",
                    );
                    return;
                }
            }
        }
        self.visit_expression(&member.expression);
    }
}

// A table is eligible only if every use is a present, literal index read and
// its name has exactly one binding anywhere in the file. This deliberately
// rejects aliasing, mutation, closures that write, shadowing, holes and escapes.
#[derive(Default)]
struct TableUses {
    bindings: HashMap<String, usize>,
    reads: HashMap<String, Vec<usize>>,
    allowed: HashSet<u32>,
    unsafe_names: HashSet<String>,
    dynamic_scope: bool,
    deleting: bool,
}
impl TableUses {
    fn safe(&self, name: &str, length: usize) -> bool {
        !self.dynamic_scope
            && self.bindings.get(name) == Some(&1)
            && !self.unsafe_names.contains(name)
            && self
                .reads
                .get(name)
                .is_some_and(|reads| reads.iter().all(|i| *i < length))
    }
}
impl<'a> Visit<'a> for TableUses {
    fn visit_with_statement(&mut self, statement: &WithStatement<'a>) {
        self.dynamic_scope = true;
        walk::walk_with_statement(self, statement);
    }
    fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
        *self.bindings.entry(id.name.to_string()).or_default() += 1;
    }
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Expression::ComputedMemberExpression(member) = expression {
            if let (Expression::Identifier(id), Expression::NumericLiteral(index)) =
                (&member.object, &member.expression)
            {
                if !self.deleting
                    && !member.optional
                    && index.value >= 0.0
                    && index.value < 256.0
                    && index.value.fract() == 0.0
                {
                    self.allowed.insert(id.span.start);
                    self.reads
                        .entry(id.name.to_string())
                        .or_default()
                        .push(index.value as usize);
                }
            }
        }
        if let Expression::UnaryExpression(e) = expression {
            if e.operator == U::Delete {
                let previous = self.deleting;
                self.deleting = true;
                walk::walk_expression(self, expression);
                self.deleting = previous;
                return;
            }
        }
        walk::walk_expression(self, expression);
    }
    fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
        if id.name == "eval" {
            self.dynamic_scope = true;
        }
        if !self.allowed.contains(&id.span.start) {
            self.unsafe_names.insert(id.name.to_string());
        }
    }
}

#[derive(Default)]
struct Declarations {
    found: bool,
}
impl<'a> Visit<'a> for Declarations {
    fn visit_variable_declaration(&mut self, _: &VariableDeclaration<'a>) {
        self.found = true;
    }
    fn visit_function(&mut self, _: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
        self.found = true;
    }
    fn visit_class(&mut self, _: &Class<'a>) {
        self.found = true;
    }
}
