//! Closed proxy descriptions own bounded source text rather than AST pointers.
use oxc_ast::ast::*;
use oxc_ast_visit::Visit;
use oxc_span::{GetSpan, Span};
use std::collections::HashSet;

#[derive(Clone)]
pub struct Proxy {
    pub parameters: Vec<String>,
    pub expression: String,
    pub block: bool,
    pub control_flow: bool,
}

impl Proxy {
    pub fn expression(expression: &Expression<'_>, source: &str) -> Option<Self> {
        match expression {
            Expression::ParenthesizedExpression(e) => Self::expression(&e.expression, source),
            Expression::ArrowFunctionExpression(f) if !f.r#async => {
                let body = match &f.body {
                    ArrowFunctionBody::FunctionBody(body) => {
                        return Self::body(&f.params, body, source);
                    }
                    body => body.as_expression()?,
                };
                Self::capture(&f.params, body.span(), false, source)
            }
            Expression::FunctionExpression(f) => Self::function(f, source),
            _ => None,
        }
    }

    pub fn function(function: &Function<'_>, source: &str) -> Option<Self> {
        if function.r#async || function.generator {
            return None;
        }
        Self::body(&function.params, function.body.as_ref()?, source)
    }

    fn body(params: &FormalParameters<'_>, body: &FunctionBody<'_>, source: &str) -> Option<Self> {
        if let Some(expression) = return_expression(body) {
            Self::capture(params, expression.span(), false, source)
        } else {
            let mut proxy = Self::capture(params, body.span, true, source)?;
            let mut flow = ControlFlow::default();
            flow.visit_function_body(body);
            proxy.control_flow = flow.0;
            Some(proxy)
        }
    }

    fn capture(
        params: &FormalParameters<'_>,
        span: Span,
        block: bool,
        source: &str,
    ) -> Option<Self> {
        if params.rest.is_some() || params.items.len() > 16 || span.size() > 4096 {
            return None;
        }
        let mut names = HashSet::new();
        let mut parameters = Vec::new();
        for param in &params.items {
            let BindingPattern::BindingIdentifier(id) = &param.pattern else {
                return None;
            };
            if param.initializer.is_some() || !names.insert(id.name.as_str()) {
                return None;
            }
            parameters.push(id.name.to_string());
        }
        Some(Self {
            parameters,
            block,
            control_flow: false,
            expression: source[span.start as usize..span.end as usize].to_string(),
        })
    }
}

fn return_expression<'a, 'b>(body: &'b FunctionBody<'a>) -> Option<&'b Expression<'a>> {
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(statement) = &body.statements[0] else {
        return None;
    };
    statement.argument.as_ref()
}

#[derive(Default)]
struct ControlFlow(bool);
impl<'a> Visit<'a> for ControlFlow {
    fn visit_while_statement(&mut self, _: &WhileStatement<'a>) {
        self.0 = true;
    }
    fn visit_do_while_statement(&mut self, _: &DoWhileStatement<'a>) {
        self.0 = true;
    }
    fn visit_switch_statement(&mut self, _: &SwitchStatement<'a>) {
        self.0 = true;
    }
}
