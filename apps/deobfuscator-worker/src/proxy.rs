//! Closed proxy descriptions own bounded source text rather than AST pointers.
use oxc_ast::ast::*;
use oxc_span::GetSpan;
use std::collections::HashSet;

#[derive(Clone)]
pub struct Proxy {
    pub parameters: Vec<String>,
    pub expression: String,
}

impl Proxy {
    pub fn expression(expression: &Expression<'_>, source: &str) -> Option<Self> {
        match expression {
            Expression::ParenthesizedExpression(e) => Self::expression(&e.expression, source),
            Expression::ArrowFunctionExpression(f) if !f.r#async => {
                let body = match &f.body {
                    ArrowFunctionBody::FunctionBody(body) => return_expression(body)?,
                    body => body.as_expression()?,
                };
                Self::capture(&f.params, body, source)
            }
            Expression::FunctionExpression(f) => Self::function(f, source),
            _ => None,
        }
    }

    pub fn function(function: &Function<'_>, source: &str) -> Option<Self> {
        if function.r#async || function.generator {
            return None;
        }
        Self::capture(
            &function.params,
            return_expression(function.body.as_ref()?)?,
            source,
        )
    }

    fn capture(params: &FormalParameters<'_>, body: &Expression<'_>, source: &str) -> Option<Self> {
        if params.rest.is_some() || params.items.len() > 16 || body.span().size() > 4096 {
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
        let span = body.span();
        Some(Self {
            parameters,
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
