//! Prettier-style JavaScript layout over Oxc tokens. Every printed token is
//! its original source slice; only whitespace between tokens is chosen.
use crate::source_format_doc::{Doc, Line};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::{Kind, Parser, Token, config::TokensParserConfig};
use oxc_span::{GetSpan, SourceType};
use oxc_syntax::precedence::{GetPrecedence, Precedence};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Parse,
    Output,
    /// Re-lexing the output did not reproduce the original tokens.
    Fidelity,
}

pub(crate) fn format(source: &str, output_limit: usize) -> Result<String, Refusal> {
    // Sloppy scripts first: most captured bundles are classic scripts.
    for source_type in [SourceType::mjs().with_script(true), SourceType::mjs()] {
        if let Some((text, tokens, comments)) = layout(source, source_type, output_limit) {
            let text = text?;
            verify(source, &text, source_type, &tokens, &comments)?;
            return Ok(text);
        }
    }
    Err(Refusal::Parse)
}

type Laid = (Result<String, Refusal>, Vec<Token>, Vec<(u32, u32)>);

/// Parses and prints; the parse arena is released before verification.
fn layout(source: &str, source_type: SourceType, output_limit: usize) -> Option<Laid> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_config(TokensParserConfig)
        .parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        return None;
    }
    let tokens: Vec<Token> = parsed
        .tokens
        .iter()
        .copied()
        .filter(|token| token.kind() != Kind::Eof)
        .collect();
    let comments = parsed
        .program
        .comments
        .iter()
        .map(|comment| (comment.span.start, comment.span.end))
        .collect();
    let mut layout = Layout::new(source, &tokens, &parsed.program.comments);
    layout.program(&parsed.program);
    let text = layout
        .doc
        .print(source, output_limit)
        .map_err(|_| Refusal::Output);
    drop(layout);
    Some((text, tokens, comments))
}

/// The output must lex to the same token texts and comments, in order.
fn verify(
    source: &str,
    output: &str,
    source_type: SourceType,
    tokens: &[Token],
    comments: &[(u32, u32)],
) -> Result<(), Refusal> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, output, source_type)
        .with_config(TokensParserConfig)
        .parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        return Err(Refusal::Fidelity);
    }
    fn slice(text: &str, start: u32, end: u32) -> &str {
        &text[start as usize..end as usize]
    }
    let original = tokens
        .iter()
        .map(|token| (token.kind(), slice(source, token.start(), token.end())));
    let printed = parsed
        .tokens
        .iter()
        .filter(|token| token.kind() != Kind::Eof)
        .map(|token| (token.kind(), slice(output, token.start(), token.end())));
    let original_comments = comments
        .iter()
        .map(|&(start, end)| slice(source, start, end));
    let printed_comments = parsed
        .program
        .comments
        .iter()
        .map(|comment| slice(output, comment.span.start, comment.span.end));
    if !original.eq(printed) || !original_comments.eq(printed_comments) {
        return Err(Refusal::Fidelity);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Sep {
    Default,
    None,
    Space,
    Line(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rhs {
    SameLine,
    BreakAfter,
    Fluid,
}

#[derive(Clone, Copy)]
struct Note {
    start: u32,
    end: u32,
    line: bool,
}

struct Layout<'s, 't> {
    source: &'s str,
    tokens: &'t [Token],
    comments: Vec<Note>,
    next: usize,
    next_comment: usize,
    doc: Doc,
    prev: Option<Token>,
    /// The previous token is a property name after `.` or `?.`.
    prev_property: bool,
    prev_comment: bool,
    last_end: u32,
    sep: Sep,
}

impl<'s, 't> Layout<'s, 't> {
    fn new(source: &'s str, tokens: &'t [Token], comments: &[Comment]) -> Self {
        let comments = comments
            .iter()
            .map(|comment| Note {
                start: comment.span.start,
                end: comment.span.end,
                line: matches!(
                    comment.kind,
                    CommentKind::Line | CommentKind::HtmlOpen | CommentKind::HtmlClose
                ),
            })
            .collect();
        Self {
            source,
            tokens,
            comments,
            next: 0,
            next_comment: 0,
            doc: Doc::new(tokens.len() * 2 + 16),
            prev: None,
            prev_property: false,
            prev_comment: false,
            last_end: 0,
            sep: Sep::Default,
        }
    }

    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.next).copied()
    }
    fn peek_kind(&self) -> Option<Kind> {
        self.peek().map(|token| token.kind())
    }
    fn emit(&mut self) {
        let Some(token) = self.peek() else {
            return;
        };
        self.leading_comments(token.start());
        self.separate(token);
        self.doc.text(token.start(), token.end());
        self.prev_property = matches!(
            self.prev.map(|prev| prev.kind()),
            Some(Kind::Dot | Kind::QuestionDot)
        ) && token.kind().is_identifier_name();
        self.prev = Some(token);
        self.prev_comment = false;
        self.last_end = token.end();
        self.next += 1;
        self.sep = Sep::Default;
        self.trailing_comments();
    }
    fn emit_until(&mut self, end: u32) {
        while self.peek().is_some_and(|token| token.start() < end) {
            self.emit();
        }
    }
    /// Emits every token before the one that ends at `end`.
    fn emit_before_last(&mut self, end: u32) {
        while self.peek().is_some_and(|token| token.end() < end) {
            self.emit();
        }
    }
    fn space(&mut self) {
        self.sep = Sep::Space;
    }
    fn none(&mut self) {
        self.sep = Sep::None;
    }
    fn line(&mut self, line: Line) {
        let at = self.doc.line(line);
        self.sep = Sep::Line(at);
    }
    fn hard(&mut self, blank: bool) {
        self.line(if blank { Line::Blank } else { Line::Hard });
    }

    fn separate(&mut self, token: Token) {
        if self.prev_comment {
            match self.sep {
                Sep::Line(at) => self.doc.harden_soft(at),
                Sep::None => (),
                Sep::Default | Sep::Space => self.doc.space(),
            }
            return;
        }
        let Some(prev) = self.prev else {
            return;
        };
        let hazard = hazard(self.source, prev, token);
        match self.sep {
            Sep::Line(at) => {
                if hazard {
                    self.doc.harden_soft(at);
                }
            }
            Sep::None => {
                if hazard {
                    self.doc.space();
                }
            }
            Sep::Space => self.doc.space(),
            Sep::Default => {
                if hazard || default_space(prev, token, self.prev_property) {
                    self.doc.space();
                }
            }
        }
    }

    fn leading_comments(&mut self, before: u32) {
        while let Some(comment) = self.comments.get(self.next_comment).copied()
            && comment.start < before
        {
            let gap = &self.source[self.last_end as usize..comment.start as usize];
            let newlines = gap.matches('\n').count();
            if newlines > 0 && (self.prev.is_some() || self.prev_comment) {
                self.hard(newlines > 1);
            }
            self.comment(comment, before);
        }
    }
    fn trailing_comments(&mut self) {
        let before = self
            .peek()
            .map_or(self.source.len() as u32, |token| token.start());
        // Only comments that end the line stay with the previous token.
        while let Some(comment) = self.comments.get(self.next_comment).copied()
            && comment.start < before
            && !self.source[self.last_end as usize..comment.start as usize].contains('\n')
            && (comment.line || self.ends_line(comment.end, before))
        {
            self.comment(comment, before);
        }
    }
    fn ends_line(&self, end: u32, before: u32) -> bool {
        let next = self
            .comments
            .get(self.next_comment + 1)
            .map_or(before, |next| next.start.min(before));
        self.source[end as usize..next.max(end) as usize].contains('\n')
    }
    /// An unprinted comment lies inside `span`, after its opening token.
    fn comment_within(&self, span: oxc_span::Span) -> bool {
        self.comments[self.next_comment..]
            .iter()
            .take_while(|comment| comment.start < span.end)
            .any(|comment| comment.start > span.start)
    }
    fn comment(&mut self, comment: Note, before: u32) {
        let opener = matches!(
            self.prev.map(|prev| prev.kind()),
            Some(Kind::LParen | Kind::LBrack)
        ) && comment.start == self.last_end;
        match self.sep {
            Sep::Line(_) | Sep::None => (),
            Sep::Default | Sep::Space => {
                if (self.prev.is_some() || self.prev_comment) && !opener {
                    self.doc.space();
                }
            }
        }
        self.doc.text(comment.start, comment.end);
        self.prev_comment = true;
        self.last_end = comment.end;
        self.next_comment += 1;
        let next = self
            .comments
            .get(self.next_comment)
            .map_or(before, |next| next.start.min(before))
            .max(comment.end);
        let after = &self.source[comment.end as usize..next as usize];
        if comment.line || after.contains('\n') {
            self.hard(after.matches('\n').count() > 1);
        } else {
            self.space();
        }
    }

    fn blank_between(&self, end: u32, start: u32) -> bool {
        let gap = &self.source[end.min(start) as usize..start as usize];
        let mut newline = false;
        for byte in gap.bytes() {
            match byte {
                b'\n' if newline => return true,
                b'\n' => newline = true,
                b' ' | b'\t' | b'\r' => (),
                _ => newline = false,
            }
        }
        false
    }

    fn program(&mut self, program: &Program) {
        if let Some(hashbang) = &program.hashbang {
            if self.peek_kind() == Some(Kind::HashbangComment) {
                self.emit();
            } else {
                self.doc.text(hashbang.span.start, hashbang.span.end);
                self.prev_comment = true;
                self.last_end = hashbang.span.end;
            }
            self.hard(false);
        }
        self.body(&program.directives, &program.body);
        self.emit_until(u32::MAX);
        self.leading_comments(self.source.len() as u32);
    }

    fn body(&mut self, directives: &[Directive], statements: &[Statement]) {
        let mut previous: Option<u32> = None;
        let spans = directives
            .iter()
            .map(|directive| (directive.span, None))
            .chain(
                statements
                    .iter()
                    .map(|statement| (statement.span(), Some(statement))),
            );
        for (span, statement) in spans {
            if let Some(end) = previous {
                let blank = self.blank_between(end, span.start);
                self.hard(blank);
            }
            match statement {
                Some(statement) => self.statement(statement),
                None => self.emit_until(span.end),
            }
            previous = Some(span.end);
        }
    }

    fn block(&mut self, span: oxc_span::Span, directives: &[Directive], statements: &[Statement]) {
        let comments_inside = self.comment_within(span);
        self.emit_until(span.start + 1);
        if directives.is_empty() && statements.is_empty() && !comments_inside {
            self.none();
            self.emit_until(span.end);
            return;
        }
        self.doc.indent();
        self.hard(false);
        self.body(directives, statements);
        self.emit_before_last(span.end);
        self.leading_comments(span.end - 1);
        self.doc.dedent();
        self.hard(false);
        self.emit_until(span.end);
    }

    fn statement(&mut self, statement: &Statement) {
        let span = statement.span();
        self.emit_until(span.start);
        match statement {
            Statement::BlockStatement(block) => self.block(block.span, &[], &block.body),
            Statement::ExpressionStatement(statement) => {
                self.expr(&statement.expression);
                self.finish(span.end);
            }
            Statement::VariableDeclaration(declaration) => {
                self.variables(declaration, false);
                self.finish(span.end);
            }
            Statement::FunctionDeclaration(function) => self.function(function),
            Statement::ClassDeclaration(class) => self.class(class),
            Statement::ReturnStatement(statement) => {
                self.keyword_argument(statement.argument.as_ref(), span.end)
            }
            Statement::ThrowStatement(statement) => {
                self.keyword_argument(Some(&statement.argument), span.end)
            }
            Statement::IfStatement(statement) => self.if_statement(statement),
            Statement::ForStatement(statement) => self.for_statement(statement),
            Statement::ForInStatement(statement) => {
                self.for_each(&statement.left, &statement.right, &statement.body)
            }
            Statement::ForOfStatement(statement) => {
                self.for_each(&statement.left, &statement.right, &statement.body)
            }
            Statement::WhileStatement(statement) => {
                self.doc.open();
                self.keyword_test(&statement.test);
                self.clause(&statement.body);
                self.doc.close();
            }
            Statement::WithStatement(statement) => {
                self.doc.open();
                self.keyword_test(&statement.object);
                self.clause(&statement.body);
                self.doc.close();
            }
            Statement::DoWhileStatement(statement) => {
                self.doc.open();
                self.emit();
                self.clause(&statement.body);
                self.doc.close();
                if matches!(statement.body, Statement::BlockStatement(_)) {
                    self.space();
                } else {
                    self.hard(false);
                }
                self.keyword_test(&statement.test);
                self.finish(span.end);
            }
            Statement::SwitchStatement(statement) => self.switch(statement),
            Statement::TryStatement(statement) => {
                self.emit();
                self.space();
                self.block(statement.block.span, &[], &statement.block.body);
                if let Some(handler) = &statement.handler {
                    self.space();
                    self.emit();
                    if let Some(param) = &handler.param {
                        self.space();
                        self.emit_until(param.span.start);
                        self.binding(&param.pattern);
                        self.none();
                        self.emit_until(handler.body.span.start);
                    }
                    self.space();
                    self.block(handler.body.span, &[], &handler.body.body);
                }
                if let Some(finalizer) = &statement.finalizer {
                    self.space();
                    self.emit_until(finalizer.span.start);
                    self.space();
                    self.block(finalizer.span, &[], &finalizer.body);
                }
            }
            Statement::LabeledStatement(statement) => {
                self.emit_until(statement.label.span.end);
                self.none();
                self.emit_until(statement.body.span().start);
                if matches!(statement.body, Statement::EmptyStatement(_)) {
                    self.none();
                } else {
                    self.space();
                }
                self.statement(&statement.body);
            }
            Statement::ExportDeclaration(export) => {
                self.emit_until(export.declaration.span().start);
                self.space();
                self.declaration(&export.declaration);
            }
            Statement::ExportDefaultDeclaration(export) => {
                let declaration = &export.declaration;
                self.emit_until(declaration.span().start);
                self.space();
                match declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        self.function(function)
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => self.class(class),
                    _ => match declaration.as_expression() {
                        Some(expression) => self.expr(expression),
                        None => self.emit_until(declaration.span().end),
                    },
                }
                self.finish(span.end);
            }
            _ => (),
        }
        self.emit_until(span.end);
    }

    fn declaration(&mut self, declaration: &Declaration) {
        match declaration {
            Declaration::VariableDeclaration(variables) => {
                self.variables(variables, false);
                self.finish(variables.span.end);
            }
            Declaration::FunctionDeclaration(function) => self.function(function),
            Declaration::ClassDeclaration(class) => self.class(class),
            _ => self.emit_until(declaration.span().end),
        }
    }

    /// Optional `;` and any trailing tokens of a statement.
    fn finish(&mut self, end: u32) {
        self.none();
        self.emit_until(end);
    }

    fn keyword_argument(&mut self, argument: Option<&Expression>, end: u32) {
        self.emit();
        if let Some(argument) = argument {
            self.space();
            self.expr(argument);
        }
        self.finish(end);
    }

    /// `keyword (test)` with the test indented when it breaks.
    fn keyword_test(&mut self, test: &Expression) {
        let start = test.span().start;
        while self
            .peek()
            .is_some_and(|token| token.kind() != Kind::LParen && token.start() < start)
        {
            self.emit();
        }
        self.space();
        self.emit();
        self.doc.open();
        self.doc.indent();
        self.line(Line::Soft);
        self.test(test);
        self.doc.dedent();
        self.line(Line::Soft);
        self.doc.close();
        self.none();
        self.emit();
    }

    fn test(&mut self, test: &Expression) {
        match test {
            Expression::BinaryExpression(_) | Expression::LogicalExpression(_) => {
                self.binary(test, true)
            }
            _ => self.expr(test),
        }
    }

    /// Prettier's `adjustClause`.
    fn clause(&mut self, body: &Statement) {
        match body {
            Statement::BlockStatement(_) => {
                self.space();
                self.statement(body);
            }
            Statement::EmptyStatement(_) => {
                self.none();
                self.statement(body);
            }
            _ => {
                self.doc.indent();
                self.line(Line::Normal);
                self.statement(body);
                self.doc.dedent();
            }
        }
    }

    fn if_statement(&mut self, statement: &IfStatement) {
        self.doc.open();
        self.keyword_test(&statement.test);
        self.clause(&statement.consequent);
        self.doc.close();
        if let Some(alternate) = &statement.alternate {
            if matches!(statement.consequent, Statement::BlockStatement(_)) {
                self.space();
            } else {
                self.hard(false);
            }
            self.emit_until(alternate.span().start);
            if let Statement::IfStatement(nested) = alternate {
                self.space();
                self.if_statement(nested);
            } else {
                self.doc.open();
                self.clause(alternate);
                self.doc.close();
            }
        }
    }

    fn for_statement(&mut self, statement: &ForStatement) {
        self.doc.open();
        self.emit();
        self.space();
        self.emit();
        let body_start = statement.body.span().start;
        if statement.init.is_none() && statement.test.is_none() && statement.update.is_none() {
            while self.peek().is_some_and(|token| token.start() < body_start) {
                self.none();
                self.emit();
            }
        } else {
            self.doc.open();
            self.doc.indent();
            self.line(Line::Soft);
            if let Some(init) = &statement.init {
                match init {
                    ForStatementInit::VariableDeclaration(variables) => {
                        self.variables(variables, true)
                    }
                    _ => {
                        if let Some(expression) = init.as_expression() {
                            self.expr(expression);
                        }
                    }
                }
            }
            let mut gap = false;
            for part in [statement.test.as_ref(), statement.update.as_ref()] {
                if gap {
                    self.space();
                } else {
                    self.none();
                }
                self.emit();
                gap = part.is_none();
                if let Some(expression) = part {
                    self.line(Line::Normal);
                    self.expr(expression);
                }
            }
            self.doc.dedent();
            self.line(Line::Soft);
            self.doc.close();
            self.none();
            self.emit_until(body_start);
        }
        self.clause(&statement.body);
        self.doc.close();
    }

    fn for_each(&mut self, left: &ForStatementLeft, right: &Expression, body: &Statement) {
        self.doc.open();
        self.emit_until(left.span().start);
        match left {
            ForStatementLeft::VariableDeclaration(variables) => self.variables(variables, true),
            _ => match left.as_assignment_target() {
                Some(target) => self.target(target),
                None => self.emit_until(left.span().end),
            },
        }
        self.space();
        self.emit_until(right.span().start);
        self.space();
        self.expr(right);
        self.none();
        self.emit_until(body.span().start);
        self.clause(body);
        self.doc.close();
    }

    fn switch(&mut self, statement: &SwitchStatement) {
        self.keyword_test(&statement.discriminant);
        self.space();
        self.emit();
        if statement.cases.is_empty() {
            self.none();
            self.emit_until(statement.span.end);
            return;
        }
        self.doc.indent();
        let mut previous: Option<u32> = None;
        for case in &statement.cases {
            let blank = previous.is_some_and(|end| self.blank_between(end, case.span.start));
            self.hard(blank);
            self.emit();
            if let Some(test) = &case.test {
                self.space();
                self.expr(test);
            }
            self.none();
            self.emit();
            match case.consequent.as_slice() {
                [Statement::BlockStatement(block)] => {
                    self.space();
                    self.block(block.span, &[], &block.body);
                }
                [] => (),
                statements => {
                    self.doc.indent();
                    let mut previous_statement: Option<u32> = None;
                    for statement in statements {
                        let blank = previous_statement
                            .is_some_and(|end| self.blank_between(end, statement.span().start));
                        self.hard(blank);
                        self.statement(statement);
                        previous_statement = Some(statement.span().end);
                    }
                    self.doc.dedent();
                }
            }
            previous = Some(case.span.end);
        }
        self.emit_before_last(statement.span.end);
        self.leading_comments(statement.span.end - 1);
        self.doc.dedent();
        self.hard(false);
        self.emit_until(statement.span.end);
    }

    fn variables(&mut self, declaration: &VariableDeclaration, in_for: bool) {
        let declarators = &declaration.declarations;
        let Some(first) = declarators.first() else {
            self.emit_until(declaration.span.end);
            return;
        };
        self.emit_until(first.span.start);
        self.space();
        let has_value = declarators
            .iter()
            .any(|declarator| declarator.init.is_some());
        self.doc.open();
        let several = declarators.len() > 1;
        if several {
            self.doc.indent();
        }
        for (index, declarator) in declarators.iter().enumerate() {
            if index > 0 {
                self.none();
                self.emit_until(declarator.span.start);
                if has_value && !in_for {
                    self.hard(false);
                } else {
                    self.line(Line::Normal);
                }
            }
            self.binding(&declarator.id);
            self.emit_until(
                declarator
                    .init
                    .as_ref()
                    .map_or(declarator.span.end, |init| init.span().start)
                    .min(declarator.span.end),
            );
            if let Some(init) = &declarator.init {
                self.rhs(init, false);
            }
            self.emit_until(declarator.span.end);
        }
        if several {
            self.doc.dedent();
        }
        self.doc.close();
    }

    fn function(&mut self, function: &Function) {
        self.doc.open();
        let params = function.params.span.start;
        while self.peek().is_some_and(|token| token.start() < params) {
            if self.peek_kind() == Some(Kind::Star) {
                self.none();
                self.emit();
                self.space();
            } else {
                self.emit();
            }
        }
        if function.id.is_none()
            && !matches!(self.prev.map(|token| token.kind()), Some(Kind::Ident))
        {
            self.space();
        } else {
            self.none();
        }
        self.function_tail(function);
        self.doc.close();
    }

    /// Parameters and body; the caller has printed everything before `(`.
    fn function_tail(&mut self, function: &Function) {
        self.params(&function.params);
        self.emit_until(
            function
                .body
                .as_ref()
                .map_or(function.span.end, |body| body.span.start),
        );
        if let Some(body) = &function.body {
            self.space();
            self.block(body.span, &body.directives, &body.statements);
        }
        self.emit_until(function.span.end);
    }

    fn params(&mut self, params: &FormalParameters) {
        let mut starts: Vec<u32> = params.items.iter().map(|item| item.span.start).collect();
        if let Some(rest) = &params.rest {
            starts.push(rest.span.start);
        }
        if self.peek_kind() != Some(Kind::LParen) {
            // A single arrow parameter without parentheses.
            if let Some(item) = params.items.first() {
                self.parameter(item);
            }
            return;
        }
        let rest = params.rest.as_deref();
        self.list(
            params.span.end,
            false,
            &starts,
            None,
            false,
            |layout, index| match params.items.get(index) {
                Some(item) => layout.parameter(item),
                None => {
                    if let Some(rest) = rest {
                        layout.rest(&rest.rest);
                    }
                }
            },
        );
    }

    fn parameter(&mut self, parameter: &FormalParameter) {
        self.emit_until(parameter.pattern.span().start);
        self.binding(&parameter.pattern);
        if let Some(initializer) = &parameter.initializer {
            self.space();
            self.emit_until(initializer.span().start);
            self.space();
            self.expr(initializer);
        }
        self.emit_until(parameter.span.end);
    }

    fn rest(&mut self, rest: &BindingRestElement) {
        self.emit_until(rest.argument.span().start);
        self.none();
        self.binding(&rest.argument);
        self.emit_until(rest.span.end);
    }

    fn arrow(&mut self, arrow: &ArrowFunctionExpression) {
        self.doc.open();
        if arrow.r#async {
            self.emit();
            self.space();
        }
        self.emit_until(arrow.params.span.start);
        self.params(&arrow.params);
        let body_start = match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => body.span.start,
            _ => arrow.body.span().start,
        };
        self.space();
        self.emit_until(body_start);
        match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                self.space();
                self.block(body.span, &body.directives, &body.statements);
            }
            _ => {
                let Some(body) = arrow.body.as_expression() else {
                    self.emit_until(arrow.span.end);
                    self.doc.close();
                    return;
                };
                if same_line_body(body) {
                    self.space();
                    self.expr(body);
                } else {
                    self.doc.open();
                    self.doc.indent();
                    self.line(Line::Normal);
                    self.indented(body);
                    self.doc.dedent();
                    self.doc.close();
                }
            }
        }
        self.emit_until(arrow.span.end);
        self.doc.close();
    }

    fn class(&mut self, class: &Class) {
        self.doc.open();
        if let Some(heritage) = &class.heritage {
            self.emit_until(heritage.expression.span().start);
            self.space();
            self.expr(&heritage.expression);
        }
        self.emit_until(class.body.span.start);
        self.space();
        let comments_inside = self.comment_within(class.body.span);
        self.emit();
        let members = &class.body.body;
        if members.is_empty() && !comments_inside {
            self.none();
            self.emit_until(class.body.span.end);
            self.doc.close();
            return;
        }
        self.doc.indent();
        let mut previous: Option<u32> = None;
        for member in members {
            let blank = previous.is_some_and(|end| self.blank_between(end, member.span().start));
            self.hard(blank);
            self.class_member(member);
            previous = Some(member.span().end);
        }
        self.emit_before_last(class.body.span.end);
        self.leading_comments(class.body.span.end - 1);
        self.doc.dedent();
        self.hard(false);
        self.emit_until(class.body.span.end);
        self.emit_until(class.span.end);
        self.doc.close();
    }

    fn class_member(&mut self, member: &ClassElement) {
        let span = member.span();
        match member {
            ClassElement::MethodDefinition(method) => {
                self.modifiers(method.key.span().start, method.computed);
                self.key(&method.key, method.computed);
                self.none();
                self.emit_until(method.value.params.span.start);
                self.none();
                self.function_tail(&method.value);
            }
            ClassElement::PropertyDefinition(property) => {
                self.modifiers(property.key.span().start, property.computed);
                self.key(&property.key, property.computed);
                if let Some(value) = &property.value {
                    self.space();
                    self.emit_until(value.span().start);
                    self.rhs(value, false);
                }
                self.finish(span.end);
            }
            ClassElement::AccessorProperty(property) => {
                self.modifiers(property.key.span().start, property.computed);
                self.key(&property.key, property.computed);
                if let Some(value) = &property.value {
                    self.space();
                    self.emit_until(value.span().start);
                    self.rhs(value, false);
                }
                self.finish(span.end);
            }
            ClassElement::StaticBlock(block) => {
                self.emit();
                self.space();
                let open = self.peek().map_or(block.span.end, |token| token.start());
                self.block(oxc_span::Span::new(open, block.span.end), &[], &block.body);
            }
            ClassElement::TSIndexSignature(_) => self.emit_until(span.end),
        }
    }

    /// `static`, `async`, `get`, `set` and `*` before a member key.
    fn modifiers(&mut self, key: u32, computed: bool) {
        let first = self.next;
        let end = if computed {
            self.tokens[self.next..]
                .iter()
                .find(|token| token.kind() == Kind::LBrack && token.start() <= key)
                .map_or(key, |token| token.start())
        } else {
            key
        };
        while self.peek().is_some_and(|token| token.start() < end) {
            if self.peek_kind() == Some(Kind::Star) {
                if self.next == first {
                    self.none();
                } else {
                    self.space();
                }
                self.emit();
                self.none();
            } else {
                self.emit();
                self.space();
            }
        }
    }

    fn key(&mut self, key: &PropertyKey, computed: bool) {
        if computed && let Some(expression) = key.as_expression() {
            self.emit_until(expression.span().start);
            self.none();
            self.expr(expression);
            self.none();
            self.emit();
        } else {
            self.emit_until(key.span().end);
        }
    }

    fn expr(&mut self, expression: &Expression) {
        let span = expression.span();
        self.emit_until(span.start);
        match expression {
            Expression::TemplateLiteral(template) => self.template(template),
            Expression::TaggedTemplateExpression(tagged) => {
                self.expr(&tagged.tag);
                self.none();
                self.emit_until(tagged.quasi.span.start);
                self.none();
                self.template(&tagged.quasi);
            }
            Expression::ArrayExpression(array) => {
                let starts: Vec<u32> = array
                    .elements
                    .iter()
                    .map(|element| element.span().start)
                    .collect();
                self.list(span.end, false, &starts, None, false, |layout, index| {
                    layout.element(&array.elements[index]);
                });
            }
            Expression::ObjectExpression(object) => self.object(object),
            Expression::FunctionExpression(function) => self.function(function),
            Expression::ArrowFunctionExpression(arrow) => self.arrow(arrow),
            Expression::ClassExpression(class) => self.class(class),
            Expression::CallExpression(call) => self.call(call),
            Expression::NewExpression(new) => {
                self.emit_until(new.callee.span().start);
                self.space();
                self.expr(&new.callee);
                self.emit_before_paren(span.end);
                if self
                    .peek()
                    .is_some_and(|token| token.kind() == Kind::LParen && token.start() < span.end)
                {
                    self.arguments(span.end, &new.arguments);
                }
            }
            Expression::ChainExpression(chain) => match &chain.expression {
                ChainElement::CallExpression(call) => self.call(call),
                element => match element.as_member_expression() {
                    Some(member) => self.member(member),
                    None => self.emit_until(span.end),
                },
            },
            Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => {
                self.member(expression.to_member_expression())
            }
            Expression::UnaryExpression(unary) => {
                self.emit_until(unary.argument.span().start);
                if unary.operator.is_keyword() {
                    self.space();
                } else {
                    self.none();
                }
                self.expr(&unary.argument);
            }
            Expression::UpdateExpression(update) => {
                if update.prefix {
                    self.emit_until(update.argument.span().start);
                    self.none();
                    self.simple_target(&update.argument);
                } else {
                    self.simple_target(&update.argument);
                    self.none();
                    self.emit_until(span.end);
                }
            }
            Expression::BinaryExpression(_) | Expression::LogicalExpression(_) => {
                self.binary(expression, false)
            }
            Expression::PrivateInExpression(private) => {
                self.emit_until(private.left.span.end);
                self.space();
                self.emit_until(private.right.span().start);
                self.space();
                self.expr(&private.right);
            }
            Expression::ConditionalExpression(conditional) => {
                self.doc.open();
                self.expr(&conditional.test);
                self.doc.indent();
                // Prettier aligns each branch under the text after `? ` and `: `.
                for branch in [&conditional.consequent, &conditional.alternate] {
                    self.line(Line::Normal);
                    self.emit_until(branch.span().start);
                    self.space();
                    self.doc.indent();
                    self.expr(branch);
                    self.doc.dedent();
                }
                self.doc.dedent();
                self.doc.close();
            }
            Expression::AssignmentExpression(assignment) => {
                self.doc.open();
                self.target(&assignment.left);
                self.space();
                self.emit_until(assignment.right.span().start);
                self.rhs(&assignment.right, false);
                self.doc.close();
            }
            Expression::SequenceExpression(sequence) => {
                self.doc.open();
                for (index, expression) in sequence.expressions.iter().enumerate() {
                    if index == 1 {
                        self.doc.indent();
                    }
                    if index > 0 {
                        self.none();
                        self.emit_until(expression.span().start);
                        self.line(Line::Normal);
                    }
                    self.expr(expression);
                }
                if sequence.expressions.len() > 1 {
                    self.doc.dedent();
                }
                self.doc.close();
            }
            Expression::ParenthesizedExpression(paren) => {
                let inner = &paren.expression;
                if breakable_in_parens(inner) {
                    self.doc.open();
                    self.emit();
                    self.doc.indent();
                    self.line(Line::Soft);
                    self.test(inner);
                    self.doc.dedent();
                    self.line(Line::Soft);
                    self.emit_until(span.end);
                    self.doc.close();
                } else {
                    self.emit();
                    self.none();
                    self.expr(inner);
                    self.none();
                    self.emit_until(span.end);
                }
            }
            Expression::AwaitExpression(await_expression) => {
                self.emit();
                self.space();
                self.expr(&await_expression.argument);
            }
            Expression::YieldExpression(yield_expression) => {
                self.emit();
                if yield_expression.delegate {
                    self.none();
                    self.emit();
                }
                if let Some(argument) = &yield_expression.argument {
                    self.space();
                    self.expr(argument);
                }
            }
            Expression::ImportExpression(import) => {
                self.emit();
                self.emit_before_paren(span.end);
                self.none();
                let mut arguments: Vec<&Expression> = vec![&import.source];
                if let Some(options) = &import.options {
                    arguments.push(options);
                }
                let starts: Vec<u32> = arguments
                    .iter()
                    .map(|argument| argument.span().start)
                    .collect();
                self.list(span.end, false, &starts, None, false, |layout, index| {
                    layout.expr(arguments[index]);
                });
            }
            _ => (),
        }
        self.emit_until(span.end);
    }

    fn template(&mut self, template: &TemplateLiteral) {
        for expression in &template.expressions {
            self.emit_until(expression.span().start);
            self.none();
            self.expr(expression);
            self.none();
        }
        self.emit_until(template.span.end);
    }

    fn element(&mut self, element: &ArrayExpressionElement) {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => self.spread(spread),
            ArrayExpressionElement::Elision(_) => (),
            _ => {
                if let Some(expression) = element.as_expression() {
                    self.expr(expression);
                }
            }
        }
    }

    fn spread(&mut self, spread: &SpreadElement) {
        self.emit_until(spread.argument.span().start);
        self.none();
        self.expr(&spread.argument);
    }

    fn argument(&mut self, argument: &Argument) {
        match argument {
            Argument::SpreadElement(spread) => self.spread(spread),
            _ => {
                if let Some(expression) = argument.as_expression() {
                    self.expr(expression);
                }
            }
        }
    }

    fn object(&mut self, object: &ObjectExpression) {
        let starts: Vec<u32> = object
            .properties
            .iter()
            .map(|property| property.span().start)
            .collect();
        // Prettier keeps an object expanded when its first key starts a new line.
        let expand = starts.first().is_some_and(|first| {
            self.source[object.span.start as usize..*first as usize].contains('\n')
        });
        self.list(
            object.span.end,
            true,
            &starts,
            None,
            expand,
            |layout, index| match &object.properties[index] {
                ObjectPropertyKind::ObjectProperty(property) => layout.property(property),
                ObjectPropertyKind::SpreadProperty(spread) => layout.spread(spread),
            },
        );
    }

    fn property(&mut self, property: &ObjectProperty) {
        if property.shorthand {
            self.expr(&property.value);
            return;
        }
        if property.method || property.kind != PropertyKind::Init {
            self.modifiers(property.key.span().start, property.computed);
            self.key(&property.key, property.computed);
            if let Expression::FunctionExpression(function) = &property.value {
                self.none();
                self.emit_until(function.params.span.start);
                self.none();
                self.function_tail(function);
            } else {
                self.expr(&property.value);
            }
            return;
        }
        self.key(&property.key, property.computed);
        self.none();
        self.emit_until(property.value.span().start);
        let short = !property.computed && property.key.span().size() <= 2;
        self.rhs(&property.value, short);
    }

    fn call(&mut self, call: &CallExpression) {
        if self.member_chain(call) {
            return;
        }
        self.expr(&call.callee);
        self.emit_before_paren(call.span.end);
        self.arguments(call.span.end, &call.arguments);
    }

    /// Optional chaining and type arguments before `(`.
    fn emit_before_paren(&mut self, end: u32) {
        while self
            .peek()
            .is_some_and(|token| token.kind() != Kind::LParen && token.start() < end)
        {
            self.none();
            self.emit();
        }
        self.none();
    }

    fn arguments(&mut self, end: u32, arguments: &[Argument]) {
        let starts: Vec<u32> = arguments
            .iter()
            .map(|argument| argument.span().start)
            .collect();
        let hug = hug_argument(arguments);
        self.none();
        self.list(end, false, &starts, hug, false, |layout, index| {
            layout.argument(&arguments[index]);
        });
    }

    fn member(&mut self, member: &MemberExpression) {
        self.expr(member.object());
        self.member_link(member);
    }

    fn member_link(&mut self, member: &MemberExpression) {
        match member {
            MemberExpression::ComputedMemberExpression(computed) => {
                self.none();
                self.emit_until(computed.expression.span().start);
                self.none();
                self.expr(&computed.expression);
                self.none();
                self.emit_until(computed.span.end);
            }
            MemberExpression::StaticMemberExpression(member) => {
                self.none();
                self.emit_until(member.property.span.start);
                self.none();
                self.emit_until(member.span.end);
            }
            MemberExpression::PrivateFieldExpression(member) => {
                self.none();
                self.emit_until(member.field.span.start);
                self.none();
                self.emit_until(member.span.end);
            }
        }
    }

    /// Prettier's member chain: `head.a().b().c()` breaks before each call group.
    fn member_chain(&mut self, call: &CallExpression) -> bool {
        enum Link<'x, 'a> {
            Call(&'x CallExpression<'a>),
            Member(&'x MemberExpression<'a>),
        }
        let mut links = vec![Link::Call(call)];
        let mut current = &call.callee;
        loop {
            if let Some(member) = current.as_member_expression() {
                links.push(Link::Member(member));
                current = member.object();
            } else if let Expression::CallExpression(inner) = current {
                links.push(Link::Call(inner));
                current = &inner.callee;
            } else {
                break;
            }
        }
        links.reverse();
        // The head keeps its own calls and computed accesses: `$(x)` or `a[0]`.
        let mut first = 0;
        while let Some(link) = links.get(first) {
            match link {
                Link::Call(_) => first += 1,
                Link::Member(MemberExpression::ComputedMemberExpression(_)) => first += 1,
                Link::Member(_) => break,
            }
        }
        let mut groups: Vec<std::ops::Range<usize>> = Vec::new();
        let mut index = first;
        while index < links.len() {
            let start = index;
            index += 1;
            while let Some(link) = links.get(index) {
                match link {
                    Link::Call(_) | Link::Member(MemberExpression::ComputedMemberExpression(_)) => {
                        index += 1
                    }
                    Link::Member(_) => break,
                }
            }
            groups.push(start..index);
        }
        let calls: Vec<&CallExpression> = links
            .iter()
            .filter_map(|link| match link {
                Link::Call(call) => Some(*call),
                Link::Member(_) => None,
            })
            .collect();
        let merge = first == 0
            && match current {
                Expression::ThisExpression(_) => true,
                Expression::Identifier(identifier) => {
                    let name = identifier.name.as_str();
                    name.len() <= 2
                        || name.starts_with(|c: char| c.is_ascii_uppercase())
                        || name.chars().all(|c| c == '$' || c == '_')
                }
                _ => false,
            };
        let cutoff = if merge { 3 } else { 2 };
        if groups.len() <= cutoff || calls.len() < 3 {
            return false;
        }
        let complex = calls.iter().any(|call| {
            call.arguments.iter().any(|argument| {
                matches!(
                    argument,
                    Argument::FunctionExpression(_) | Argument::ArrowFunctionExpression(_)
                )
            })
        });
        self.doc.open();
        if complex {
            self.doc.force_break();
        }
        self.expr(current);
        let print = |layout: &mut Self, link: &Link| match link {
            Link::Call(call) => {
                layout.emit_before_paren(call.span.end);
                layout.arguments(call.span.end, &call.arguments);
            }
            Link::Member(member) => layout.member_link(member),
        };
        for link in &links[..first] {
            print(self, link);
        }
        let mut groups = groups.into_iter();
        if merge && let Some(group) = groups.next() {
            for link in &links[group] {
                print(self, link);
            }
        }
        self.doc.indent();
        for group in groups {
            self.line(Line::Soft);
            for link in &links[group] {
                print(self, link);
            }
        }
        self.doc.dedent();
        self.doc.close();
        true
    }

    /// `in_test`: the enclosing parentheses own the group.
    fn binary(&mut self, expression: &Expression, in_test: bool) {
        self.chain(expression, in_test, false);
    }
    /// `flush`: the enclosing layout already indents the chain.
    fn chain(&mut self, expression: &Expression, in_test: bool, flush: bool) {
        let (Some((mut current, right)), Some(root)) =
            (binary_parts(expression), operator(expression))
        else {
            self.expr(expression);
            return;
        };
        let mut operands = vec![right];
        while let Some((left, right)) = binary_parts(current)
            && let Some(op) = operator(current)
            && flattens(root, op)
        {
            operands.push(right);
            current = left;
        }
        operands.push(current);
        operands.reverse();
        let indent = !in_test && !flush;
        if !in_test {
            self.doc.open();
        }
        self.expr(operands[0]);
        if indent {
            self.doc.indent();
        }
        for operand in &operands[1..] {
            self.space();
            self.emit_until(operand.span().start);
            self.line(Line::Normal);
            self.expr(operand);
        }
        if indent {
            self.doc.dedent();
        }
        if !in_test {
            self.doc.close();
        }
    }
    /// An expression whose enclosing layout already indents its lines.
    fn indented(&mut self, expression: &Expression) {
        match expression {
            Expression::BinaryExpression(_) | Expression::LogicalExpression(_) => {
                self.emit_until(expression.span().start);
                self.chain(expression, false, true);
                self.emit_until(expression.span().end);
            }
            _ => self.expr(expression),
        }
    }

    fn rhs(&mut self, value: &Expression, short_key: bool) {
        let layout = if short_key {
            Rhs::SameLine
        } else {
            rhs_layout(value)
        };
        match layout {
            Rhs::SameLine => {
                self.space();
                self.expr(value);
            }
            Rhs::BreakAfter => {
                self.doc.open();
                self.doc.indent();
                self.line(Line::Normal);
                self.indented(value);
                self.doc.dedent();
                self.doc.close();
            }
            Rhs::Fluid => {
                let group = self.doc.open();
                self.doc.indent();
                self.line(Line::Normal);
                self.doc.dedent();
                self.doc.close();
                self.doc.indent_if(group);
                self.expr(value);
                self.doc.dedent();
            }
        }
    }

    fn binding(&mut self, pattern: &BindingPattern) {
        let span = pattern.span();
        self.emit_until(span.start);
        match pattern {
            BindingPattern::BindingIdentifier(_) => self.emit_until(span.end),
            BindingPattern::AssignmentPattern(assignment) => {
                self.binding(&assignment.left);
                self.space();
                self.emit_until(assignment.right.span().start);
                self.space();
                self.expr(&assignment.right);
            }
            BindingPattern::ObjectPattern(object) => {
                let mut starts: Vec<u32> = object
                    .properties
                    .iter()
                    .map(|property| property.span.start)
                    .collect();
                if let Some(rest) = &object.rest {
                    starts.push(rest.span.start);
                }
                let rest = object.rest.as_deref();
                self.list(
                    span.end,
                    true,
                    &starts,
                    None,
                    false,
                    |layout, index| match object.properties.get(index) {
                        Some(property) => {
                            if property.shorthand {
                                layout.binding(&property.value);
                            } else {
                                layout.key(&property.key, property.computed);
                                layout.none();
                                layout.emit_until(property.value.span().start);
                                layout.space();
                                layout.binding(&property.value);
                            }
                        }
                        None => {
                            if let Some(rest) = rest {
                                layout.rest(rest);
                            }
                        }
                    },
                );
            }
            BindingPattern::ArrayPattern(array) => {
                let mut starts: Vec<u32> = Vec::new();
                let mut previous = array.span.start + 1;
                for element in &array.elements {
                    let start = element
                        .as_ref()
                        .map_or(previous, |element| element.span().start);
                    starts.push(start);
                    previous = element.as_ref().map_or(start, |element| element.span().end);
                }
                if let Some(rest) = &array.rest {
                    starts.push(rest.span.start);
                }
                let rest = array.rest.as_deref();
                let holes = array.elements.iter().any(Option::is_none);
                if holes {
                    // Positions of holes are only implied by commas; keep them flat.
                    self.emit_until(span.end);
                } else {
                    self.list(
                        span.end,
                        false,
                        &starts,
                        None,
                        false,
                        |layout, index| match array.elements.get(index) {
                            Some(Some(element)) => layout.binding(element),
                            Some(None) => (),
                            None => {
                                if let Some(rest) = rest {
                                    layout.rest(rest);
                                }
                            }
                        },
                    );
                }
            }
        }
        self.emit_until(span.end);
    }

    fn target(&mut self, target: &AssignmentTarget) {
        if let Some(simple) = target.as_simple_assignment_target() {
            self.simple_target(simple);
        } else {
            self.emit_until(target.span().end);
        }
    }

    fn simple_target(&mut self, target: &SimpleAssignmentTarget) {
        match target.as_member_expression() {
            Some(member) => self.member(member),
            None => self.emit_until(target.span().end),
        }
    }

    /// `(a, b)`, `[a, b]` or `{ a, b }`: flat when it fits, else one item per line.
    fn list(
        &mut self,
        end: u32,
        spaced: bool,
        starts: &[u32],
        hug: Option<usize>,
        expand: bool,
        mut each: impl FnMut(&mut Self, usize),
    ) {
        self.doc.open();
        if expand {
            self.doc.force_break();
        }
        let opener = self.peek().map_or(end, |token| token.start());
        let commented = spaced && self.comment_within(oxc_span::Span::new(opener, end));
        self.emit();
        if starts.is_empty() && commented {
            self.doc.indent();
            self.hard(false);
            self.leading_comments(end.saturating_sub(1));
            self.doc.dedent();
            self.hard(false);
            self.emit_until(end);
            self.doc.close();
            return;
        }
        if starts.is_empty() {
            self.none();
            self.emit_before_last(end);
            self.leading_comments(end.saturating_sub(1));
            self.none();
            self.emit_until(end);
            self.doc.close();
            return;
        }
        self.doc.indent();
        self.line(if spaced { Line::Normal } else { Line::Soft });
        let mut previous_end = None;
        for (index, start) in starts.iter().enumerate() {
            if index > 0 {
                self.none();
                self.emit_until(*start);
                let blank =
                    spaced && previous_end.is_some_and(|end| self.blank_between(end, *start));
                if blank {
                    self.hard(true);
                } else {
                    self.line(Line::Normal);
                }
            }
            if hug == Some(index) {
                self.doc.hug_next();
            }
            each(self, index);
            previous_end = Some(self.last_end);
        }
        self.none();
        self.emit_before_last(end);
        self.leading_comments(end.saturating_sub(1));
        self.doc.dedent();
        self.line(if spaced { Line::Normal } else { Line::Soft });
        self.none();
        self.emit_until(end);
        self.doc.close();
    }
}

fn same_line_body(body: &Expression) -> bool {
    matches!(
        body,
        Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::TemplateLiteral(_)
            | Expression::TaggedTemplateExpression(_)
            | Expression::ParenthesizedExpression(_)
    )
}

fn breakable_in_parens(inner: &Expression) -> bool {
    matches!(
        inner,
        Expression::BinaryExpression(_)
            | Expression::LogicalExpression(_)
            | Expression::SequenceExpression(_)
            | Expression::ConditionalExpression(_)
            | Expression::AssignmentExpression(_)
    )
}

fn binary_parts<'x, 'a>(
    expression: &'x Expression<'a>,
) -> Option<(&'x Expression<'a>, &'x Expression<'a>)> {
    match expression {
        Expression::BinaryExpression(binary) => Some((&binary.left, &binary.right)),
        Expression::LogicalExpression(logical) => Some((&logical.left, &logical.right)),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operator {
    Binary(BinaryOperator),
    Logical(LogicalOperator),
}

fn operator(expression: &Expression) -> Option<Operator> {
    match expression {
        Expression::BinaryExpression(binary) => Some(Operator::Binary(binary.operator)),
        Expression::LogicalExpression(logical) => Some(Operator::Logical(logical.operator)),
        _ => None,
    }
}

/// Prettier's `shouldFlatten`.
fn flattens(parent: Operator, child: Operator) -> bool {
    let precedence = |op: Operator| match op {
        Operator::Binary(op) => op.precedence(),
        Operator::Logical(op) => op.precedence(),
    };
    if precedence(parent) as u8 != precedence(child) as u8 {
        return false;
    }
    match (parent, child) {
        (Operator::Logical(parent), Operator::Logical(child)) => parent == child,
        (Operator::Binary(parent), Operator::Binary(child)) => {
            let group = precedence(Operator::Binary(parent));
            !matches!(group, Precedence::Exponentiation | Precedence::Equals)
                && !(parent != child && matches!(group, Precedence::Multiply | Precedence::Shift))
        }
        _ => false,
    }
}

/// A subset of Prettier's assignment layouts.
fn rhs_layout(value: &Expression) -> Rhs {
    match value {
        Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_)
        | Expression::TemplateLiteral(_)
        | Expression::TaggedTemplateExpression(_) => Rhs::SameLine,
        Expression::CallExpression(call) if call.callee.is_specific_id("require") => Rhs::SameLine,
        Expression::BinaryExpression(_) | Expression::SequenceExpression(_) => Rhs::BreakAfter,
        Expression::LogicalExpression(logical) => {
            let inline = match &logical.right {
                Expression::ObjectExpression(object) => !object.properties.is_empty(),
                Expression::ArrayExpression(array) => !array.elements.is_empty(),
                _ => false,
            };
            if inline { Rhs::Fluid } else { Rhs::BreakAfter }
        }
        Expression::ConditionalExpression(conditional)
            if matches!(
                conditional.test,
                Expression::BinaryExpression(_) | Expression::LogicalExpression(_)
            ) =>
        {
            Rhs::BreakAfter
        }
        Expression::StringLiteral(_) => Rhs::BreakAfter,
        Expression::StaticMemberExpression(member) if is_member_chain(&member.object) => {
            Rhs::BreakAfter
        }
        _ => Rhs::Fluid,
    }
}

fn is_member_chain(expression: &Expression) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => is_member_chain(&member.object),
        Expression::Identifier(_) | Expression::ThisExpression(_) => true,
        _ => false,
    }
}

/// Prettier's `shouldGroupLast` and `shouldGroupFirst`, simplified.
fn hug_argument(arguments: &[Argument]) -> Option<usize> {
    let expandable = |argument: &Argument| match argument {
        Argument::ObjectExpression(object) => !object.properties.is_empty(),
        Argument::ArrayExpression(array) => !array.elements.is_empty(),
        Argument::FunctionExpression(_) => true,
        Argument::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(_) => true,
            body => matches!(
                body.as_expression(),
                Some(
                    Expression::ObjectExpression(_)
                        | Expression::ArrayExpression(_)
                        | Expression::ArrowFunctionExpression(_)
                        | Expression::CallExpression(_)
                        | Expression::ConditionalExpression(_)
                )
            ),
        },
        _ => false,
    };
    let last = arguments.last()?;
    let penultimate = arguments
        .len()
        .checked_sub(2)
        .map(|index| &arguments[index]);
    if expandable(last)
        && penultimate.is_none_or(|penultimate| {
            std::mem::discriminant(penultimate) != std::mem::discriminant(last)
        })
    {
        return Some(arguments.len() - 1);
    }
    if let [first, second] = arguments {
        let block_function = match first {
            Argument::FunctionExpression(_) => true,
            Argument::ArrowFunctionExpression(arrow) => {
                matches!(arrow.body, ArrowFunctionBody::FunctionBody(_))
            }
            _ => false,
        };
        let simple_second = !expandable(second)
            && !matches!(
                second,
                Argument::FunctionExpression(_)
                    | Argument::ArrowFunctionExpression(_)
                    | Argument::ConditionalExpression(_)
            );
        if block_function && simple_second {
            return Some(0);
        }
    }
    None
}

fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'\\') || byte >= 0x80
}

/// Adjacent tokens that would lex differently without a space.
fn hazard(source: &str, prev: Token, next: Token) -> bool {
    let before = &source.as_bytes()[prev.start() as usize..prev.end() as usize];
    let after = &source.as_bytes()[next.start() as usize..next.end() as usize];
    let (Some(&last), Some(&first)) = (before.last(), after.first()) else {
        return false;
    };
    (word_byte(last) && word_byte(first))
        || (last == b'+' && first == b'+')
        || (last == b'-' && first == b'-')
        || (last == b'/' && matches!(first, b'/' | b'*'))
        || (prev.kind() == Kind::RegExp && word_byte(first))
        || (prev.kind() == Kind::Decimal && first == b'.' && before.iter().all(u8::is_ascii_digit))
        || (last == b'<' && first == b'!')
        || (before.ends_with(b"--") && first == b'>')
}

/// Prettier spacing between two tokens when the layout states no preference.
fn default_space(prev: Token, next: Token, prev_property: bool) -> bool {
    use Kind::*;
    let (before, after) = (prev.kind(), next.kind());
    if before == Comma && after == Comma {
        return true;
    }
    if matches!(
        after,
        RParen
            | RBrack
            | Comma
            | Semicolon
            | Dot
            | QuestionDot
            | TemplateMiddle
            | TemplateTail
            | Colon
    ) {
        return false;
    }
    if matches!(
        before,
        LParen
            | LBrack
            | Dot
            | QuestionDot
            | Dot3
            | Bang
            | Tilde
            | TemplateHead
            | TemplateMiddle
            | At
    ) {
        return false;
    }
    if before == LCurly && after == RCurly {
        return false;
    }
    if matches!(
        after,
        LParen | LBrack | NoSubstitutionTemplate | TemplateHead
    ) {
        return !(prev_property || callable_end(before));
    }
    true
}

fn callable_end(kind: Kind) -> bool {
    use Kind::*;
    matches!(
        kind,
        This | Super
            | Import
            | True
            | False
            | Null
            | RParen
            | RBrack
            | RCurly
            | Str
            | RegExp
            | NoSubstitutionTemplate
            | TemplateTail
            | PrivateIdentifier
    ) || kind.is_number()
        || (kind.is_identifier_name() && !kind.is_reserved_keyword())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_format::whitespace_only;

    // Shared with tools/check-source-format-ui.mjs.
    const SAMPLE: &str = include_str!("../../../tools/fixtures/source-format/minified.js");
    const TARGET: &str = include_str!("../../../tools/fixtures/source-format/minified.prettier.js");

    fn layout(source: &str) -> String {
        let text = format(source, source.len() * 4 + 4096).unwrap();
        assert!(whitespace_only(source, &text), "{text}");
        text
    }

    #[test]
    fn minified_sample_matches_the_prettier_target_and_is_stable() {
        assert_eq!(layout(SAMPLE), TARGET);
        assert_eq!(layout(TARGET), TARGET);
    }

    #[test]
    fn layouts_keep_tokens_comments_and_statement_boundaries() {
        let cases = [
            (
                "function g(){/* only comment */}var h={/* c */};a(/* x */b,c// tail\n);",
                "function g() {\n  /* only comment */\n}\nvar h = {\n  /* c */\n};\na(\n  /* x */ b,\n  c // tail\n);\n",
            ),
            ("a\n++b\nx=1", "a\n++b\nx = 1\n"),
            ("let d=1\n[1,2].map(x=>x)", "let d = 1[1, 2].map(x => x)\n"),
            (
                "var a=1 .toString()+-(-b)- -c+ +d;",
                "var a = 1 .toString() + -(-b) - -c + +d;\n",
            ),
            (
                "setTimeout(function(){go()},500);",
                "setTimeout(function () {\n  go()\n}, 500);\n",
            ),
            (
                "$(document).ready(function(){$('.a').addClass('b').fadeIn(200).on('click',function(){go()})});",
                "$(document).ready(function () {\n  $('.a')\n    .addClass('b')\n    .fadeIn(200)\n    .on('click', function () {\n      go()\n    })\n});\n",
            ),
            (
                "if(a)b();else c();do x++;while(y)",
                "if (a) b();\nelse c();\ndo x++;\nwhile (y)\n",
            ),
            (
                "x=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:function(){return c};",
                "x = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  ? bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n  : function () {\n      return c\n    };\n",
            ),
        ];
        for (source, expected) in cases {
            assert_eq!(layout(source), expected, "{source}");
        }
        for source in [
            "#!/usr/bin/env node\n'use strict';/*! keep */\nclass A extends B{static #p=1;constructor(x){super(x)}get v(){return this.#p}static async*g(){yield*h()}[k](){}}",
            "switch(x){case 1:case 2:f();break;default:{g()}}try{a()}catch{b()}finally{c()}",
            "outer:for(var i in o){if(i)continue outer}for(const[k,v]of m)x(k,v);for(;;){}for(i=0;;i++);",
            "const{a,b:{c},...r}=o,[x,,y=3,...z]=w;({a,b}=c);var t=`a${b+`c${d}`}`+tag`e${f}`+/re+/gi.source;",
            "export default async function(){for await(const x of y){}}export*from'm';import q,{r as s}from'n';",
        ] {
            layout(source);
        }
    }

    #[test]
    fn comments_after_the_last_token_keep_their_text_and_end_the_output() {
        let cases = [
            (
                "a;//# sourceMappingURL=app.js.map",
                "a; //# sourceMappingURL=app.js.map\n",
            ),
            (
                "a;\n//# sourceMappingURL=app.js.map\n",
                "a;\n//# sourceMappingURL=app.js.map\n",
            ),
            ("a; // tail", "a; // tail\n"),
            ("a; /* end */", "a; /* end */\n"),
            ("a;\n\n/* end */\n", "a;\n\n/* end */\n"),
            (
                "a; /* one */ /* two */ // three",
                "a; /* one */ /* two */ // three\n",
            ),
            ("// only", "// only\n"),
            ("/* only */\n", "/* only */\n"),
            ("/* one */\n\n// two\n", "/* one */\n\n// two\n"),
        ];
        for (source, expected) in cases {
            assert_eq!(layout(source), expected, "{source}");
            assert_eq!(layout(expected), expected, "{source}");
        }
    }

    #[test]
    fn broken_syntax_and_output_growth_are_refused() {
        assert_eq!(format("function(){", 1 << 20), Err(Refusal::Parse));
        assert_eq!(
            format("var a=function(){return 1}", 8),
            Err(Refusal::Output)
        );
    }
}
