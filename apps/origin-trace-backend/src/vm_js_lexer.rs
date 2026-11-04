//! One JavaScript token pass shared by the lexical analyzers that run without a
//! parser: literal masking and the parser stack admission guard.
//!
//! Comments, strings, template text and regular-expression literals are single
//! tokens; template substitutions re-enter code. A slash starts a regular
//! expression or divides according to the previous significant token, the
//! heuristic every parser-free JavaScript tokenizer uses: it divides after an
//! operand (a name, literal, `)`, `]`, an object literal's `}` or a postfix
//! `++`/`--`) and starts a literal elsewhere. Literals read where valid code
//! may also divide are marked uncertain: after a block-like `}` (a function or
//! class expression body divides) and after `await` or `yield` (identifiers in
//! scripts). An unterminated literal is read as division. Oxc remains the
//! parser; consumers that bound it must not trust these guesses alone.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `//` up to its line terminator, or `/* */` (to the end if unterminated).
    Comment,
    /// A quoted string. An unescaped line terminator ends an unterminated one.
    String,
    /// Template text: from a backtick or a substitution's closing `}` up to and
    /// including the next backtick or the `$` of `${`.
    TemplateText,
    /// A regular-expression literal with its flags; `body_end` is the closing
    /// slash. `uncertain` marks a reading where valid code may divide instead.
    Regex { body_end: usize, uncertain: bool },
    /// An identifier, keyword, number or private name.
    Word,
    /// `(`, `[`, `{` or the `{` of a template substitution.
    Open,
    /// `)`, `]` or `}`, including the `}` that resumes template text.
    Close,
    /// Any other punctuator: one byte, or `++`, `--`, `?.` and `...`.
    Punct,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

/// What a slash or a brace means after the previous significant token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Previous {
    /// A statement can start: input start, `;`, `=>`, a block's `{`, a control
    /// statement's `)`, `else`, `do`, `try` or `finally`.
    Statement,
    /// An expression operand is expected after an operator, an opening
    /// delimiter or an operator keyword.
    Operator,
    /// An operand ended; a slash divides.
    Operand,
    /// `.` or `?.`: the next word is a property name, never a keyword.
    Dot,
    /// A `}` that closed a block-like brace: a statement usually follows, but
    /// a function or class expression body can be divided.
    BlockEnd,
    /// `await` or `yield`: an operator keyword in async or generator code, but
    /// an identifier, which can be divided, in a script.
    Contextual,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    Paren { control: bool },
    Bracket,
    Block,
    Object,
    Substitution,
}

pub(crate) struct Lexer<'a> {
    bytes: &'a [u8],
    index: usize,
    previous: Previous,
    frames: Vec<Frame>,
    /// The previous token was `if`, `while`, `for`, `with`, `switch` or
    /// `catch`, so a `(` opens a control head.
    control: bool,
    /// Template text is scanned next, after a backtick or a substitution end.
    template: bool,
    /// The `{` at `index` opens the substitution template text just ended on.
    substitution: bool,
    /// A literal scan that reached a line terminator found no closing slash
    /// before this offset; slashes before it divide. This keeps the pass linear.
    regex_barrier: usize,
}

/// U+2028 and U+2029 end lines in comments and regular expressions.
fn line_separator(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&0xe2)
        && bytes.get(index + 1) == Some(&0x80)
        && matches!(bytes.get(index + 2), Some(0xa8 | 0xa9))
}

/// Byte length of whitespace or a line terminator at `index`, or zero.
fn space(bytes: &[u8], index: usize) -> usize {
    match bytes[index] {
        b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => 1,
        0xc2 if bytes.get(index + 1) == Some(&0xa0) => 2,
        0xef if bytes.get(index + 1) == Some(&0xbb) && bytes.get(index + 2) == Some(&0xbf) => 3,
        _ if line_separator(bytes, index) => 3,
        _ => 0,
    }
}

fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || byte >= 0x80
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            index: 0,
            previous: Previous::Statement,
            frames: Vec::new(),
            control: false,
            template: false,
            substitution: false,
            regex_barrier: 0,
        }
    }

    fn token(&mut self, kind: Kind, start: usize) -> Option<Token> {
        Some(Token {
            kind,
            start,
            end: self.index,
        })
    }

    fn template_text(&mut self, start: usize) -> Option<Token> {
        let bytes = self.bytes;
        self.template = false;
        while self.index < bytes.len() {
            match bytes[self.index] {
                b'\\' => self.index = (self.index + 2).min(bytes.len()),
                b'`' => {
                    self.index += 1;
                    self.previous = Previous::Operand;
                    return self.token(Kind::TemplateText, start);
                }
                b'$' if bytes.get(self.index + 1) == Some(&b'{') => {
                    self.index += 1;
                    self.substitution = true;
                    return self.token(Kind::TemplateText, start);
                }
                _ => self.index += 1,
            }
        }
        self.previous = Previous::Operand;
        self.token(Kind::TemplateText, start)
    }

    /// The closing slash of a literal starting at `start`, or `None` when a
    /// line terminator or the end comes first.
    fn regex_end(&self, start: usize) -> Option<usize> {
        let bytes = self.bytes;
        let mut index = start + 1;
        let mut class = false;
        while index < bytes.len() {
            match bytes[index] {
                b'\n' | b'\r' => return None,
                _ if line_separator(bytes, index) => return None,
                b'\\' => {
                    index += 1;
                    if index < bytes.len()
                        && (matches!(bytes[index], b'\n' | b'\r') || line_separator(bytes, index))
                    {
                        return None;
                    }
                }
                b'[' => class = true,
                b']' => class = false,
                b'/' if !class => return Some(index),
                _ => (),
            }
            index += 1;
        }
        None
    }

    fn line_end(&self, mut index: usize) -> usize {
        while index < self.bytes.len()
            && !matches!(self.bytes[index], b'\n' | b'\r')
            && !line_separator(self.bytes, index)
        {
            index += 1;
        }
        index
    }
}

impl Iterator for Lexer<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        let bytes = self.bytes;
        if self.template {
            return self.template_text(self.index);
        }
        while self.index < bytes.len() {
            match space(bytes, self.index) {
                0 => break,
                width => self.index += width,
            }
        }
        let start = self.index;
        if start == bytes.len() {
            return None;
        }
        let byte = bytes[start];
        let next = bytes.get(start + 1).copied();
        let control = std::mem::take(&mut self.control);
        if byte == b'/' && next == Some(b'/') {
            self.index = self.line_end(start + 2);
            self.control = control;
            return self.token(Kind::Comment, start);
        }
        if byte == b'/' && next == Some(b'*') {
            self.index = bytes[start + 2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .map_or(bytes.len(), |at| start + 2 + at + 2);
            self.control = control;
            return self.token(Kind::Comment, start);
        }
        if matches!(byte, b'\'' | b'"') {
            self.index += 1;
            while self.index < bytes.len() {
                match bytes[self.index] {
                    b'\n' | b'\r' => break,
                    b'\\' => {
                        self.index += 1;
                        if bytes.get(self.index) == Some(&b'\r')
                            && bytes.get(self.index + 1) == Some(&b'\n')
                        {
                            self.index += 1;
                        }
                        self.index = (self.index + 1).min(bytes.len());
                    }
                    quote if quote == byte => {
                        self.index += 1;
                        break;
                    }
                    _ => self.index += 1,
                }
            }
            self.previous = Previous::Operand;
            return self.token(Kind::String, start);
        }
        if byte == b'`' {
            self.index += 1;
            return self.template_text(start);
        }
        let regex_allowed = matches!(
            self.previous,
            Previous::Statement | Previous::Operator | Previous::BlockEnd | Previous::Contextual
        );
        if byte == b'/' && regex_allowed && start >= self.regex_barrier {
            if let Some(body_end) = self.regex_end(start) {
                self.index = body_end + 1;
                while self.index < bytes.len()
                    && (bytes[self.index].is_ascii_alphanumeric()
                        || matches!(bytes[self.index], b'_' | b'$'))
                {
                    self.index += 1;
                }
                let uncertain = matches!(self.previous, Previous::BlockEnd | Previous::Contextual);
                self.previous = Previous::Operand;
                return self.token(
                    Kind::Regex {
                        body_end,
                        uncertain,
                    },
                    start,
                );
            }
            // Valid code has no unterminated literal: this slash divides.
            self.regex_barrier = self.line_end(start);
        }
        if word_byte(byte) || (byte == b'.' && next.is_some_and(|n| n.is_ascii_digit())) {
            self.index += 1;
            while self.index < bytes.len()
                && word_byte(bytes[self.index])
                && space(bytes, self.index) == 0
            {
                self.index += 1;
            }
            let word = &bytes[start..self.index];
            if self.previous == Previous::Dot || word[0].is_ascii_digit() || word[0] == b'.' {
                self.previous = Previous::Operand;
            } else {
                // `for await (` still opens a control head.
                self.control = matches!(
                    word,
                    b"if" | b"while" | b"for" | b"with" | b"switch" | b"catch"
                ) || (control && word == b"await");
                self.previous = match word {
                    b"else" | b"do" | b"try" | b"finally" => Previous::Statement,
                    b"return" | b"throw" | b"case" | b"new" | b"typeof" | b"void" | b"delete"
                    | b"in" | b"instanceof" => Previous::Operator,
                    b"await" | b"yield" => Previous::Contextual,
                    _ if self.control => Previous::Operator,
                    _ => Previous::Operand,
                };
            }
            return self.token(Kind::Word, start);
        }
        self.index += 1;
        match byte {
            b'(' | b'[' | b'{' => {
                let frame = match byte {
                    b'(' => Frame::Paren { control },
                    b'[' => Frame::Bracket,
                    _ if std::mem::take(&mut self.substitution) => Frame::Substitution,
                    _ if matches!(self.previous, Previous::Operator | Previous::Contextual) => {
                        Frame::Object
                    }
                    _ => Frame::Block,
                };
                self.previous = if frame == Frame::Block {
                    Previous::Statement
                } else {
                    Previous::Operator
                };
                self.frames.push(frame);
                return self.token(Kind::Open, start);
            }
            b')' | b']' | b'}' => {
                self.previous = match self.frames.pop() {
                    Some(Frame::Substitution) if byte == b'}' => {
                        self.template = true;
                        Previous::Operand
                    }
                    Some(Frame::Paren { control: true }) if byte == b')' => Previous::Statement,
                    Some(Frame::Block) | None if byte == b'}' => Previous::BlockEnd,
                    _ => Previous::Operand,
                };
                return self.token(Kind::Close, start);
            }
            // A postfix update ends an operand and a prefix one precedes one,
            // so the slash reading is that of the token before it.
            b'+' | b'-' if next == Some(byte) => self.index += 1,
            b'.' if bytes.get(start + 1..start + 3) == Some(b"..") => {
                self.index += 2;
                self.previous = Previous::Operator;
            }
            b'.' => self.previous = Previous::Dot,
            b'?' if next == Some(b'.')
                && !bytes.get(start + 2).is_some_and(|n| n.is_ascii_digit()) =>
            {
                self.index += 1;
                self.previous = Previous::Dot;
            }
            b'=' if next == Some(b'>') => {
                self.index += 1;
                self.previous = Previous::Statement;
            }
            b';' => self.previous = Previous::Statement,
            _ => self.previous = Previous::Operator,
        }
        self.token(Kind::Punct, start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(Kind, &str)> {
        Lexer::new(source)
            .map(|token| (token.kind, &source[token.start..token.end]))
            .collect()
    }

    fn regexes(source: &str) -> Vec<&str> {
        Lexer::new(source)
            .filter(|token| matches!(token.kind, Kind::Regex { .. }))
            .map(|token| &source[token.start..token.end])
            .collect()
    }

    #[test]
    fn slash_reading_follows_the_previous_significant_token() {
        assert_eq!(regexes("x = /'/g; y = a / b / c;"), ["/'/g"]);
        assert_eq!(regexes("a++ / 2 / 3; b-- / 4 / 5"), Vec::<&str>::new());
        assert_eq!(regexes("x = ++/a/.lastIndex"), ["/a/"]);
        assert_eq!(regexes("f(a) / 2 / g; if (a) /x/.test(s)"), ["/x/"]);
        assert_eq!(
            regexes("x = a[0] / 2 / 3; o = {} / 2 / 3"),
            Vec::<&str>::new()
        );
        assert_eq!(
            regexes("return /a/; typeof /b/; o.return / 2 / 3"),
            ["/a/", "/b/"]
        );
        assert_eq!(regexes("x = y ? /a/ : /b/, [/c/]"), ["/a/", "/b/", "/c/"]);
        assert_eq!(regexes("/[/]/.test(s); x = 1 /* / */ / 2"), ["/[/]/"]);
        assert_eq!(regexes("x = a?.b / 2 / 3; f = () => /a/"), ["/a/"]);
        assert_eq!(regexes("\u{feff}/a/.test(s); x = 雪 / 2 / 3"), ["/a/"]);
    }

    #[test]
    fn literals_where_code_may_divide_are_marked_uncertain() {
        let source = "function f(){}\n/a/.test(s); x = {}\n/ 2; y = /b/; await /c/; yield /d/;\nfor await (x of y) /e/.test(x)";
        let flagged = Lexer::new(source)
            .filter_map(|token| match token.kind {
                Kind::Regex { uncertain, .. } => Some((&source[token.start..token.end], uncertain)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            flagged,
            [
                ("/a/", true),
                ("/b/", false),
                ("/c/", true),
                ("/d/", true),
                ("/e/", false)
            ]
        );
    }

    #[test]
    fn templates_reenter_code_in_nested_substitutions() {
        let source = "x = `a${ `b${ c / 2 }` + /}/ }d` / 2;";
        assert_eq!(
            kinds(source),
            [
                (Kind::Word, "x"),
                (Kind::Punct, "="),
                (Kind::TemplateText, "`a$"),
                (Kind::Open, "{"),
                (Kind::TemplateText, "`b$"),
                (Kind::Open, "{"),
                (Kind::Word, "c"),
                (Kind::Punct, "/"),
                (Kind::Word, "2"),
                (Kind::Close, "}"),
                (Kind::TemplateText, "`"),
                (Kind::Punct, "+"),
                (
                    Kind::Regex {
                        body_end: 27,
                        uncertain: false
                    },
                    "/}/"
                ),
                (Kind::Close, "}"),
                (Kind::TemplateText, "d`"),
                (Kind::Punct, "/"),
                (Kind::Word, "2"),
                (Kind::Punct, ";"),
            ]
        );
    }

    #[test]
    fn line_terminators_end_comments_strings_and_literals() {
        assert_eq!(
            kinds("// a\rb\u{2028}c // d\u{2029}e"),
            [
                (Kind::Comment, "// a"),
                (Kind::Word, "b"),
                (Kind::Word, "c"),
                (Kind::Comment, "// d"),
                (Kind::Word, "e"),
            ]
        );
        assert_eq!(
            kinds("'a\\\r\nb' 'c\nd"),
            [
                (Kind::String, "'a\\\r\nb'"),
                (Kind::String, "'c"),
                (Kind::Word, "d"),
            ]
        );
        // Unterminated literals divide; the rest of the line stays code.
        assert_eq!(regexes("x = /[a/ + (b) / 2\ny = /c/"), ["/c/"]);
    }

    #[test]
    fn unterminated_literal_scans_stay_linear() {
        let source = format!("{}\n", "(/[".repeat(100_000));
        let started = std::time::Instant::now();
        assert!(regexes(&source).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
