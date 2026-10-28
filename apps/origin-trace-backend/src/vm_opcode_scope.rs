//! Lexical bindings of JavaScript names inside one masked dispatch region.
//!
//! The opcode-claim gate ties a recovered handler table to the indexed calls
//! that read the same binding, not merely the same spelling: a nested
//! function that declares its own `ops` dispatches a different table. This is
//! a syntactic, conservative resolver. Any binding it cannot resolve with
//! certainty (block-scoped or destructured declarations, catch parameters,
//! braceless arrow parameters, `with`, `eval`, a truncated declaration list)
//! is ambiguous, and the gate withholds the table rather than guess.
//!
//! Work is linear in the region: one bracket pass, one declaration pass, and
//! declarator scans that jump over nested brackets and stop at the next
//! statement keyword, so no byte is rescanned per declaration.

use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

/// Depth-0 bytes one declaration list may span before its scope is opaque.
const MAX_DECLARATOR_SCAN: usize = 4096;

/// `function name(` or `name(`: a parameter list that may open a scope.
static CALLABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfunction\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*\(|\b([A-Za-z_$][\w$]*)\s*\(")
        .expect("callable")
});
static DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:var|let|const)\b|\bfunction\s+([A-Za-z_$][\w$]*)").expect("declaration")
});
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*").expect("identifier"));
static TRAILING_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*\s*$").expect("trailing identifier"));
static CATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcatch\s*\(([^()]{0,1024})\)").expect("catch"));
static DYNAMIC_SCOPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:with|eval)\s*\(").expect("dynamic scope"));
/// Tokens that start a new statement and so end a declaration list.
/// `function` is absent: a function expression is a common initializer.
static STATEMENT_KEYWORDS: [&str; 11] = [
    "var", "let", "const", "return", "if", "for", "while", "do", "switch", "throw", "try",
];
/// Keywords whose parenthesized head precedes a block, not a function body.
static NOT_METHODS: [&str; 6] = ["if", "for", "while", "switch", "catch", "with"];

/// Which declaration a name at one position reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Binding {
    /// Declared nowhere in the region: one binding outside it.
    Root,
    /// Declared by the function scope with this index.
    Scope(usize),
    /// A property access such as `this.ops`; properties are not lexical.
    Property,
    /// Not resolvable with certainty.
    Ambiguous,
}

struct Scope {
    /// Signature start; parameters are in scope from here.
    start: usize,
    closing: usize,
    /// A declaration list ran past the scan bound, so this scope may declare
    /// names that were never seen.
    opaque: bool,
}

pub(super) struct Scopes<'a> {
    region: &'a [u8],
    scopes: Vec<Scope>,
    /// Name to (declaring scope, declaration is ambiguous).
    declared: BTreeMap<String, Vec<(usize, bool)>>,
    ambiguous: BTreeSet<String>,
    dynamic: bool,
}

impl<'a> Scopes<'a> {
    /// `region` is masked JavaScript: literals and comments are blank.
    pub(super) fn new(region: &'a str) -> Self {
        let bytes = region.as_bytes();
        let pairs = bracket_pairs(bytes);
        let close = |opening: usize| {
            pairs
                .binary_search_by_key(&opening, |(open, _)| *open)
                .ok()
                .map(|index| pairs[index].1)
        };
        let open_of = {
            let mut by_close = pairs
                .iter()
                .map(|(open, shut)| (*shut, *open))
                .collect::<Vec<_>>();
            by_close.sort_unstable();
            by_close
        };
        let next_byte = |from: usize| {
            (from..bytes.len())
                .find(|index| !bytes[*index].is_ascii_whitespace())
                .map(|index| (index, bytes[index]))
        };
        // Function scopes keyed by their opening brace, with parameter text.
        // A parameter list is found by bracket matching, so destructured and
        // defaulted parameters never hide a function.
        let mut signatures = BTreeMap::<usize, (usize, String)>::new();
        let mut braceless_parameters = Vec::new();
        for captures in CALLABLE.captures_iter(region) {
            let whole = captures.get(0).expect("callable");
            if captures.get(1).is_some_and(|name| {
                NOT_METHODS.contains(&name.as_str()) || name.as_str() == "function"
            }) {
                continue;
            }
            let Some(shut) = close(whole.end() - 1) else {
                continue;
            };
            if let Some((opening, b'{')) = next_byte(shut + 1) {
                signatures
                    .entry(opening)
                    .or_insert_with(|| (whole.start(), region[whole.end()..shut].to_owned()));
            }
        }
        for arrow in region.match_indices("=>").map(|(at, _)| at) {
            let before = bytes[..arrow]
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace());
            let (start, params) = match before.map(|at| (at, bytes[at])) {
                Some((shut, b')')) => {
                    let Ok(index) = open_of.binary_search_by_key(&shut, |(close, _)| *close) else {
                        continue;
                    };
                    let open = open_of[index].1;
                    (open, region[open + 1..shut].to_owned())
                }
                Some((end, _)) => {
                    let from = region.ceil_char_boundary(end.saturating_sub(255));
                    let until = region.ceil_char_boundary(end + 1);
                    match TRAILING_IDENTIFIER.find(&region[from..until]) {
                        Some(name) => (from + name.start(), name.as_str().trim().to_owned()),
                        None => continue,
                    }
                }
                None => continue,
            };
            match next_byte(arrow + 2) {
                Some((opening, b'{')) => {
                    signatures.entry(opening).or_insert((start, params));
                }
                _ => braceless_parameters.push(params),
            }
        }
        let mut scopes = Vec::new();
        let mut scope_of = BTreeMap::new();
        for (opening, (start, _)) in &signatures {
            if let Some(closing) = close(*opening) {
                scope_of.insert(*opening, scopes.len());
                scopes.push(Scope {
                    start: *start,
                    closing,
                    opaque: false,
                });
            }
        }
        let mut this = Self {
            region: bytes,
            scopes,
            declared: BTreeMap::new(),
            ambiguous: BTreeSet::new(),
            dynamic: DYNAMIC_SCOPE.is_match(region),
        };
        for (opening, (_, params)) in &signatures {
            if let Some(&scope) = scope_of.get(opening) {
                this.declare_list(params, scope, false);
            }
        }
        for captures in CATCH.captures_iter(region) {
            this.ambiguous_identifiers(&captures[1]);
        }
        // A braceless arrow body has no extent here, so its parameters may
        // shadow any use.
        for params in &braceless_parameters {
            this.ambiguous_identifiers(params);
        }
        // One pass over the brackets: at each declaration, the innermost
        // open function scope declares it, and any bracket opened inside
        // that scope makes a block-scoped declaration ambiguous.
        let mut stack: Vec<Option<usize>> = Vec::new();
        let mut declarations = DECLARATION.captures_iter(region).peekable();
        for (index, byte) in bytes.iter().enumerate() {
            while let Some(captures) = declarations.peek() {
                let found = captures.get(0).expect("declaration");
                if found.start() != index {
                    if found.start() < index {
                        declarations.next();
                        continue;
                    }
                    break;
                }
                let depth = stack.iter().rposition(Option::is_some);
                let scope = depth.and_then(|depth| stack[depth]);
                let nested = depth.map_or(!stack.is_empty(), |depth| depth + 1 < stack.len());
                if let Some(name) = captures.get(1) {
                    this.declare(scope, name.as_str(), nested);
                } else {
                    let block_scoped = !found.as_str().starts_with("var");
                    this.declarators(found.end(), scope, block_scoped && nested, &close);
                }
                declarations.next();
            }
            match byte {
                b'{' | b'(' | b'[' => stack.push(scope_of.get(&index).copied()),
                b'}' | b')' | b']' => {
                    stack.pop();
                }
                _ => (),
            }
        }
        this
    }

    /// The declaration `name` at byte `at` of the region reads.
    pub(super) fn binding(&self, name: &str, at: usize) -> Binding {
        let before = self.region[..at.min(self.region.len())]
            .iter()
            .rev()
            .find(|byte| !byte.is_ascii_whitespace());
        if before == Some(&b'.') {
            return Binding::Property;
        }
        if self.dynamic || self.ambiguous.contains(name) {
            return Binding::Ambiguous;
        }
        let contains = |scope: &Scope| scope.start <= at && at <= scope.closing;
        let declaring = self.declared.get(name).and_then(|declarations| {
            declarations
                .iter()
                .filter(|(scope, _)| contains(&self.scopes[*scope]))
                .max_by_key(|(scope, _)| self.scopes[*scope].start)
                .copied()
        });
        let floor = declaring.map_or(0, |(scope, _)| self.scopes[scope].start);
        let hidden = self
            .scopes
            .iter()
            .any(|scope| scope.opaque && contains(scope) && scope.start >= floor);
        match declaring {
            _ if hidden => Binding::Ambiguous,
            Some((_, true)) => Binding::Ambiguous,
            Some((scope, false)) => Binding::Scope(scope),
            None => Binding::Root,
        }
    }

    fn declare(&mut self, scope: Option<usize>, name: &str, ambiguous: bool) {
        match scope {
            Some(scope) => self
                .declared
                .entry(name.to_owned())
                .or_default()
                .push((scope, ambiguous)),
            // A declaration directly in the region binds the region-level
            // name every free use reads; only a block-scoped one is unsure.
            None if ambiguous => {
                self.ambiguous.insert(name.to_owned());
            }
            None => (),
        }
    }

    fn ambiguous_identifiers(&mut self, text: &str) {
        for identifier in IDENTIFIER.find_iter(text) {
            self.ambiguous.insert(identifier.as_str().to_owned());
        }
    }

    /// Parameters: plain names declare, destructured names are ambiguous.
    fn declare_list(&mut self, text: &str, scope: usize, ambiguous: bool) {
        for parameter in split_top_level(text) {
            let parameter = parameter.trim().trim_start_matches("...").trim_start();
            if parameter.starts_with(['{', '[']) {
                let pattern = parameter.split('=').next().unwrap_or("");
                for identifier in IDENTIFIER.find_iter(pattern) {
                    self.declare(Some(scope), identifier.as_str(), true);
                }
            } else if let Some(name) = IDENTIFIER.find(parameter).filter(|m| m.start() == 0) {
                self.declare(Some(scope), name.as_str(), ambiguous);
            }
        }
    }

    /// The names one `var`, `let` or `const` list declares, from just after
    /// the keyword. Nested brackets are jumped, not rescanned.
    fn declarators(
        &mut self,
        mut at: usize,
        scope: Option<usize>,
        ambiguous: bool,
        close: &impl Fn(usize) -> Option<usize>,
    ) {
        let bytes = self.region;
        let mut expect_name = true;
        let mut scanned = 0usize;
        while at < bytes.len() {
            scanned += 1;
            if scanned > MAX_DECLARATOR_SCAN {
                match scope {
                    Some(scope) => self.scopes[scope].opaque = true,
                    None => self.dynamic = true,
                }
                return;
            }
            let byte = bytes[at];
            if byte.is_ascii_whitespace() {
                if byte == b'\n' && !expect_name && !continues(bytes, at) {
                    return;
                }
                at += 1;
                continue;
            }
            if expect_name {
                expect_name = false;
                if matches!(byte, b'{' | b'[') {
                    let Some(end) = close(at) else {
                        return;
                    };
                    let pattern = String::from_utf8_lossy(&bytes[at..end]).into_owned();
                    for identifier in IDENTIFIER.find_iter(&pattern) {
                        self.declare(scope, identifier.as_str(), true);
                    }
                    at = end + 1;
                    continue;
                }
                let tail = std::str::from_utf8(&bytes[at..(at + 256).min(bytes.len())])
                    .unwrap_or_default();
                if let Some(name) = IDENTIFIER.find(tail).filter(|m| m.start() == 0) {
                    self.declare(scope, name.as_str(), ambiguous);
                    at += name.end();
                    continue;
                }
            }
            match byte {
                b';' | b')' | b'}' | b']' => return,
                b',' => expect_name = true,
                b'{' | b'(' | b'[' => {
                    let Some(end) = close(at) else {
                        return;
                    };
                    at = end;
                }
                _ if starts_statement(bytes, at) => return,
                _ => (),
            }
            at += 1;
        }
    }
}

/// Every matched bracket pair, sorted by opening offset.
fn bracket_pairs(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    let mut stack = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' | b'(' | b'[' => stack.push((*byte, index)),
            b'}' | b')' | b']' => {
                let open = match byte {
                    b'}' => b'{',
                    b')' => b'(',
                    _ => b'[',
                };
                if stack.last().is_some_and(|(kind, _)| *kind == open) {
                    let (_, opening) = stack.pop().expect("open bracket");
                    pairs.push((opening, index));
                } else {
                    stack.clear();
                }
            }
            _ => (),
        }
    }
    pairs.sort_unstable();
    pairs
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut from = 0;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(&text[from..index]);
                from = index + 1;
            }
            _ => (),
        }
    }
    parts.push(&text[from..]);
    parts
}

/// A line break inside a declaration list continues it only beside a comma.
fn continues(bytes: &[u8], newline: usize) -> bool {
    let previous = bytes[..newline]
        .iter()
        .rev()
        .find(|byte| !byte.is_ascii_whitespace());
    let next = bytes[newline..]
        .iter()
        .take(MAX_DECLARATOR_SCAN)
        .find(|byte| !byte.is_ascii_whitespace());
    previous == Some(&b',') || next == Some(&b',')
}

fn starts_statement(bytes: &[u8], at: usize) -> bool {
    if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || b"_$.".contains(&bytes[at - 1])) {
        return false;
    }
    STATEMENT_KEYWORDS.iter().any(|keyword| {
        bytes[at..].starts_with(keyword.as_bytes())
            && bytes
                .get(at + keyword.len())
                .is_none_or(|next| !(next.is_ascii_alphanumeric() || b"_$".contains(next)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(region: &str, needle: &str, nth: usize) -> usize {
        region.match_indices(needle).nth(nth).expect("needle").0
    }

    #[test]
    fn nested_declarations_shadow_and_free_names_share_one_binding() {
        let region = "var pc=0,stack=[],ops={};function step(){var ops=[];ops[x]();}ops[y]();q[z]();function f(){q[w]();}";
        let scopes = Scopes::new(region);
        let outer = scopes.binding("ops", at(region, "ops={", 0));
        assert_eq!(outer, scopes.binding("ops", at(region, "ops[y]", 0)));
        assert_ne!(outer, scopes.binding("ops", at(region, "ops[x]", 0)));
        assert!(matches!(
            scopes.binding("ops", at(region, "ops[x]", 0)),
            Binding::Scope(_)
        ));
        assert_eq!(scopes.binding("q", at(region, "q[z]", 0)), Binding::Root);
        assert_eq!(scopes.binding("q", at(region, "q[w]", 0)), Binding::Root);
    }

    #[test]
    fn parameters_and_methods_declare() {
        let region = "var ops={};function a(ops){ops[x]();}var o={m(ops){ops[y]();}};ops[z]();";
        let scopes = Scopes::new(region);
        let outer = scopes.binding("ops", at(region, "ops[z]", 0));
        assert_eq!(outer, Binding::Root);
        assert!(matches!(
            scopes.binding("ops", at(region, "ops[x]", 0)),
            Binding::Scope(_)
        ));
        assert!(matches!(
            scopes.binding("ops", at(region, "ops[y]", 0)),
            Binding::Scope(_)
        ));
    }

    #[test]
    fn uncertain_bindings_are_ambiguous() {
        for region in [
            "var ops={};if(a){let ops=[];ops[x]();}",
            "var ops={};try{}catch(ops){ops[x]();}",
            "var ops={};list.map(ops=>ops[x]());",
            "var ops={};with(o){ops[x]();}",
            "var ops={};function f({ops}){ops[x]();}",
        ] {
            let scopes = Scopes::new(region);
            assert_eq!(
                scopes.binding("ops", at(region, "ops[x]", 0)),
                Binding::Ambiguous,
                "{region}"
            );
        }
    }

    #[test]
    fn properties_are_not_lexical_bindings() {
        let region = "this.ops={};var ops=[];this.ops[x]();";
        let scopes = Scopes::new(region);
        assert_eq!(
            scopes.binding("ops", at(region, "ops[x]", 0)),
            Binding::Property
        );
        assert_eq!(
            scopes.binding("ops", at(region, "ops={", 0)),
            Binding::Property
        );
    }

    #[test]
    fn declaration_lists_end_at_the_next_statement() {
        let region = "function h(){var a=1\nops[x]()\nvar b=f(1,2),c=[3,4],d=function(){},e\nops[y]();c[z]();e[w]();}";
        let scopes = Scopes::new(region);
        assert_eq!(
            scopes.binding("ops", at(region, "ops[x]", 0)),
            Binding::Root
        );
        assert_eq!(
            scopes.binding("ops", at(region, "ops[y]", 0)),
            Binding::Root
        );
        assert_eq!(
            scopes.binding("c", at(region, "c[z]", 0)),
            Binding::Scope(0)
        );
        assert_eq!(
            scopes.binding("e", at(region, "e[w]", 0)),
            Binding::Scope(0)
        );
    }
}
