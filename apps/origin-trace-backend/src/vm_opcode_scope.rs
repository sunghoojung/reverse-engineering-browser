//! Conservative lexical resolution for the opcode claim gate.
//!
//! Tokens retain byte spans, never partial identifiers or copied source.
//! Delimiters, scope extents and hoisted declarations are indexed once. A
//! second sweep enters/leaves scopes with a binding stack per name, resolving
//! all uses without walking their ancestors. Unsupported bindings poison only
//! their lexical extent. In particular an arrow parameter cannot shadow a
//! sibling expression. No parser dependency or executable page code is used.
use crate::vm::dispatch_shape::{Memory, Meter};
use regex::Regex;
use std::{collections::HashMap, sync::LazyLock};

static UNICODE_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[$_\p{ID_Start}][$_\u{200c}\u{200d}\p{ID_Continue}]*$")
        .expect("Unicode identifier")
});

const NONE: u32 = u32::MAX;
const AMBIGUOUS: u32 = u32::MAX - 1;
const PROPERTY: u32 = u32::MAX - 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) enum Binding {
    Root,
    Scope(usize),
    Property,
    Ambiguous,
}

#[derive(Clone, Copy)]
struct Token {
    start: u32,
    end: u32,
    mate: u32,
    binding: u32,
}

struct Scope<'a> {
    start: usize,
    end: usize,
    function: bool,
    opaque: bool,
    declarations: Vec<(&'a str, bool)>,
}

pub(super) struct Scopes<'a> {
    region: &'a str,
    tokens: Vec<Token>,
    complete: bool,
    _memory: Memory,
}

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_$\\".contains(&byte) || byte >= 128
}

impl<'a> Scopes<'a> {
    pub(super) fn new(region: &'a str, meter: &Meter) -> Self {
        let memory = Memory::new(meter);
        let mut this = Self {
            region,
            tokens: Vec::new(),
            complete: false,
            _memory: memory,
        };
        if region.len() > u32::MAX as usize || !meter.charge(region.len() as u64) {
            return this;
        }
        let bytes = region.as_bytes();
        let mut brackets = Vec::<usize>::new();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at].is_ascii_whitespace() {
                at += 1;
                continue;
            }
            let start = at;
            at += 1;
            if word(bytes[start]) {
                while at < bytes.len() && word(bytes[at]) {
                    at += 1;
                }
            } else if bytes[start..].starts_with(b"=>") {
                at += 1;
            }
            let index = this.tokens.len();
            if !this._memory.push(
                &mut this.tokens,
                Token {
                    start: start as u32,
                    end: at as u32,
                    mate: NONE,
                    binding: 0,
                },
            ) {
                return this;
            }
            match bytes[start] {
                b'(' | b'[' | b'{' => {
                    if !this._memory.push(&mut brackets, index) {
                        return this;
                    }
                }
                b')' | b']' | b'}' => {
                    let Some(open) = brackets.pop() else {
                        return this;
                    };
                    let opening = bytes[this.tokens[open].start as usize];
                    if !matches!(
                        (opening, bytes[start]),
                        (b'(', b')') | (b'[', b']') | (b'{', b'}')
                    ) {
                        return this;
                    }
                    this.tokens[open].mate = index as u32;
                    this.tokens[index].mate = open as u32;
                }
                _ => (),
            }
        }
        if !brackets.is_empty() {
            return this;
        }
        this.complete = this.resolve(meter);
        this
    }

    fn text(&self, i: usize) -> &'a str {
        self.tokens
            .get(i)
            .map_or("", |t| &self.region[t.start as usize..t.end as usize])
    }

    fn identifier(&self, i: usize) -> bool {
        let text = self.text(i);
        let name = text.as_bytes();
        if name.iter().any(|b| !b.is_ascii()) {
            return UNICODE_IDENTIFIER.is_match(text);
        }
        name.first()
            .is_some_and(|b| b.is_ascii_alphabetic() || b"_$".contains(b))
            && name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"_$".contains(b))
    }

    fn close(&self, i: usize) -> Option<usize> {
        let end = self.tokens.get(i)?.mate;
        (end != NONE && end as usize > i).then_some(end as usize)
    }

    fn resolve(&mut self, meter: &Meter) -> bool {
        let n = self.tokens.len();
        // Expression ends are suffix facts. Even thousands of nested arrows
        // share them instead of scanning the same bodies repeatedly.
        if !self._memory.keep(((n + 1) * 8) as u64) {
            return false;
        }
        let mut ends = vec![n; n + 1];
        for i in (0..n).rev() {
            if !meter.charge(1) {
                return false;
            }
            ends[i] = match self.text(i) {
                "," | ";" | ")" | "]" | "}" => i,
                "(" | "[" | "{" => ends[self.close(i).unwrap_or(i) + 1],
                _ => ends[i + 1],
            };
        }
        // A scope descriptor keyed by its first token. Function/arrow
        // signatures replace their body's ordinary block descriptor.
        let mut ranges = HashMap::<usize, Scope<'a>>::new();
        let mut bodies = HashMap::<usize, usize>::new();
        for i in 0..n {
            if !meter.charge(1) {
                return false;
            }
            let text = self.text(i);
            let mut descriptor = None;
            if text == "function" {
                let mut p = i + 1;
                if self.text(p) == "*" {
                    p += 1;
                }
                let name = self.identifier(p).then_some(p);
                if name.is_some() {
                    p += 1;
                }
                if self.text(p) == "("
                    && let Some(shut) = self.close(p)
                    && self.text(shut + 1) == "{"
                    && let Some(end) = self.close(shut + 1)
                {
                    let mut scope = Scope {
                        start: i,
                        end: end + 1,
                        function: true,
                        opaque: false,
                        declarations: vec![("arguments", true)],
                    };
                    self.parameters(p + 1, shut, &mut scope, meter);
                    if let Some(name) = name {
                        scope.declarations.push((self.text(name), true));
                    }
                    descriptor = Some((scope, shut + 1));
                } else {
                    return false;
                }
            } else if text == "=>" {
                let Some(before) = i.checked_sub(1) else {
                    return false;
                };
                let (start, from, until) = if self.text(before) == ")" {
                    let open = self.tokens[before].mate as usize;
                    (open, open + 1, before)
                } else {
                    (before, before, i)
                };
                let body = i + 1;
                let end = if self.text(body) == "{" {
                    self.close(body).map_or(n, |end| end + 1)
                } else {
                    ends[body.min(n)]
                };
                let mut scope = Scope {
                    start,
                    end,
                    function: true,
                    opaque: false,
                    declarations: Vec::new(),
                };
                self.parameters(from, until, &mut scope, meter);
                descriptor = Some((scope, if self.text(body) == "{" { body } else { n }));
            } else if text == ")" && self.text(i + 1) == "{" {
                let open = self.tokens[i].mate as usize;
                let preceding = open.checked_sub(1).map(|p| self.text(p)).unwrap_or("");
                if !["if", "for", "while", "switch", "with"].contains(&preceding)
                    && !bodies.contains_key(&(i + 1))
                    && let Some(end) = self.close(i + 1)
                {
                    let mut scope = Scope {
                        start: open,
                        end: end + 1,
                        function: preceding != "catch",
                        opaque: false,
                        declarations: Vec::new(),
                    };
                    if scope.function {
                        scope.declarations.push(("arguments", true));
                    }
                    self.parameters(open + 1, i, &mut scope, meter);
                    if preceding == "catch" {
                        for (_, uncertain) in &mut scope.declarations {
                            *uncertain = true;
                        }
                    }
                    descriptor = Some((scope, i + 1));
                }
            } else if text == "class" {
                let name = self.identifier(i + 1).then_some(i + 1);
                // Only a simple name/extends name is proved. Complex heritage
                // syntax is opaque rather than searched with an unbounded walk.
                let mut body = i + 1 + usize::from(name.is_some());
                if self.text(body) == "extends" {
                    body += 2;
                }
                if self.text(body) != "{" {
                    return false;
                }
                let Some(end) = self.close(body) else {
                    return false;
                };
                let mut scope = Scope {
                    start: i,
                    end: end + 1,
                    function: false,
                    opaque: false,
                    declarations: Vec::new(),
                };
                if let Some(name) = name {
                    scope.declarations.push((self.text(name), true));
                }
                descriptor = Some((scope, body));
            } else if text == "for" && self.text(i + 1) == "(" {
                let Some(shut) = self.close(i + 1) else {
                    return false;
                };
                let body = shut + 1;
                let end = self.close(body).filter(|_| self.text(body) == "{").map_or(
                    ends[body.min(n)] + usize::from(ends[body.min(n)] < n),
                    |end| end + 1,
                );
                descriptor = Some((
                    Scope {
                        start: i,
                        end,
                        function: false,
                        opaque: false,
                        declarations: Vec::new(),
                    },
                    if self.text(body) == "{" { body } else { n },
                ));
            }
            if let Some((scope, body)) = descriptor {
                if !self
                    ._memory
                    .keep(256 + (scope.declarations.capacity() * 24) as u64)
                {
                    return false;
                }
                bodies.insert(body, scope.start);
                ranges.insert(scope.start, scope);
            }
        }
        for i in 0..n {
            if self.text(i) == "{" && self.close(i) != Some(i + 1) && !bodies.contains_key(&i) {
                if !self._memory.keep(256) {
                    return false;
                }
                ranges.entry(i).or_insert(Scope {
                    start: i,
                    end: self.close(i).unwrap_or(n) + 1,
                    function: false,
                    opaque: false,
                    declarations: Vec::new(),
                });
            }
        }
        let mut scopes = vec![Scope {
            start: 0,
            end: n + 1,
            function: true,
            opaque: false,
            declarations: Vec::new(),
        }];
        let mut stack = vec![0usize];
        let mut functions = vec![0usize];
        for i in 0..n {
            if !meter.charge(1) {
                return false;
            }
            while scopes[*stack.last().unwrap()].end <= i {
                let scope = stack.pop().unwrap();
                if scopes[scope].function {
                    functions.pop();
                }
            }
            if let Some(scope) = ranges.remove(&i) {
                let index = scopes.len();
                if !self._memory.push(&mut stack, index) || !self._memory.push(&mut scopes, scope) {
                    return false;
                }
                if scopes[index].function && !self._memory.push(&mut functions, index) {
                    return false;
                }
            }
            let current = *stack.last().unwrap();
            self.tokens[i].binding = current as u32;
            let text = self.text(i);
            if (text == "eval" || (text == "with" && self.text(i + 1) == "("))
                && (i == 0 || self.text(i - 1) != ".")
            {
                scopes[*functions.last().unwrap()].opaque = true;
            }
            if ["var", "let", "const"].contains(&text) {
                let scope = if text == "var" {
                    *functions.last().unwrap()
                } else {
                    current
                };
                self.declarators(
                    i + 1,
                    &mut scopes[scope],
                    text != "var" && scope != 0,
                    meter,
                );
            }
            if text == "function" || text == "class" {
                let mut name = i + 1;
                if self.text(name) == "*" {
                    name += 1;
                }
                let declaration =
                    i == 0 || matches!(self.text(i - 1), ";" | "{" | "}" | "export" | "default");
                if self.identifier(name) && declaration {
                    let outer = stack.iter().rev().nth(1).copied().unwrap_or(0);
                    if !self._memory.push(
                        &mut scopes[outer].declarations,
                        (self.text(name), text == "class"),
                    ) {
                        return false;
                    }
                }
            }
        }
        if meter.exhausted() {
            return false;
        }
        // Hoisting is complete before any use is resolved. Scope enter/exit
        // events update one active stack per spelling, including opacity.
        let mut active = HashMap::<&str, Vec<u32>>::new();
        let mut stack = Vec::<usize>::new();
        let mut next = 0usize;
        let mut opaque = 0usize;
        for i in 0..n {
            if !meter.charge(1) {
                return false;
            }
            while stack.last().is_some_and(|s| scopes[*s].end <= i) {
                let s = stack.pop().unwrap();
                opaque -= usize::from(scopes[s].opaque);
                for (name, _) in scopes[s].declarations.iter().rev() {
                    active.get_mut(name).unwrap().pop();
                }
            }
            while next < scopes.len() && (next == 0 || scopes[next].start == i) {
                opaque += usize::from(scopes[next].opaque);
                for (name, uncertain) in &scopes[next].declarations {
                    if !meter.charge(name.len() as u64 + 1) || !self._memory.keep(96) {
                        return false;
                    }
                    active.entry(name).or_default().push(if *uncertain {
                        AMBIGUOUS
                    } else {
                        next as u32
                    });
                }
                stack.push(next);
                next += 1;
            }
            let name = self.text(i);
            self.tokens[i].binding =
                if opaque > 0 || (!self.identifier(i) && word(name.as_bytes()[0])) {
                    AMBIGUOUS
                } else if i > 0 && self.text(i - 1) == "." {
                    PROPERTY
                } else {
                    active
                        .get(name)
                        .and_then(|stack| stack.last())
                        .copied()
                        .unwrap_or(0)
                };
        }
        true
    }

    fn parameters(&self, mut at: usize, end: usize, scope: &mut Scope<'a>, meter: &Meter) {
        while at < end {
            if !meter.charge(1) {
                scope.opaque = true;
                return;
            }
            while self.text(at) == "." {
                at += 1;
            }
            if self.identifier(at) {
                if !self
                    ._memory
                    .push(&mut scope.declarations, (self.text(at), false))
                {
                    return;
                }
            } else {
                scope.opaque = true;
            }
            at += 1;
            while at < end && self.text(at) != "," {
                if !meter.charge(1) {
                    scope.opaque = true;
                    return;
                }
                at = self.close(at).map_or(at + 1, |end| end + 1);
            }
            at += 1;
        }
    }

    fn declarators(&self, mut at: usize, scope: &mut Scope<'a>, ambiguous: bool, meter: &Meter) {
        loop {
            if !meter.charge(1) || !self.identifier(at) {
                scope.opaque = true;
                return;
            }
            if !self
                ._memory
                .push(&mut scope.declarations, (self.text(at), ambiguous))
            {
                return;
            }
            at += 1;
            if self.text(at) == "=" {
                at += 1;
                while at < self.tokens.len() {
                    if !meter.charge(1) {
                        scope.opaque = true;
                        return;
                    }
                    if matches!(
                        self.text(at),
                        "," | ";"
                            | ")"
                            | "]"
                            | "}"
                            | "in"
                            | "of"
                            | "var"
                            | "let"
                            | "const"
                            | "return"
                            | "if"
                            | "for"
                            | "while"
                            | "do"
                            | "switch"
                            | "throw"
                            | "try"
                    ) {
                        break;
                    }
                    let previous = self.tokens[at - 1].end as usize;
                    if self.region.as_bytes()[previous..self.tokens[at].start as usize]
                        .contains(&b'\n')
                    {
                        break;
                    }
                    at = self.close(at).map_or(at + 1, |end| end + 1);
                }
            }
            if self.text(at) != "," {
                return;
            }
            at += 1;
        }
    }

    pub(super) fn binding(&self, name: &str, at: usize) -> Binding {
        if !self.complete {
            return Binding::Ambiguous;
        }
        let Ok(index) = self
            .tokens
            .binary_search_by_key(&(at as u32), |token| token.start)
        else {
            return Binding::Ambiguous;
        };
        if self.text(index) != name {
            return Binding::Ambiguous;
        }
        match self.tokens[index].binding {
            0 => Binding::Root,
            AMBIGUOUS => Binding::Ambiguous,
            PROPERTY => Binding::Property,
            scope => Binding::Scope(scope as usize - 1),
        }
    }
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
        let scopes = Scopes::new(region, &Meter::new());
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
        let scopes = Scopes::new(region, &Meter::new());
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
            "var ops={};with(o){ops[x]();}",
            "var ops={};function f({ops}){ops[x]();}",
        ] {
            let scopes = Scopes::new(region, &Meter::new());
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
        let scopes = Scopes::new(region, &Meter::new());
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
        let scopes = Scopes::new(region, &Meter::new());
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
