//! Finds the function a native JavaScript invocation site names
//! (protocol/native-js-invocation-v1.md), either by a dotted name bound to a
//! function or by a byte offset inside one. It reads the bounded tree-sitter
//! preflight tree, so text inside a string, template or comment can never
//! match. It reports byte offsets and syntax facts only; the caller computes
//! the site key from the verified artifact bytes and decides what to refuse.
use serde::{Deserialize, Serialize};
use tree_sitter::Node;

pub(crate) const MAX_NAME_BYTES: usize = 256;
pub(crate) const MAX_SEGMENTS: usize = 8;
const MAX_CANDIDATES: usize = 32;
const MAX_BINDING_BYTES: usize = 160;
/// In a document's main world these three name the same global object, and
/// invocation capture never arms a worker isolate, where `self` would differ.
const GLOBAL_OBJECTS: [&str; 3] = ["window", "self", "globalThis"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) operation: String,
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) byte_offset: Option<u32>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct Candidate {
    /// `function`, `arrow`, `method`, `getter`, `setter`, `generator` or
    /// `constructor`.
    pub(crate) kind: &'static str,
    /// The `(` that opens the parameter list, which is V8's start position
    /// for every kind V8 can arm at a `(`. Null for a bare-parameter arrow.
    pub(crate) anchor_byte: Option<u32>,
    pub(crate) start: u32,
    pub(crate) end: u32,
    /// The name this definition binds, as written, when it binds one.
    pub(crate) binding: Option<String>,
    /// Why V8 would not arm this function at `anchor_byte`, if it would not.
    pub(crate) unsupported: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Response {
    schema: &'static str,
    ok: bool,
    error: Option<&'static str>,
    source_bytes: usize,
    matches: Vec<Candidate>,
    match_count: usize,
    /// With no exact match: definitions whose name ends in the same segment.
    related: Vec<Candidate>,
    related_count: usize,
    selected: Option<Candidate>,
    /// Why a position names no function, when it does not.
    reason: Option<&'static str>,
}

fn response(source: &str) -> Response {
    Response {
        schema: "reb-invocation-site-worker-v1",
        ok: true,
        error: None,
        source_bytes: source.len(),
        matches: Vec::new(),
        match_count: 0,
        related: Vec::new(),
        related_count: 0,
        selected: None,
        reason: None,
    }
}

pub(crate) fn invalid(message: &'static str, source_bytes: usize) -> Response {
    Response {
        ok: false,
        error: Some(message),
        source_bytes,
        ..response("")
    }
}

/// A requested name: an optional global-object prefix and 1 to 8 segments.
struct Name {
    global: bool,
    segments: Vec<String>,
}

pub(crate) fn segment(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '$' || first == '_' || first.is_alphabetic())
        && chars.all(|c| c == '$' || c == '_' || c.is_alphanumeric())
}

fn parse_name(value: &str) -> Option<Name> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES {
        return None;
    }
    let mut segments = value.split('.').map(str::to_owned).collect::<Vec<_>>();
    if segments.len() > MAX_SEGMENTS || !segments.iter().all(|part| segment(part)) {
        return None;
    }
    let global = segments.len() > 1 && GLOBAL_OBJECTS.contains(&segments[0].as_str());
    if global {
        segments.remove(0);
    }
    Some(Name { global, segments })
}

/// What one definition binds. `global` paths are rooted at the global object;
/// the others at an identifier or, for an unbound object literal, nothing.
struct Binding {
    global: bool,
    segments: Vec<String>,
    text: String,
}

impl Binding {
    fn new(segments: Vec<String>, text: String) -> Option<Self> {
        if segments.is_empty() || segments.len() > MAX_SEGMENTS + 1 {
            return None;
        }
        let global = segments.len() > 1 && GLOBAL_OBJECTS.contains(&segments[0].as_str());
        let segments = if global {
            segments[1..].to_vec()
        } else {
            segments
        };
        Some(Self {
            global,
            segments,
            text,
        })
    }
    fn matches(&self, name: &Name) -> bool {
        self.segments == name.segments && (!name.global || self.global)
    }
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.start_byte()..node.end_byte()]
}

fn bounded(value: &str) -> String {
    let single = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if single.len() <= MAX_BINDING_BYTES {
        return single;
    }
    let mut end = MAX_BINDING_BYTES;
    while !single.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &single[..end])
}

fn has_token(node: Node, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == token)
}

fn unparenthesized(mut node: Node) -> Node {
    while let Some(parent) = node.parent() {
        if parent.kind() != "parenthesized_expression" {
            break;
        }
        node = parent;
    }
    node
}

fn is_field(parent: Node, field: &str, child: Node) -> bool {
    parent.child_by_field_name(field) == Some(child)
}

/// A property key that is a plain name. Escaped, computed, numeric and private
/// keys are not names a researcher types.
fn key(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" => Some(text(node, source).to_owned()),
        "string" => {
            let mut cursor = node.walk();
            let mut parts = node.named_children(&mut cursor);
            let fragment = parts.next()?;
            let value = text(fragment, source);
            (fragment.kind() == "string_fragment" && parts.next().is_none() && segment(value))
                .then(|| value.to_owned())
        }
        _ => None,
    }
}

/// The segments of an assignment target such as `a.b["c"]`.
fn path(node: Node, source: &str, depth: usize) -> Option<Vec<String>> {
    if depth > MAX_SEGMENTS {
        return None;
    }
    match node.kind() {
        "identifier" => Some(vec![text(node, source).to_owned()]),
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let mut inner = node.named_children(&mut cursor);
            let only = inner.next()?;
            if inner.next().is_some() {
                return None;
            }
            path(only, source, depth + 1)
        }
        "member_expression" => {
            if node.child_by_field_name("optional_chain").is_some() {
                return None;
            }
            let property = node.child_by_field_name("property")?;
            if property.kind() != "property_identifier" {
                return None;
            }
            let mut segments = path(node.child_by_field_name("object")?, source, depth + 1)?;
            segments.push(text(property, source).to_owned());
            Some(segments)
        }
        "subscript_expression" => {
            if node.child_by_field_name("optional_chain").is_some() {
                return None;
            }
            let index = key(node.child_by_field_name("index")?, source)?;
            let mut segments = path(node.child_by_field_name("object")?, source, depth + 1)?;
            segments.push(index);
            Some(segments)
        }
        _ => None,
    }
}

struct Program {
    /// A module's top-level declarations never become global properties.
    module: bool,
}

/// Whether a `var` or function declaration creates a global property: it is a
/// direct statement of a classic script.
fn top_level(statement: Node, program: &Program) -> bool {
    !program.module
        && statement
            .parent()
            .is_some_and(|parent| parent.kind() == "program")
}

/// Every name a definition binds. `holder` is the node whose parent decides
/// the binding: the function itself, or its enclosing object literal.
fn bindings_of(holder: Node, source: &str, program: &Program, depth: usize) -> Vec<Binding> {
    let mut found = Vec::new();
    if depth > MAX_SEGMENTS {
        return found;
    }
    let holder = unparenthesized(holder);
    let Some(parent) = holder.parent() else {
        return found;
    };
    match parent.kind() {
        "variable_declarator" if is_field(parent, "value", holder) => {
            let Some(name) = parent.child_by_field_name("name") else {
                return found;
            };
            if name.kind() != "identifier" {
                return found;
            }
            let value = text(name, source).to_owned();
            found.extend(Binding::new(vec![value.clone()], value.clone()));
            if let Some(declaration) = parent.parent()
                && declaration.kind() == "variable_declaration"
                && top_level(declaration, program)
            {
                found.extend(Binding::new(
                    vec!["window".into(), value.clone()],
                    format!("var {value}"),
                ));
            }
        }
        "assignment_expression" if is_field(parent, "right", holder) => {
            if let Some(left) = parent.child_by_field_name("left")
                && let Some(segments) = path(left, source, 0)
            {
                found.extend(Binding::new(segments, bounded(text(left, source))));
            }
            // `a = b = function(){}` binds both names.
            found.extend(bindings_of(parent, source, program, depth + 1));
        }
        "pair" if is_field(parent, "value", holder) => {
            if let Some(name) = parent
                .child_by_field_name("key")
                .and_then(|k| key(k, source))
            {
                found.extend(property(parent, name, source, program, depth));
            }
        }
        _ => {}
    }
    found
}

/// The bindings of an object-literal member `name`: the object's own bindings
/// extended by the key, or the bare key for an object bound to nothing.
fn property(
    member: Node,
    name: String,
    source: &str,
    program: &Program,
    depth: usize,
) -> Vec<Binding> {
    let Some(object) = member.parent().filter(|node| node.kind() == "object") else {
        return Vec::new();
    };
    let owners = bindings_of(object, source, program, depth + 1);
    if owners.is_empty() {
        return Binding::new(vec![name.clone()], name).into_iter().collect();
    }
    owners
        .into_iter()
        .filter_map(|owner| {
            let mut segments = owner.segments;
            if owner.global {
                segments.insert(0, "window".into());
            }
            segments.push(name.clone());
            Binding::new(segments, bounded(&format!("{}.{name}", owner.text)))
        })
        .collect()
}

fn function_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_expression"
            | "function_declaration"
            | "generator_function"
            | "generator_function_declaration"
            | "arrow_function"
            | "method_definition"
    )
}

fn candidate(node: Node, source: &str) -> Candidate {
    let anchor = node
        .child_by_field_name("parameters")
        .filter(|parameters| source.as_bytes().get(parameters.start_byte()) == Some(&b'('))
        .map(|parameters| parameters.start_byte() as u32);
    let (kind, unsupported) = match node.kind() {
        "function_expression" | "function_declaration" => ("function", None),
        "generator_function" | "generator_function_declaration" => ("generator", Some("generator")),
        "arrow_function" if has_token(node, "async") => ("arrow", Some("async_arrow")),
        "arrow_function" if anchor.is_none() => ("arrow", Some("arrow_bare_parameter")),
        "arrow_function" => ("arrow", None),
        _ => {
            let constructor = node.parent().is_some_and(|p| p.kind() == "class_body")
                && !has_token(node, "static")
                && node
                    .child_by_field_name("name")
                    .and_then(|name| key(name, source))
                    .as_deref()
                    == Some("constructor");
            if constructor {
                ("constructor", Some("class_constructor"))
            } else if has_token(node, "*") {
                ("generator", Some("generator"))
            } else if has_token(node, "get") {
                ("getter", None)
            } else if has_token(node, "set") {
                ("setter", None)
            } else {
                ("method", None)
            }
        }
    };
    Candidate {
        kind,
        anchor_byte: anchor,
        start: node.start_byte() as u32,
        end: node.end_byte() as u32,
        binding: None,
        unsupported: unsupported.or(anchor.is_none().then_some("no_parameter_list")),
    }
}

fn definition_bindings(node: Node, source: &str, program: &Program) -> Vec<Binding> {
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            let Some(name) = node.child_by_field_name("name") else {
                return Vec::new();
            };
            let value = text(name, source).to_owned();
            let mut found: Vec<Binding> = Binding::new(vec![value.clone()], value.clone())
                .into_iter()
                .collect();
            if top_level(node, program) {
                found.extend(Binding::new(
                    vec!["window".into(), value.clone()],
                    format!("function {value}"),
                ));
            }
            found
        }
        "method_definition" => node
            .child_by_field_name("name")
            .and_then(|name| key(name, source))
            .map(|name| property(node, name, source, program, 0))
            .unwrap_or_default(),
        _ => bindings_of(node, source, program, 0),
    }
}

/// The start of the definition a click can land on: a function's own range,
/// extended to the head that binds it (`window.hsw=`, `var hsw=`, `hsw:`).
fn definition_start(node: Node) -> usize {
    let holder = unparenthesized(node);
    match holder.parent() {
        Some(parent)
            if (parent.kind() == "variable_declarator" && is_field(parent, "value", holder))
                || (parent.kind() == "assignment_expression"
                    && is_field(parent, "right", holder))
                || (parent.kind() == "pair" && is_field(parent, "value", holder)) =>
        {
            parent.start_byte()
        }
        _ => node.start_byte(),
    }
}

fn each_function<'t>(root: Node<'t>, mut visit: impl FnMut(Node<'t>)) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if function_kind(node.kind()) {
            visit(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

pub(crate) fn analyze(request: Request) -> Response {
    let source = request.source.as_str();
    if request.operation != "invocation_site" {
        return invalid("invalid invocation site request", source.len());
    }
    if source.len() > crate::MAX_SOURCE_BYTES {
        return invalid("source exceeds the analysis byte limit", source.len());
    }
    let by_name = match (&request.name, request.byte_offset) {
        (Some(name), None) => match parse_name(name) {
            Some(name) => Some(name),
            None => {
                return invalid(
                    "name must be 1 to 8 dot-separated identifiers",
                    source.len(),
                );
            }
        },
        (None, Some(offset)) => {
            if offset as usize >= source.len() || !source.is_char_boundary(offset as usize) {
                return invalid("byte_offset is not a character in the source", source.len());
            }
            None
        }
        _ => return invalid("give exactly one of name and byte_offset", source.len()),
    };
    let tree = match crate::preflight::parse_checked(source) {
        Ok(tree) => tree,
        Err(message) => return invalid(message, source.len()),
    };
    let root = tree.root_node();
    let program = Program {
        module: {
            let mut cursor = root.walk();
            root.named_children(&mut cursor)
                .any(|child| matches!(child.kind(), "import_statement" | "export_statement"))
        },
    };
    let mut result = response(source);
    match by_name {
        Some(name) => each_function(root, |node| {
            let bindings = definition_bindings(node, source, &program);
            let last = name.segments.last();
            if let Some(binding) = bindings.iter().find(|binding| binding.matches(&name)) {
                result.match_count += 1;
                if result.matches.len() < MAX_CANDIDATES {
                    result.matches.push(Candidate {
                        binding: Some(binding.text.clone()),
                        ..candidate(node, source)
                    });
                }
            } else if let Some(binding) = bindings
                .iter()
                .find(|binding| binding.segments.last() == last)
            {
                result.related_count += 1;
                if result.related.len() < MAX_CANDIDATES {
                    result.related.push(Candidate {
                        binding: Some(binding.text.clone()),
                        ..candidate(node, source)
                    });
                }
            }
        }),
        None => {
            let offset = request.byte_offset.unwrap() as usize;
            let mut best: Option<(usize, Node)> = None;
            each_function(root, |node| {
                let start = definition_start(node);
                if start <= offset
                    && offset < node.end_byte()
                    && best.is_none_or(|(width, _)| node.end_byte() - start < width)
                {
                    best = Some((node.end_byte() - start, node));
                }
            });
            // A class field initializer or static block between the position
            // and its enclosing function is a function V8 synthesizes.
            let mut node = root.descendant_for_byte_range(offset, offset + 1);
            while let Some(current) = node {
                // Everything above the selected definition also encloses it.
                if best.is_some_and(|(_, function)| {
                    current.start_byte() <= function.start_byte()
                        && current.end_byte() >= function.end_byte()
                }) {
                    break;
                }
                if current.kind() == "class_static_block"
                    || (current.kind() == "field_definition"
                        && current
                            .child_by_field_name("value")
                            .is_some_and(|value| value.start_byte() <= offset))
                {
                    result.reason = Some("class_initializer");
                    return result;
                }
                node = current.parent();
            }
            match best {
                Some((_, function)) => {
                    result.selected = Some(Candidate {
                        binding: definition_bindings(function, source, &program)
                            .into_iter()
                            .next()
                            .map(|binding| binding.text),
                        ..candidate(function, source)
                    })
                }
                None => result.reason = Some("no_function"),
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(source: &str, name: &str) -> Response {
        analyze(Request {
            operation: "invocation_site".into(),
            source: source.into(),
            name: Some(name.into()),
            byte_offset: None,
        })
    }

    fn at(source: &str, offset: usize) -> Response {
        analyze(Request {
            operation: "invocation_site".into(),
            source: source.into(),
            name: None,
            byte_offset: Some(offset as u32),
        })
    }

    fn anchors(response: &Response) -> Vec<Option<u32>> {
        response.matches.iter().map(|c| c.anchor_byte).collect()
    }

    #[test]
    fn a_name_matches_only_definitions_that_bind_it() {
        let source = "var s='window.hsw=function(a){}';/* window.hsw=function(b){} */\
                      `${'window.hsw=function(c){}'}`;window.hsw=function(aGh,jR,qN){return aGh};";
        let response = named(source, "window.hsw");
        assert!(response.ok);
        assert_eq!(response.match_count, 1);
        assert_eq!(
            response.matches[0].anchor_byte,
            Some(source.find("(aGh").unwrap() as u32)
        );
        assert_eq!(response.matches[0].binding.as_deref(), Some("window.hsw"));
        assert_eq!(response.matches[0].kind, "function");
        assert_eq!(response.matches[0].unsupported, None);
        // The bare name and the other global objects reach the same property.
        for name in ["hsw", "self.hsw", "globalThis.hsw"] {
            assert_eq!(anchors(&named(source, name)), anchors(&response), "{name}");
        }
    }

    #[test]
    fn declarations_properties_and_chains_bind_names() {
        let source = "function hsw(a){}var api={run:function(b){},go(c){},'q':function(d){}};\
                      a.b.c=function(e){};x=y=function(f){};window['k']=function(g){};\
                      Object.assign(window,{late:function(h){}});\
                      (function(){var inner=function(i){};function hidden(j){}})();";
        let first = |name: &str| {
            let response = named(source, name);
            assert_eq!(response.match_count, 1, "{name}");
            response.matches[0].anchor_byte.unwrap() as usize
        };
        assert_eq!(&source[first("hsw")..first("hsw") + 2], "(a");
        assert_eq!(first("window.hsw"), first("hsw"));
        assert_eq!(&source[first("api.run")..][..2], "(b");
        assert_eq!(first("window.api.run"), first("api.run"));
        assert_eq!(&source[first("api.go")..][..2], "(c");
        assert_eq!(&source[first("api.q")..][..2], "(d");
        assert_eq!(&source[first("a.b.c")..][..2], "(e");
        assert_eq!(first("x"), first("y"));
        assert_eq!(&source[first("window.k")..][..2], "(g");
        assert_eq!(&source[first("late")..][..2], "(h");
        assert_eq!(&source[first("inner")..][..2], "(i");
        assert_eq!(&source[first("hidden")..][..2], "(j");
        // Function-local and object-literal names are not global properties.
        for name in [
            "window.inner",
            "window.hidden",
            "window.late",
            "window.x",
            "b.c",
        ] {
            assert_eq!(named(source, name).match_count, 0, "{name}");
        }
    }

    #[test]
    fn module_declarations_are_not_global_properties() {
        let source = "export function hsw(a){}";
        assert_eq!(named(source, "hsw").match_count, 1);
        assert_eq!(named(source, "window.hsw").match_count, 0);
        assert_eq!(named(source, "window.hsw").related_count, 1);
    }

    #[test]
    fn zero_and_several_matches_are_reported_with_their_candidates() {
        let source = "window.hsw=function(a){};if(x){window.hsw=function(b){}}hsw2=function(){}";
        let several = named(source, "window.hsw");
        assert_eq!(several.match_count, 2);
        assert_eq!(several.matches.len(), 2);
        let none = named(source, "window.hsw3");
        assert_eq!((none.match_count, none.related_count), (0, 0));
        let related = named("var o={};o.hsw=function(a){}", "window.hsw");
        assert_eq!(related.match_count, 0);
        assert_eq!(related.related_count, 1);
        assert_eq!(related.related[0].binding.as_deref(), Some("o.hsw"));
        let many = (0..40)
            .map(|_| "window.f=function(){};")
            .collect::<String>();
        let bounded = named(&many, "window.f");
        assert_eq!(
            (bounded.match_count, bounded.matches.len()),
            (40, MAX_CANDIDATES)
        );
    }

    #[test]
    fn unsupported_definitions_are_marked_not_skipped() {
        let source = "a=x=>x;b=async(y)=>y;c=function*(z){};d=async function(w){};\
                      class K{constructor(v){}get g(){return 1}static constructor(u){}}";
        let reason = |name: &str| named(source, name).matches[0].unsupported;
        assert_eq!(reason("a"), Some("arrow_bare_parameter"));
        assert_eq!(named(source, "a").matches[0].anchor_byte, None);
        assert_eq!(reason("b"), Some("async_arrow"));
        assert_eq!(reason("c"), Some("generator"));
        assert_eq!(reason("d"), None);
        let constructor = at(source, source.find("constructor(v").unwrap());
        assert_eq!(
            constructor.selected.unwrap().unsupported,
            Some("class_constructor")
        );
        let getter = at(source, source.find("return 1").unwrap())
            .selected
            .unwrap();
        assert_eq!((getter.kind, getter.unsupported), ("getter", None));
        let fake = at(source, source.find("constructor(u").unwrap())
            .selected
            .unwrap();
        assert_eq!((fake.kind, fake.unsupported), ("method", None));
    }

    #[test]
    fn a_position_selects_the_innermost_enclosing_definition() {
        let source = "(function(){window.hsw=function(aGh){return Mk().then(function(){return awb(aGh)})}})();";
        let selected = |offset: usize| at(source, offset).selected.map(|c| c.anchor_byte.unwrap());
        let hsw = source.find("(aGh)").unwrap() as u32;
        let callback = source.find("(){return awb").unwrap() as u32;
        let wrapper = source.find("(){window").unwrap() as u32;
        assert_eq!(selected(hsw as usize), Some(hsw));
        assert_eq!(selected(source.find("Mk()").unwrap()), Some(hsw));
        assert_eq!(selected(source.find("awb").unwrap()), Some(callback));
        // The binding head belongs to the function it binds, not the wrapper.
        assert_eq!(selected(source.find("window").unwrap()), Some(hsw));
        assert_eq!(selected(source.find("hsw=").unwrap()), Some(hsw));
        assert_eq!(selected(1), Some(wrapper));
        assert_eq!(
            at(source, hsw as usize)
                .selected
                .unwrap()
                .binding
                .as_deref(),
            Some("window.hsw")
        );
        assert_eq!(at(source, 0).reason, Some("no_function"));
        assert_eq!(at(source, source.len() - 1).reason, Some("no_function"));
    }

    #[test]
    fn class_initializers_are_refused_by_position() {
        let source = "function outer(){class C{x=compute();static{run()}y=function(q){}}}";
        assert_eq!(
            at(source, source.find("compute").unwrap()).reason,
            Some("class_initializer")
        );
        assert_eq!(
            at(source, source.find("run").unwrap()).reason,
            Some("class_initializer")
        );
        let inside = at(source, source.find("(q)").unwrap()).selected.unwrap();
        assert_eq!(inside.anchor_byte, Some(source.find("(q)").unwrap() as u32));
        let head = "class D{static{window.f=function(r){}}}";
        let selected = at(head, head.find("window").unwrap()).selected.unwrap();
        assert_eq!(selected.anchor_byte, Some(head.find("(r)").unwrap() as u32));
        let outer = at(source, source.find("class").unwrap()).selected.unwrap();
        assert_eq!(
            outer.anchor_byte,
            Some(source.find("(){class").unwrap() as u32)
        );
    }

    #[test]
    fn offsets_are_utf8_bytes_and_invalid_requests_are_refused() {
        let source = "var é='☃';window.hsw=function(a){}";
        let response = named(source, "hsw");
        assert_eq!(
            response.matches[0].anchor_byte,
            Some(source.find("(a)").unwrap() as u32)
        );
        assert!(!named(source, "1abc").ok);
        assert!(!named(source, "a..b").ok);
        assert!(!named(source, "a.b.c.d.e.f.g.h.i").ok);
        assert!(!named(source, &"a".repeat(MAX_NAME_BYTES + 1)).ok);
        assert!(named("var é=function(a){}", "é").match_count == 1);
        assert!(!at(source, source.len()).ok);
        assert!(!at(source, source.find('é').unwrap() + 1).ok);
        let both = analyze(Request {
            operation: "invocation_site".into(),
            source: source.into(),
            name: Some("hsw".into()),
            byte_offset: Some(0),
        });
        assert!(!both.ok);
        let malformed = named("window.hsw=function(a){", "hsw");
        assert!(!malformed.ok);
        assert!(malformed.error.unwrap().contains("preflight"));
    }
}
