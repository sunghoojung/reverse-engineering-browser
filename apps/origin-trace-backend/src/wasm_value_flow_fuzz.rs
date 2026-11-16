//! Property test for `wasm-value-flow-v1`: a typed generator of valid modules
//! and an independent flow-sensitive reference.
//!
//! The reference tracks, for every value, the set of leaves it is built from
//! backward (`b`: params, local zero values, constants, globals, loads and
//! call results) and the set it carries forward (`f`), through locals, joins,
//! loop back edges (to a fixpoint) and same-block constant-address stores. For
//! every operand of every reachable instruction the slice's backward sources
//! must equal the reference's `b`; for every reachable constant the slice's
//! forward sinks must be exactly the consumers whose operand carries it; every
//! unreachable instruction must be refused. Each class of wrong slice found by
//! review stays caught: producer seeds that skipped the leaf rules, seeds that
//! are also their own source around a loop, sinks hidden by a source role.
//!
//! Seeds are deterministic; `REB_VALUE_FLOW_FUZZ_SEEDS` raises the count.
use crate::{wasm_def_use::Module, wasm_graph::Artifact, wasm_value_flow};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

const NLOC: usize = 5;
const DEFAULT_SEEDS: u64 = 120;
/// Seeds past the default range that each produced a node that is both ends
/// of a slice (a call or load whose result returns to its own operand around
/// a back edge); a mutation that let a source role hide a sink failed only on
/// these.
const PINNED_SEEDS: [u64; 3] = [122, 254, 281];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    /// Inclusive.
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

struct Gen {
    r: Rng,
    out: Vec<String>,
}

impl Gen {
    fn emit(&mut self, line: impl Into<String>) {
        self.out.push(line.into());
    }
    fn stmts(&mut self, labels: &[u8], depth: u32, count: Option<usize>) {
        let count = count.unwrap_or_else(|| self.r.range(1, 4) as usize);
        for _ in 0..count {
            self.stmt(labels, depth);
        }
    }
    fn with(labels: &[u8], arity: u8) -> Vec<u8> {
        let mut inner = labels.to_vec();
        inner.push(arity);
        inner
    }
    fn expr(&mut self, labels: &[u8], depth: u32) {
        let mut choices = vec!["const", "get", "get", "global"];
        if depth < 4 {
            choices.extend([
                "add", "add", "tee", "select", "load", "loadc", "call", "callg", "blockr", "ifr",
                "loopr",
            ]);
        }
        let d = depth + 1;
        match choices[self.r.below(choices.len())] {
            "const" => {
                let random = self.r.range(-50, 50);
                let value = [0, 4, 8, random][self.r.below(4)];
                self.emit(format!("i32.const {value}"));
            }
            "get" => {
                let local = self.r.below(NLOC);
                self.emit(format!("local.get {local}"));
            }
            "global" => self.emit("global.get 0"),
            "add" => {
                self.expr(labels, d);
                self.expr(labels, d);
                self.emit("i32.add");
            }
            "tee" => {
                self.expr(labels, d);
                let local = self.r.below(NLOC);
                self.emit(format!("local.tee {local}"));
            }
            "select" => {
                self.expr(labels, d);
                self.expr(labels, d);
                self.expr(labels, d);
                self.emit("select");
            }
            "load" => {
                self.expr(labels, d);
                self.emit("i32.load");
            }
            "loadc" => {
                let address = [0, 4, 8][self.r.below(3)];
                self.emit(format!("i32.const {address}"));
                self.emit("i32.load");
            }
            "call" => {
                self.expr(labels, d);
                self.emit("call 0");
            }
            "callg" => {
                self.expr(labels, d);
                self.emit("call 1");
            }
            "blockr" => {
                self.emit("block (result i32)");
                let inner = Self::with(labels, 1);
                let count = self.r.range(0, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(&inner, d);
                self.emit("end");
            }
            "ifr" => {
                self.expr(labels, d);
                self.emit("if (result i32)");
                let inner = Self::with(labels, 1);
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(&inner, d);
                self.emit("else");
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(&inner, d);
                self.emit("end");
            }
            _ => {
                self.emit("loop (result i32)");
                let inner = Self::with(labels, 0);
                let count = self.r.range(1, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(&inner, d);
                self.emit("end");
            }
        }
    }
    fn branch_value(&mut self, labels: &[u8], target: usize, depth: u32) {
        if labels[labels.len() - 1 - target] == 1 {
            self.expr(labels, depth + 1);
        }
    }
    fn stmt(&mut self, labels: &[u8], depth: u32) {
        let mut choices = vec!["set", "set", "drop", "store", "gset", "storeload"];
        if depth < 4 {
            choices.extend([
                "block", "loop", "if", "ifelse", "br", "brif", "brif", "brtable", "ret",
            ]);
        }
        let d = depth + 1;
        match choices[self.r.below(choices.len())] {
            "set" => {
                self.expr(labels, d);
                let local = self.r.below(NLOC);
                self.emit(format!("local.set {local}"));
            }
            "drop" => {
                self.expr(labels, d);
                self.emit("drop");
            }
            "store" => {
                self.expr(labels, d);
                self.expr(labels, d);
                self.emit("i32.store");
            }
            "gset" => {
                self.expr(labels, d);
                self.emit("global.set 0");
            }
            "storeload" => {
                let a = [0, 4, 8][self.r.below(3)];
                let b = if self.r.chance(0.8) {
                    a
                } else {
                    [0, 4, 8][self.r.below(3)]
                };
                self.emit(format!("i32.const {a}"));
                self.expr(labels, d);
                self.emit("i32.store");
                let k = self.r.range(0, 9);
                if k < 2 {
                    self.stmt(labels, d);
                } else if k < 3 {
                    self.emit("i32.const 4");
                    self.emit("i32.const 1");
                    self.emit("i32.store");
                }
                self.emit(format!("i32.const {b}"));
                self.emit("i32.load");
                let local = self.r.below(NLOC);
                self.emit(format!("local.set {local}"));
            }
            "block" => {
                self.emit("block");
                self.stmts(&Self::with(labels, 0), d, None);
                self.emit("end");
            }
            "loop" => {
                self.emit("loop");
                let inner = Self::with(labels, 0);
                self.stmts(&inner, d, None);
                self.expr(&inner, d);
                self.emit("br_if 0");
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.emit("end");
            }
            "if" => {
                self.expr(labels, d);
                self.emit("if");
                self.stmts(&Self::with(labels, 0), d, None);
                self.emit("end");
            }
            "ifelse" => {
                self.expr(labels, d);
                self.emit("if");
                self.stmts(&Self::with(labels, 0), d, None);
                self.emit("else");
                self.stmts(&Self::with(labels, 0), d, None);
                self.emit("end");
            }
            "br" => {
                let target = self.r.below(labels.len());
                self.branch_value(labels, target, depth);
                self.emit(format!("br {target}"));
                if self.r.chance(0.7) {
                    let count = self.r.range(1, 2) as usize;
                    self.stmts(labels, d, Some(count));
                }
            }
            "brif" => {
                let target = self.r.below(labels.len());
                self.branch_value(labels, target, depth);
                self.expr(labels, d);
                self.emit(format!("br_if {target}"));
                if labels[labels.len() - 1 - target] == 1 {
                    if self.r.chance(0.5) {
                        self.emit("drop");
                    } else {
                        let local = self.r.below(NLOC);
                        self.emit(format!("local.set {local}"));
                    }
                }
            }
            "brtable" => {
                let mut arity = self.r.below(2) as u8;
                let mut targets: Vec<usize> = (0..labels.len())
                    .filter(|target| labels[labels.len() - 1 - target] == arity)
                    .collect();
                if targets.is_empty() {
                    arity = labels[0];
                    targets = vec![labels.len() - 1];
                }
                let count = self.r.range(1, 3) as usize;
                let chosen: Vec<String> = (0..count)
                    .map(|_| targets[self.r.below(targets.len())].to_string())
                    .collect();
                if arity == 1 {
                    self.expr(labels, d);
                }
                self.expr(labels, d);
                self.emit(format!("br_table {}", chosen.join(" ")));
                if self.r.chance(0.5) {
                    self.stmts(labels, d, Some(1));
                }
            }
            _ => {
                self.expr(labels, d);
                self.emit("return");
                if self.r.chance(0.5) {
                    self.stmts(labels, d, Some(1));
                }
            }
        }
    }
}

fn generate(seed: u64) -> Vec<String> {
    let mut generator = Gen {
        r: Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0x5EED),
        out: Vec::new(),
    };
    let count = generator.r.range(2, 6) as usize;
    generator.stmts(&[1], 0, Some(count));
    generator.expr(&[1], 0);
    generator.out
}

fn module_text(body: &[String]) -> String {
    format!(
        r#"(module
  (import "env" "imp" (func (param i32) (result i32)))
  (memory 1)
  (global (mut i32) (i32.const 0))
  (func (param i32) (result i32) local.get 0)
  (func (param i32 i32) (result i32) (local i32 i32 i32)
    {}
  )
)"#,
        body.join("\n    ")
    )
}

/// A leaf of the reference: kind and instruction index (or local).
type Leaf = (&'static str, usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Prod {
    Instr(usize),
    Param(usize),
    Init(usize),
    LoopPhi(usize, usize),
    Phi(usize, usize),
}

#[derive(Clone, Debug)]
struct V {
    b: BTreeSet<Leaf>,
    f: BTreeSet<Leaf>,
    prod: Prod,
    cval: Option<i64>,
}

impl V {
    fn leaf(leaf: Leaf, prod: Prod, cval: Option<i64>) -> Self {
        Self {
            b: BTreeSet::from([leaf]),
            f: BTreeSet::from([leaf]),
            prod,
            cval,
        }
    }
    fn renamed(&self, prod: Prod) -> Self {
        Self {
            b: self.b.clone(),
            f: self.f.clone(),
            prod,
            cval: None,
        }
    }
}

fn join(values: &[V], ident: Prod) -> V {
    let mut b = BTreeSet::new();
    let mut f = BTreeSet::new();
    for value in values {
        b.extend(value.b.iter().copied());
        f.extend(value.f.iter().copied());
    }
    let same = values.iter().all(|value| value.prod == values[0].prod);
    V {
        b,
        f,
        prod: if same { values[0].prod } else { ident },
        cval: if same { values[0].cval } else { None },
    }
}

#[derive(Clone)]
struct Frame {
    kind: &'static str,
    arity: usize,
    height: usize,
    entry: Vec<V>,
    incoming: Vec<(Vec<V>, Vec<V>)>,
    reachable_at_entry: bool,
    index: usize,
    then: Option<(Vec<V>, Vec<V>)>,
}

struct Reference {
    rec: HashMap<usize, Vec<V>>,
    live: Vec<bool>,
    sinks: Vec<(usize, usize, V)>,
}

fn analyze(instrs: &[String]) -> Reference {
    let op = |i: usize| instrs[i].split_whitespace().next().unwrap_or("");
    let arg = |i: usize| -> usize {
        instrs[i]
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    };
    let mut writes: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let mut open: Vec<usize> = Vec::new();
    for i in 0..instrs.len() {
        match op(i) {
            "block" | "loop" | "if" => open.push(i),
            "end" => {
                open.pop();
            }
            "local.set" | "local.tee" => {
                for &j in &open {
                    if op(j) == "loop" {
                        writes.entry(j).or_default().insert(arg(i));
                    }
                }
            }
            _ => {}
        }
    }
    let mut back: HashMap<usize, Vec<V>> = HashMap::new();
    for _pass in 0..60 {
        let mut rec: HashMap<usize, Vec<V>> = HashMap::new();
        let mut live = vec![false; instrs.len()];
        let mut sinks = Vec::new();
        let mut changed = false;
        let mut locals: Vec<V> = (0..NLOC)
            .map(|n| {
                if n < 2 {
                    V::leaf(("param", n), Prod::Param(n), None)
                } else {
                    V::leaf(("init", n), Prod::Init(n), None)
                }
            })
            .collect();
        let mut st: Vec<V> = Vec::new();
        let mut reach = true;
        let mut store: Option<(i64, V)> = None;
        let mut frames = vec![Frame {
            kind: "func",
            arity: 1,
            height: 0,
            entry: Vec::new(),
            incoming: Vec::new(),
            reachable_at_entry: true,
            index: 0,
            then: None,
        }];
        let label_arity = |frames: &[Frame], depth: usize| {
            let frame = &frames[frames.len() - 1 - depth];
            if frame.kind == "loop" { 0 } else { frame.arity }
        };
        let top = |st: &[V], n: usize| st[st.len() - n..].to_vec();
        for i in 0..instrs.len() {
            let o = op(i);
            live[i] = reach;
            if !reach && !matches!(o, "block" | "loop" | "if" | "else" | "end") {
                continue;
            }
            if matches!(
                o,
                "block"
                    | "loop"
                    | "if"
                    | "else"
                    | "end"
                    | "br"
                    | "br_if"
                    | "br_table"
                    | "return"
                    | "call"
                    | "i32.store"
            ) {
                store = None;
            }
            let mut branch = |frames: &mut Vec<Frame>,
                              depth: usize,
                              values: Vec<V>,
                              locals: &[V],
                              sinks: &mut Vec<(usize, usize, V)>| {
                let at = frames.len() - 1 - depth;
                match frames[at].kind {
                    "func" => {
                        for (k, value) in values.into_iter().enumerate() {
                            sinks.push((i, k, value));
                        }
                    }
                    "loop" => {
                        let index = frames[at].index;
                        let current = locals.to_vec();
                        let merged: Vec<V> = match back.get(&index) {
                            None => current,
                            Some(old) => old
                                .iter()
                                .zip(&current)
                                .enumerate()
                                .map(|(n, (a, b))| {
                                    join(&[a.clone(), b.clone()], Prod::LoopPhi(index, n))
                                })
                                .collect(),
                        };
                        let differs = back.get(&index).is_none_or(|old| {
                            old.iter()
                                .zip(&merged)
                                .any(|(a, b)| a.b != b.b || a.f != b.f)
                        });
                        if differs {
                            changed = true;
                        }
                        back.insert(
                            index,
                            merged
                                .iter()
                                .enumerate()
                                .map(|(n, v)| v.renamed(Prod::LoopPhi(index, n)))
                                .collect(),
                        );
                    }
                    _ => frames[at].incoming.push((values, locals.to_vec())),
                }
            };
            match o {
                "i32.const" => {
                    let value: i64 = instrs[i]
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .parse()
                        .unwrap();
                    st.push(V::leaf(("const", i), Prod::Instr(i), Some(value)));
                }
                "local.get" => {
                    let v = locals[arg(i)].renamed(Prod::Instr(i));
                    st.push(v);
                }
                "local.set" | "local.tee" => {
                    let v = st.pop().unwrap();
                    rec.insert(i, vec![v.clone()]);
                    locals[arg(i)] = v.renamed(Prod::Instr(i));
                    if o == "local.tee" {
                        st.push(v.renamed(Prod::Instr(i)));
                    }
                }
                "global.get" => st.push(V::leaf(("global", i), Prod::Instr(i), None)),
                "global.set" | "drop" => {
                    let v = st.pop().unwrap();
                    rec.insert(i, vec![v.clone()]);
                    sinks.push((i, 0, v));
                }
                "i32.add" => {
                    let b = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    let mut sum = join(&[a.clone(), b.clone()], Prod::Instr(i));
                    sum.prod = Prod::Instr(i);
                    sum.cval = None;
                    rec.insert(i, vec![a, b]);
                    st.push(sum);
                }
                "select" => {
                    let c = st.pop().unwrap();
                    let b = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    let mut bs: BTreeSet<Leaf> = a.b.union(&b.b).copied().collect();
                    bs.extend(c.b.iter().copied());
                    let fs: BTreeSet<Leaf> = a.f.union(&b.f).copied().collect();
                    rec.insert(i, vec![a, b, c.clone()]);
                    sinks.push((i, 2, c));
                    st.push(V {
                        b: bs,
                        f: fs,
                        prod: Prod::Instr(i),
                        cval: None,
                    });
                }
                "i32.load" => {
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    let mut v = V::leaf(("load", i), Prod::Instr(i), None);
                    v.b.extend(a.b.iter().copied());
                    let mut inputs = vec![a.clone()];
                    if let (Some((address, value)), Some(cval), Prod::Instr(producer)) =
                        (&store, a.cval, a.prod)
                        && op(producer) == "i32.const"
                        && *address == cval
                    {
                        v.b.extend(value.b.iter().copied());
                        v.f.extend(value.f.iter().copied());
                        inputs.push(value.clone());
                    }
                    rec.insert(i, inputs);
                    st.push(v);
                }
                "i32.store" => {
                    let v = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    sinks.push((i, 1, v.clone()));
                    if let (Some(cval), Prod::Instr(producer)) = (a.cval, a.prod)
                        && op(producer) == "i32.const"
                    {
                        store = Some((cval, v.clone()));
                    }
                    rec.insert(i, vec![a, v]);
                }
                "call" => {
                    let a = st.pop().unwrap();
                    rec.insert(i, vec![a.clone()]);
                    sinks.push((i, 0, a));
                    st.push(V::leaf(("call", i), Prod::Instr(i), None));
                }
                "block" | "loop" | "if" => {
                    let arity = usize::from(instrs[i].contains("(result"));
                    if o == "if" && reach {
                        let c = st.pop().unwrap();
                        rec.insert(i, vec![c.clone()]);
                        sinks.push((i, 0, c));
                    }
                    frames.push(Frame {
                        kind: if o == "block" {
                            "block"
                        } else if o == "loop" {
                            "loop"
                        } else {
                            "if"
                        },
                        arity,
                        height: st.len(),
                        entry: locals.clone(),
                        incoming: Vec::new(),
                        reachable_at_entry: reach,
                        index: i,
                        then: None,
                    });
                    if o == "loop" && reach {
                        let previous = back.get(&i).cloned();
                        for &n in writes.get(&i).into_iter().flatten() {
                            let mut values = vec![locals[n].clone()];
                            if let Some(previous) = &previous {
                                values.push(previous[n].clone());
                            }
                            locals[n] =
                                join(&values, Prod::LoopPhi(i, n)).renamed(Prod::LoopPhi(i, n));
                        }
                    }
                }
                "else" => {
                    let frame = frames.last_mut().unwrap();
                    if reach {
                        frame.then = Some((top(&st, frame.arity), locals.clone()));
                    }
                    st.truncate(frame.height);
                    locals = frame.entry.clone();
                    reach = frame.reachable_at_entry;
                    frame.kind = "else";
                }
                "end" => {
                    let frame = frames.last().unwrap().clone();
                    if frame.kind == "func" {
                        if reach {
                            let values = top(&st, 1);
                            rec.insert(i, values.clone());
                            for (k, value) in values.into_iter().enumerate() {
                                sinks.push((i, k, value));
                            }
                        }
                        break;
                    }
                    frames.pop();
                    if frame.kind == "loop" {
                        if reach {
                            let values = top(&st, frame.arity);
                            st.truncate(frame.height);
                            st.extend(values.iter().cloned());
                            if !values.is_empty() {
                                rec.insert(i, values);
                            }
                        } else {
                            st.truncate(frame.height);
                        }
                        continue;
                    }
                    let mut incoming = frame.incoming.clone();
                    if let Some(then) = frame.then.clone() {
                        incoming.insert(0, then);
                    }
                    if reach {
                        incoming.push((top(&st, frame.arity), locals.clone()));
                    }
                    if frame.kind == "if" && frame.reachable_at_entry {
                        incoming.push((Vec::new(), frame.entry.clone()));
                    }
                    st.truncate(frame.height);
                    if incoming.is_empty() {
                        reach = false;
                        locals = frame.entry.clone();
                        continue;
                    }
                    reach = true;
                    if frame.arity > 0 {
                        let values: Vec<V> = incoming
                            .iter()
                            .map(|(values, _)| values[0].clone())
                            .collect();
                        let v = join(&values, Prod::Phi(i, usize::MAX));
                        st.push(v.clone());
                        rec.insert(i, vec![v]);
                    }
                    locals = (0..NLOC)
                        .map(|n| {
                            let values: Vec<V> = incoming
                                .iter()
                                .map(|(_, locals)| locals[n].clone())
                                .collect();
                            join(&values, Prod::Phi(i, n))
                        })
                        .collect();
                }
                "br" => {
                    let depth = arg(i);
                    let values = top(&st, label_arity(&frames, depth));
                    rec.insert(i, values.clone());
                    branch(&mut frames, depth, values, &locals, &mut sinks);
                    reach = false;
                    let height = frames.last().unwrap().height;
                    st.truncate(height);
                }
                "br_if" => {
                    let depth = arg(i);
                    let c = st.pop().unwrap();
                    let values = top(&st, label_arity(&frames, depth));
                    let mut inputs = values.clone();
                    inputs.push(c.clone());
                    sinks.push((i, values.len(), c));
                    rec.insert(i, inputs);
                    branch(&mut frames, depth, values, &locals, &mut sinks);
                }
                "br_table" => {
                    let targets: Vec<usize> = instrs[i]
                        .split_whitespace()
                        .skip(1)
                        .map(|t| t.parse().unwrap())
                        .collect();
                    let mut distinct = targets.clone();
                    distinct.sort_unstable();
                    distinct.dedup();
                    let c = st.pop().unwrap();
                    let values = top(&st, label_arity(&frames, *targets.last().unwrap()));
                    let mut inputs = values.clone();
                    inputs.push(c.clone());
                    sinks.push((i, values.len(), c));
                    rec.insert(i, inputs);
                    for depth in distinct {
                        branch(&mut frames, depth, values.clone(), &locals, &mut sinks);
                    }
                    reach = false;
                    let height = frames.last().unwrap().height;
                    st.truncate(height);
                }
                "return" => {
                    let values = top(&st, 1);
                    rec.insert(i, values.clone());
                    for (k, value) in values.into_iter().enumerate() {
                        sinks.push((i, k, value));
                    }
                    reach = false;
                    let height = frames.last().unwrap().height;
                    st.truncate(height);
                }
                other => panic!("unexpected {other}"),
            }
        }
        if !changed {
            return Reference { rec, live, sinks };
        }
    }
    panic!("reference did not reach a fixpoint");
}

fn leaf_of(node: &Value, index_of: &HashMap<u64, usize>) -> (String, usize) {
    let kind = node["kind"].as_str().unwrap();
    let at = |key: &str| node[key].as_u64().unwrap() as usize;
    match kind {
        "param" => ("param".into(), at("local")),
        "local_init" => ("init".into(), at("local")),
        "const" | "load" | "global_get" | "call" | "import_call" => {
            let name = match kind {
                "global_get" => "global",
                "import_call" => "call",
                other => other,
            };
            let offset = node["byte_offset"].as_u64().unwrap();
            (
                name.into(),
                index_of.get(&offset).copied().unwrap_or(usize::MAX),
            )
        }
        other => (other.into(), node["byte_offset"].as_u64().unwrap() as usize),
    }
}

#[test]
fn slices_match_a_flow_sensitive_reference_on_generated_modules() {
    let seeds: u64 = std::env::var("REB_VALUE_FLOW_FUZZ_SEEDS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(DEFAULT_SEEDS);
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut validator_features = wasmparser::WasmFeatures::all();
    validator_features.remove(wasmparser::WasmFeatures::COMPONENT_MODEL);
    let all: Vec<u64> = (0..seeds)
        .chain(PINNED_SEEDS.into_iter().filter(|seed| *seed >= seeds))
        .collect();
    for seed in all {
        let body = generate(seed);
        let text = module_text(&body);
        let bytes =
            wat::parse_str(&text).unwrap_or_else(|error| panic!("seed {seed}: {error}\n{text}"));
        wasmparser::Validator::new_with_features(validator_features)
            .validate_all(&bytes)
            .unwrap_or_else(|error| panic!("seed {seed} does not validate: {error}\n{text}"));
        let module = Module::read(&bytes).unwrap();
        let mut reader = module.bodies[1].get_operators_reader().unwrap();
        let mut offsets = Vec::new();
        while !reader.eof() {
            offsets.push(reader.read_with_offset().unwrap().1 as u64);
        }
        assert_eq!(
            offsets.len(),
            body.len() + 1,
            "seed {seed}: one instruction per line"
        );
        let index_of: HashMap<u64, usize> =
            offsets.iter().enumerate().map(|(i, o)| (*o, i)).collect();
        let mut instrs = body.clone();
        instrs.push("end".into());
        let reference = analyze(&instrs);
        let artifact = Artifact {
            bytes: bytes.clone(),
            artifact_id: Value::from("1"),
            sha256: Value::from("0".repeat(64)),
        };
        let ask = |query: String| -> Result<Value, (u16, String)> {
            let request =
                wasm_value_flow::parse_query(&format!("{query}&max_nodes=4096&max_depth=256"))
                    .unwrap();
            wasm_value_flow::value_flow_of(&artifact, &request)
                .map_err(|error| (error.status, error.message))
        };
        let expected = |set: &BTreeSet<Leaf>| -> BTreeSet<(String, usize)> {
            set.iter()
                .map(|(kind, at)| ((*kind).to_owned(), *at))
                .collect()
        };
        let mut record = |what: String,
                          document: Result<Value, (u16, String)>,
                          want: BTreeSet<(String, usize)>,
                          sinks: bool| {
            checked += 1;
            let document = match document {
                Ok(document) => document,
                Err((status, message)) => {
                    failures.push(format!("seed {seed} {what}: error {status} {message}"));
                    return;
                }
            };
            if document["truncated"]
                .as_object()
                .unwrap()
                .values()
                .any(|flag| flag == true)
            {
                failures.push(format!(
                    "seed {seed} {what}: truncated {}",
                    document["truncated"]
                ));
                return;
            }
            let ids = if sinks {
                &document["sinks"]
            } else {
                &document["sources"]
            };
            let got: BTreeSet<(String, usize)> = ids
                .as_array()
                .unwrap()
                .iter()
                .map(|id| {
                    let node = &document["nodes"][id.as_u64().unwrap() as usize];
                    if sinks {
                        let offset = node["byte_offset"].as_u64().unwrap();
                        (
                            "sink".to_owned(),
                            index_of.get(&offset).copied().unwrap_or(usize::MAX),
                        )
                    } else {
                        leaf_of(node, &index_of)
                    }
                })
                .collect();
            if got != want {
                let missing: Vec<_> = want.difference(&got).collect();
                let extra: Vec<_> = got.difference(&want).collect();
                failures.push(format!(
                    "seed {seed} {what}: missing {missing:?} extra {extra:?}"
                ));
            }
        };
        let mut dead = Vec::new();
        let mut disagreements: Vec<String> = Vec::new();
        let mut seeded: Vec<usize> = reference.rec.keys().copied().collect();
        seeded.sort_unstable();
        for i in seeded {
            let values = &reference.rec[&i];
            let name = instrs[i].split_whitespace().next().unwrap();
            if !reference.live[i] && name != "end" {
                continue;
            }
            let offset = offsets[i];
            let operands = if name == "i32.load" {
                let mut whole = BTreeSet::new();
                for value in values {
                    whole.extend(expected(&value.b));
                }
                let document = ask(format!("function=2&offset={offset}&direction=backward"));
                record(
                    format!("{} at {i} whole", instrs[i]),
                    document,
                    whole,
                    false,
                );
                1
            } else {
                values.len()
            };
            for (k, value) in values.iter().enumerate().take(operands) {
                let backward = ask(format!(
                    "function=2&offset={offset}&operand={k}&direction=backward"
                ));
                // Both directions at once must give the same sources as
                // backward alone and the same sinks as forward alone: a node
                // that is both ends of the slice keeps both.
                if let Ok(document) = &backward {
                    let both = ask(format!(
                        "function=2&offset={offset}&operand={k}&direction=both"
                    ));
                    let forward = ask(format!(
                        "function=2&offset={offset}&operand={k}&direction=forward"
                    ));
                    if let (Ok(both), Ok(forward)) = (both, forward) {
                        let ends = |document: &Value, key: &str| -> BTreeSet<(String, u64)> {
                            document[key]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|id| {
                                    let node = &document["nodes"][id.as_u64().unwrap() as usize];
                                    (
                                        node["kind"].as_str().unwrap().to_owned(),
                                        node["byte_offset"].as_u64().unwrap(),
                                    )
                                })
                                .collect()
                        };
                        if ends(&both, "sources") != ends(document, "sources")
                            || ends(&both, "sinks") != ends(&forward, "sinks")
                        {
                            disagreements.push(format!(
                                "seed {seed} {} at {i} operand {k}: both gives sources {:?} sinks {:?}, backward {:?}, forward {:?}",
                                instrs[i],
                                ends(&both, "sources"),
                                ends(&both, "sinks"),
                                ends(document, "sources"),
                                ends(&forward, "sinks")
                            ));
                        }
                    }
                }
                record(
                    format!("{} at {i} operand {k}", instrs[i]),
                    backward,
                    expected(&value.b),
                    false,
                );
            }
        }
        for i in 0..instrs.len() {
            let name = instrs[i].split_whitespace().next().unwrap();
            if name == "i32.const" && reference.live[i] {
                let want: BTreeSet<(String, usize)> = reference
                    .sinks
                    .iter()
                    .filter(|(_, _, value)| value.f.contains(&("const", i)))
                    .map(|(j, _, _)| ("sink".to_owned(), *j))
                    .collect();
                let document = ask(format!(
                    "function=2&offset={}&direction=forward",
                    offsets[i]
                ));
                record(
                    format!("{} at {i} forward", instrs[i]),
                    document,
                    want,
                    true,
                );
            }
            if !reference.live[i]
                && !matches!(
                    name,
                    "block"
                        | "loop"
                        | "if"
                        | "else"
                        | "end"
                        | "i32.const"
                        | "local.get"
                        | "global.get"
                )
            {
                dead.push(i);
            }
        }
        checked += disagreements.len();
        failures.append(&mut disagreements);
        for i in dead {
            checked += 1;
            match ask(format!(
                "function=2&offset={}&operand=0&direction=both",
                offsets[i]
            )) {
                Err((400, _)) => {}
                other => failures.push(format!(
                    "seed {seed} dead {} at {i} not refused: {:?}",
                    instrs[i],
                    other.map(|_| "document")
                )),
            }
        }
    }
    eprintln!("value-flow property: {checked} checks over {seeds} modules");
    assert!(checked > seeds as usize * 20, "only {checked} checks ran");
    assert!(
        failures.is_empty(),
        "{} of {checked} checks failed:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
