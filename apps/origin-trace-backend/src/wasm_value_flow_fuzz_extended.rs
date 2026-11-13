//! Extended property test for `wasm-value-flow-v1`, beside the i32 one in
//! `wasm_value_flow_fuzz.rs`: the same kind of typed generator and
//! flow-sensitive reference over typed values (i32, i64, f32, f64, funcref,
//! exnref), multi-value blocks and calls, block and loop params, try_table with
//! catch, catch_ref, catch_all and catch_all_ref, throw and throw_ref, typed
//! select, atomics and atomic.fence, bulk memory, table ops, return_call,
//! call_indirect, call_ref and deep loop nests with br_table.
//!
//! The default range keeps it to a few seconds in `make check`;
//! `REB_VALUE_FLOW_EXTENDED_FROM`/`_TO` widen it, `_LIST` runs chosen seeds.
use crate::{wasm_def_use::Module, wasm_graph::Artifact, wasm_value_flow};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

const NLOC: usize = 8;
/// The extended modules cost about a third of a second each in a debug build
/// under load; 60 keep the run near 20 s and include the fence shapes (seeds
/// 6, 11, 43 and 55 fail when a fence does not block forwarding).
const DEFAULT_EXTENDED_SEEDS: u64 = 60;

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
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ty {
    I32,
    I64,
    F32,
    F64,
}
impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::I32 => "i32",
            Ty::I64 => "i64",
            Ty::F32 => "f32",
            Ty::F64 => "f64",
        }
    }
    fn locals(self) -> &'static [usize] {
        match self {
            Ty::I32 => &[0, 1, 2, 3],
            Ty::I64 => &[4, 5],
            Ty::F32 => &[6],
            Ty::F64 => &[7],
        }
    }
}
const TYS: [Ty; 4] = [Ty::I32, Ty::I64, Ty::F32, Ty::F64];

/// Branch types of a label, as names (exnref allowed).
type Label = Vec<&'static str>;

struct Gen {
    r: Rng,
    out: Vec<String>,
    budget: usize,
}

fn types(list: &[&str]) -> String {
    list.join(" ")
}

impl Gen {
    fn emit(&mut self, line: impl Into<String>) {
        self.out.push(line.into());
    }
    fn ty(&mut self) -> Ty {
        if self.r.chance(0.55) {
            Ty::I32
        } else {
            TYS[self.r.below(4)]
        }
    }
    fn pick<T: Copy>(&mut self, list: &[T]) -> T {
        list[self.r.below(list.len())]
    }
    fn small(&self) -> bool {
        self.out.len() > self.budget
    }
    fn stmts(&mut self, labels: &[Label], depth: u32, count: Option<usize>) {
        let count = count.unwrap_or_else(|| self.r.range(1, 4) as usize);
        for _ in 0..count {
            self.stmt(labels, depth);
        }
    }
    fn with(labels: &[Label], label: Label) -> Vec<Label> {
        let mut inner = labels.to_vec();
        inner.push(label);
        inner
    }
    fn konst(&mut self, ty: Ty) {
        let random = self.r.range(-50, 50);
        let value = [0, 4, 8, random][self.r.below(4)];
        self.emit(format!("{}.const {value}", ty.name()));
    }
    fn refexpr(&mut self, labels: &[Label], depth: u32) {
        match self.r.below(3) {
            0 => self.emit("ref.func 1"),
            1 => self.emit("ref.null func"),
            _ => {
                self.expr(Ty::I32, labels, depth + 1);
                self.emit("table.get 0");
            }
        }
    }
    fn expr(&mut self, ty: Ty, labels: &[Label], depth: u32) {
        let mut choices = vec!["const", "get", "get"];
        if matches!(ty, Ty::I32 | Ty::I64) {
            choices.push("global");
        }
        if depth < 4 && !self.small() {
            choices.extend([
                "bin",
                "bin",
                "conv",
                "tee",
                "select",
                "load",
                "loadc",
                "blockr",
                "ifr",
                "loopr",
                "multi",
                "ifparam",
                "loopparam",
            ]);
            if ty == Ty::I32 {
                choices.extend([
                    "call",
                    "callg",
                    "callind",
                    "callref",
                    "atomic",
                    "refsel",
                    "trytable",
                    "blockparam",
                    "multicall",
                    "grow",
                    "tsize",
                    "aload",
                ]);
            }
            if ty == Ty::I64 {
                choices.extend(["atomic", "multicall", "narrow"]);
            }
        }
        let d = depth + 1;
        let n = ty.name();
        match self.pick(&choices) {
            "const" => self.konst(ty),
            "get" => {
                let local = self.pick(ty.locals());
                self.emit(format!("local.get {local}"));
            }
            "global" => self.emit(if ty == Ty::I32 {
                "global.get 0"
            } else {
                "global.get 1"
            }),
            "bin" => {
                self.expr(ty, labels, d);
                self.expr(ty, labels, d);
                self.emit(match ty {
                    Ty::I32 => "i32.add",
                    Ty::I64 => "i64.mul",
                    Ty::F32 => "f32.add",
                    Ty::F64 => "f64.sub",
                });
            }
            "conv" => match ty {
                Ty::I32 => match self.r.below(4) {
                    0 => {
                        self.expr(Ty::I64, labels, d);
                        self.emit("i32.wrap_i64");
                    }
                    1 => {
                        self.expr(Ty::I64, labels, d);
                        self.expr(Ty::I64, labels, d);
                        self.emit("i64.eq");
                    }
                    2 => {
                        self.expr(Ty::F32, labels, d);
                        self.expr(Ty::F32, labels, d);
                        self.emit("f32.lt");
                    }
                    _ => {
                        self.expr(Ty::I32, labels, d);
                        self.emit("i32.eqz");
                    }
                },
                Ty::I64 => {
                    self.expr(Ty::I32, labels, d);
                    self.emit("i64.extend_i32_s");
                }
                Ty::F32 => {
                    if self.r.chance(0.5) {
                        self.expr(Ty::I32, labels, d);
                        self.emit("f32.convert_i32_s");
                    } else {
                        self.expr(Ty::F64, labels, d);
                        self.emit("f32.demote_f64");
                    }
                }
                Ty::F64 => {
                    if self.r.chance(0.5) {
                        self.expr(Ty::F32, labels, d);
                        self.emit("f64.promote_f32");
                    } else {
                        self.expr(Ty::I64, labels, d);
                        self.emit("f64.convert_i64_u");
                    }
                }
            },
            "tee" => {
                self.expr(ty, labels, d);
                let local = self.pick(ty.locals());
                self.emit(format!("local.tee {local}"));
            }
            "select" => {
                self.expr(ty, labels, d);
                self.expr(ty, labels, d);
                self.expr(Ty::I32, labels, d);
                if self.r.chance(0.5) {
                    self.emit("select");
                } else {
                    self.emit(format!("select (result {n})"));
                }
            }
            "load" => {
                self.expr(Ty::I32, labels, d);
                self.emit(format!("{n}.load"));
            }
            "loadc" => {
                let address = self.pick(&[0, 4, 8]);
                self.emit(format!("i32.const {address}"));
                self.emit(format!("{n}.load"));
            }
            "narrow" => {
                let address = self.pick(&[0, 4, 8]);
                self.emit(format!("i32.const {address}"));
                self.emit("i64.load32_u");
            }
            "aload" => {
                let address = self.pick(&[0, 4, 8]);
                self.emit(format!("i32.const {address}"));
                self.emit("i32.atomic.load");
            }
            "call" => {
                self.expr(Ty::I32, labels, d);
                self.emit("call 0");
            }
            "callg" => {
                self.expr(Ty::I32, labels, d);
                self.emit("call 1");
            }
            "callind" => {
                self.expr(Ty::I32, labels, d);
                self.expr(Ty::I32, labels, d);
                self.emit("call_indirect (type 0)");
            }
            "callref" => {
                self.expr(Ty::I32, labels, d);
                self.emit("ref.func 1");
                self.emit("call_ref 0");
            }
            "multicall" => {
                // call 2: (i64 i32) -> (i32 i64)
                self.expr(Ty::I64, labels, d);
                self.expr(Ty::I32, labels, d);
                self.emit("call 2");
                if ty == Ty::I32 {
                    let local = self.pick(Ty::I64.locals());
                    self.emit(format!("local.set {local}"));
                } else {
                    // keep i64 on top: swap via local
                    self.emit("local.set 5");
                    self.emit("local.set 3");
                    self.emit("local.get 5");
                }
            }
            "atomic" => {
                self.expr(Ty::I32, labels, d);
                self.expr(ty, labels, d);
                self.emit(if ty == Ty::I32 {
                    "i32.atomic.rmw.add"
                } else {
                    "i64.atomic.rmw.xchg"
                });
            }
            "grow" => {
                self.expr(Ty::I32, labels, d);
                self.emit("memory.grow");
            }
            "tsize" => self.emit("table.size 0"),
            "refsel" => {
                self.refexpr(labels, d);
                self.refexpr(labels, d);
                self.expr(Ty::I32, labels, d);
                self.emit("select (result funcref)");
                self.emit("ref.is_null");
            }
            "blockr" => {
                self.emit(format!("block (result {n})"));
                let inner = Self::with(labels, vec![n]);
                let count = self.r.range(0, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(ty, &inner, d);
                self.emit("end");
            }
            "loopr" => {
                self.emit(format!("loop (result {n})"));
                let inner = Self::with(labels, vec![]);
                let count = self.r.range(1, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(ty, &inner, d);
                self.emit("end");
            }
            "multi" => {
                // block (result ty i32), then consume the i32.
                self.emit(format!("block (result {n} i32)"));
                let inner = Self::with(labels, vec![n, "i32"]);
                let count = self.r.range(0, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(ty, &inner, d);
                self.expr(Ty::I32, &inner, d);
                self.emit("end");
                let local = self.pick(Ty::I32.locals());
                self.emit(format!("local.set {local}"));
            }
            "blockparam" => {
                self.expr(Ty::I32, labels, d);
                self.emit("block (param i32) (result i32)");
                let inner = Self::with(labels, vec!["i32"]);
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(Ty::I32, &inner, d);
                self.emit("i32.add");
                self.emit("end");
            }
            "ifr" => {
                self.expr(Ty::I32, labels, d);
                self.emit(format!("if (result {n})"));
                let inner = Self::with(labels, vec![n]);
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(ty, &inner, d);
                self.emit("else");
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(ty, &inner, d);
                self.emit("end");
            }
            "ifparam" => {
                self.expr(ty, labels, d);
                self.expr(Ty::I32, labels, d);
                self.emit(format!("if (param {n}) (result {n})"));
                let inner = Self::with(labels, vec![n]);
                self.arm(ty, &inner, d);
                if self.r.chance(0.6) {
                    self.emit("else");
                    self.arm(ty, &inner, d);
                }
                self.emit("end");
            }
            "loopparam" => {
                self.expr(ty, labels, d);
                self.emit(format!("loop (param {n}) (result {n})"));
                let inner = Self::with(labels, vec![n]);
                self.arm(ty, &inner, d);
                self.expr(Ty::I32, &inner, d);
                self.emit("br_if 0");
                self.arm(ty, &inner, d);
                self.emit("end");
            }
            "trytable" => {
                // block (result i32) try_table (result i32) (catch 0 0) ... end end
                self.emit("block (result i32)");
                let handler = Self::with(labels, vec!["i32"]);
                let mut clauses = vec!["(catch 0 0)".to_owned()];
                self.extra_catches(&handler, &mut clauses);
                self.emit(format!("try_table (result i32) {}", clauses.join(" ")));
                let inner = Self::with(&handler, vec!["i32"]);
                let count = self.r.range(0, 3) as usize;
                self.stmts(&inner, d, Some(count));
                self.expr(Ty::I32, &inner, d);
                self.emit("end");
                self.emit("end");
            }
            other => panic!("{other}"),
        }
    }
    /// Extra catch clauses aimed at labels outside the try_table: catch_all to
    /// any label with no values (blocks, loops), catch 0 to any [i32] label
    /// (the function label too).
    fn extra_catches(&mut self, outside: &[Label], clauses: &mut Vec<String>) {
        for _ in 0..self.r.below(3) {
            let empty: Vec<usize> = (0..outside.len())
                .filter(|d| outside[outside.len() - 1 - d].is_empty())
                .collect();
            let one: Vec<usize> = (0..outside.len())
                .filter(|d| outside[outside.len() - 1 - d] == vec!["i32"])
                .collect();
            if self.r.chance(0.5) && !empty.is_empty() {
                let d = self.pick(&empty);
                clauses.push(format!("(catch_all {d})"));
            } else if !one.is_empty() {
                let d = self.pick(&one);
                clauses.push(format!("(catch 0 {d})"));
            }
        }
    }
    /// An arm that keeps one value of `ty` on the stack: identity, combine or
    /// replace.
    fn arm(&mut self, ty: Ty, labels: &[Label], depth: u32) {
        let count = self.r.range(0, 2) as usize;
        self.stmts(labels, depth, Some(count));
        match self.r.below(3) {
            0 => {}
            1 => {
                self.expr(ty, labels, depth);
                self.emit(match ty {
                    Ty::I32 => "i32.add",
                    Ty::I64 => "i64.mul",
                    Ty::F32 => "f32.add",
                    Ty::F64 => "f64.sub",
                });
            }
            _ => {
                self.emit("drop");
                self.expr(ty, labels, depth);
            }
        }
    }
    fn branch_values(&mut self, labels: &[Label], target: usize, depth: u32) {
        let label = labels[labels.len() - 1 - target].clone();
        for name in label {
            match name {
                "i32" => self.expr(Ty::I32, labels, depth + 1),
                "i64" => self.expr(Ty::I64, labels, depth + 1),
                "f32" => self.expr(Ty::F32, labels, depth + 1),
                "f64" => self.expr(Ty::F64, labels, depth + 1),
                "exnref" => self.emit("ref.null exn"),
                other => panic!("{other}"),
            }
        }
    }
    fn deep_loops(&mut self, labels: &[Label], depth: u32) {
        let levels = self.r.range(3, 6) as usize;
        let mut inner = labels.to_vec();
        for _ in 0..levels {
            self.emit("loop");
            inner.push(vec![]);
            let ty = self.ty();
            self.expr(ty, &inner, depth + 1);
            let local = self.pick(ty.locals());
            self.emit(format!("local.set {local}"));
        }
        // br_table over the loop nest, then fall out of every loop.
        let empty: Vec<usize> = (0..inner.len())
            .filter(|d| inner[inner.len() - 1 - d].is_empty())
            .collect();
        let count = self.r.range(1, 4) as usize;
        let chosen: Vec<String> = (0..count).map(|_| self.pick(&empty).to_string()).collect();
        self.expr(Ty::I32, &inner, depth + 1);
        // a conditional to avoid the br_table always running: if (...) br_table end
        self.emit("if");
        let mut in_if = inner.clone();
        in_if.push(vec![]);
        self.expr(Ty::I32, &in_if, depth + 1);
        let shifted: Vec<String> = chosen
            .iter()
            .map(|d| (d.parse::<usize>().unwrap() + 1).to_string())
            .collect();
        self.emit(format!("br_table {}", shifted.join(" ")));
        self.emit("end");
        for _ in 0..levels {
            let ty = self.ty();
            self.expr(ty, &inner, depth + 1);
            let local = self.pick(ty.locals());
            self.emit(format!("local.set {local}"));
            self.emit("end");
            inner.pop();
        }
    }
    fn stmt(&mut self, labels: &[Label], depth: u32) {
        let mut choices = vec!["set", "set", "drop", "store", "gset", "storeload"];
        if depth < 4 && !self.small() {
            choices.extend([
                "block",
                "loop",
                "if",
                "ifelse",
                "br",
                "brif",
                "brif",
                "brtable",
                "ret",
                "retcall",
                "throw",
                "try",
                "try",
                "atomicstmt",
                "bulk",
                "tset",
                "deep",
            ]);
        }
        let d = depth + 1;
        match self.pick(&choices) {
            "set" => {
                let ty = self.ty();
                self.expr(ty, labels, d);
                let local = self.pick(ty.locals());
                self.emit(format!("local.set {local}"));
            }
            "drop" => {
                let ty = self.ty();
                self.expr(ty, labels, d);
                self.emit("drop");
            }
            "store" => {
                let ty = self.ty();
                self.expr(Ty::I32, labels, d);
                self.expr(ty, labels, d);
                self.emit(format!("{}.store", ty.name()));
            }
            "gset" => {
                if self.r.chance(0.5) {
                    self.expr(Ty::I32, labels, d);
                    self.emit("global.set 0");
                } else {
                    self.expr(Ty::I64, labels, d);
                    self.emit("global.set 1");
                }
            }
            "storeload" => {
                let ty = self.ty();
                let a = self.pick(&[0, 4, 8]);
                let b = if self.r.chance(0.8) {
                    a
                } else {
                    self.pick(&[0, 4, 8])
                };
                let lty = if self.r.chance(0.85) { ty } else { self.ty() };
                self.emit(format!("i32.const {a}"));
                self.expr(ty, labels, d);
                let narrow = ty == Ty::I64 && self.r.chance(0.2);
                self.emit(if narrow {
                    "i64.store32".to_owned()
                } else {
                    format!("{}.store", ty.name())
                });
                let k = self.r.range(0, 9);
                if k < 2 {
                    self.stmt(labels, d);
                } else if k < 3 {
                    self.emit("atomic.fence");
                }
                self.emit(format!("i32.const {b}"));
                if self.r.chance(0.1) {
                    self.emit(format!("{}.load offset=4", lty.name()));
                } else {
                    self.emit(format!("{}.load", lty.name()));
                }
                let local = self.pick(lty.locals());
                self.emit(format!("local.set {local}"));
            }
            "block" => {
                self.emit("block");
                self.stmts(&Self::with(labels, vec![]), d, None);
                self.emit("end");
            }
            "loop" => {
                self.emit("loop");
                let inner = Self::with(labels, vec![]);
                self.stmts(&inner, d, None);
                self.expr(Ty::I32, &inner, d);
                self.emit("br_if 0");
                let count = self.r.range(0, 2) as usize;
                self.stmts(&inner, d, Some(count));
                self.emit("end");
            }
            "if" => {
                self.expr(Ty::I32, labels, d);
                self.emit("if");
                self.stmts(&Self::with(labels, vec![]), d, None);
                self.emit("end");
            }
            "ifelse" => {
                self.expr(Ty::I32, labels, d);
                self.emit("if");
                self.stmts(&Self::with(labels, vec![]), d, None);
                self.emit("else");
                self.stmts(&Self::with(labels, vec![]), d, None);
                self.emit("end");
            }
            "br" => {
                let target = self.r.below(labels.len());
                self.branch_values(labels, target, depth);
                self.emit(format!("br {target}"));
                if self.r.chance(0.7) {
                    let count = self.r.range(1, 2) as usize;
                    self.stmts(labels, d, Some(count));
                }
            }
            "brif" => {
                let target = self.r.below(labels.len());
                self.branch_values(labels, target, depth);
                self.expr(Ty::I32, labels, d);
                self.emit(format!("br_if {target}"));
                for _ in 0..labels[labels.len() - 1 - target].len() {
                    self.emit("drop");
                }
            }
            "brtable" => {
                let target = self.r.below(labels.len());
                let label = labels[labels.len() - 1 - target].clone();
                let targets: Vec<usize> = (0..labels.len())
                    .filter(|t| labels[labels.len() - 1 - t] == label)
                    .collect();
                let count = self.r.range(1, 3) as usize;
                let chosen: Vec<String> = (0..count)
                    .map(|_| self.pick(&targets).to_string())
                    .collect();
                self.branch_values(labels, target, depth);
                self.expr(Ty::I32, labels, d);
                self.emit(format!("br_table {}", chosen.join(" ")));
                if self.r.chance(0.5) {
                    self.stmts(labels, d, Some(1));
                }
            }
            "ret" => {
                self.expr(Ty::I32, labels, d);
                self.emit("return");
                if self.r.chance(0.5) {
                    self.stmts(labels, d, Some(1));
                }
            }
            "retcall" => {
                if self.r.chance(0.5) {
                    self.expr(Ty::I32, labels, d);
                    self.emit("return_call 1");
                } else {
                    self.expr(Ty::I32, labels, d);
                    self.expr(Ty::I32, labels, d);
                    self.emit("return_call_indirect (type 0)");
                }
                if self.r.chance(0.5) {
                    self.stmts(labels, d, Some(1));
                }
            }
            "throw" => {
                if self.r.chance(0.6) {
                    self.expr(Ty::I32, labels, d);
                    self.emit("throw 0");
                } else {
                    self.expr(Ty::I64, labels, d);
                    self.expr(Ty::I32, labels, d);
                    self.emit("throw 1");
                }
                if self.r.chance(0.4) {
                    self.stmts(labels, d, Some(1));
                }
            }
            "try" => self.try_stmt(labels, d),
            "atomicstmt" => {
                self.expr(Ty::I32, labels, d);
                self.expr(Ty::I32, labels, d);
                self.emit("i32.atomic.store");
            }
            "bulk" => {
                self.expr(Ty::I32, labels, d);
                self.expr(Ty::I32, labels, d);
                self.expr(Ty::I32, labels, d);
                let fill = self.r.chance(0.5);
                self.emit(if fill { "memory.fill" } else { "memory.copy" });
            }
            "tset" => {
                self.expr(Ty::I32, labels, d);
                self.refexpr(labels, d);
                self.emit("table.set 0");
            }
            "deep" => self.deep_loops(labels, d),
            other => panic!("{other}"),
        }
    }
    fn try_stmt(&mut self, labels: &[Label], d: u32) {
        // block $out
        //   block $h (result H)
        //     try_table (catch.. 0) [extra]
        //       body
        //     end
        //     br 1
        //   end
        //   handler consuming H
        // end
        let (clause, handler): (&str, Label) = match self.r.below(5) {
            0 | 1 => ("(catch 0 0)", vec!["i32"]),
            2 => ("(catch 1 0)", vec!["i64", "i32"]),
            3 => ("(catch_ref 0 0)", vec!["i32", "exnref"]),
            _ => {
                if self.r.chance(0.5) {
                    ("(catch_all_ref 0)", vec!["exnref"])
                } else {
                    ("(catch_all 0)", vec![])
                }
            }
        };
        self.emit("block");
        let out = Self::with(labels, vec![]);
        if handler.is_empty() {
            self.emit("block");
        } else {
            self.emit(format!("block (result {})", types(&handler)));
        }
        let h = Self::with(&out, handler.clone());
        let mut clauses = vec![clause.to_owned()];
        self.extra_catches(&h, &mut clauses);
        self.emit(format!("try_table {}", clauses.join(" ")));
        let body = Self::with(&h, vec![]);
        self.stmts(&body, d, None);
        self.emit("end");
        self.emit("br 1");
        self.emit("end");
        let mut stack = handler.clone();
        while let Some(top) = stack.pop() {
            match top {
                "exnref" => {
                    if self.r.chance(0.4) {
                        self.emit("throw_ref");
                        break;
                    }
                    self.emit("drop");
                }
                "i32" => {
                    let local = self.pick(Ty::I32.locals());
                    self.emit(format!("local.set {local}"));
                }
                "i64" => {
                    if self.r.chance(0.5) {
                        self.emit("drop");
                    } else {
                        self.emit("local.set 4");
                    }
                }
                other => panic!("{other}"),
            }
        }
        self.emit("end");
    }
}

pub(crate) fn generate(seed: u64) -> Vec<String> {
    let mut generator = Gen {
        r: Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0xF00D),
        out: Vec::new(),
        budget: 260,
    };
    let count = generator.r.range(2, 6) as usize;
    generator.stmts(&[vec!["i32"]], 0, Some(count));
    generator.expr(Ty::I32, &[vec!["i32"]], 0);
    generator.out
}

pub(crate) fn module_text(body: &[String]) -> String {
    format!(
        r#"(module
  (type (func (param i32) (result i32)))
  (import "env" "imp" (func (type 0)))
  (memory 1 1 shared)
  (table 4 funcref)
  (global (mut i32) (i32.const 0))
  (global (mut i64) (i64.const 0))
  (tag (param i32))
  (tag (param i64 i32))
  (func (type 0) local.get 0)
  (func (param i64 i32) (result i32 i64) local.get 1 local.get 0)
  (func (param i32 i32) (result i32) (local i32 i32 i64 i64 f32 f64)
    {}
  )
  (elem declare func 1)
)"#,
        body.join("\n    ")
    )
}

type Leaf = (&'static str, usize);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Prod {
    Instr(usize),
    Param(usize),
    Init(usize),
    LoopPhi(usize, usize),
    Phi(usize, usize),
    Exc(usize, usize),
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

fn op_join(values: &[V], i: usize) -> V {
    let mut v = join(values, Prod::Instr(i));
    v.prod = Prod::Instr(i);
    v.cval = None;
    v
}

#[derive(Clone)]
struct Frame {
    kind: &'static str,
    params: usize,
    results: usize,
    height: usize,
    entry: Vec<V>,
    param_values: Vec<V>,
    incoming: Vec<(Vec<V>, Vec<V>)>,
    reachable_at_entry: bool,
    index: usize,
    then: Option<(Vec<V>, Vec<V>)>,
    /// try_table: (label depth from outside, values count)
    catches: Vec<(usize, usize)>,
    writes: Vec<Vec<V>>,
}

impl Frame {
    fn label_arity(&self) -> usize {
        if self.kind == "loop" {
            self.params
        } else {
            self.results
        }
    }
}

struct Reference {
    rec: HashMap<usize, Vec<V>>,
    live: Vec<bool>,
    sinks: Vec<(usize, usize, V)>,
}

fn group_count(text: &str, key: &str) -> usize {
    let mut count = 0;
    let mut rest = text;
    while let Some(at) = rest.find(key) {
        let after = &rest[at + key.len()..];
        let close = after.find(')').unwrap();
        count += after[..close].split_whitespace().count();
        rest = &after[close..];
    }
    count
}

fn catches_of(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("(catch") {
        let after = &rest[at + 1..];
        let close = after.find(')').unwrap();
        let words: Vec<&str> = after[..close].split_whitespace().collect();
        let tag_count = |t: &str| if t == "0" { 1 } else { 2 };
        let entry = match words[0] {
            "catch" => (words[2].parse().unwrap(), tag_count(words[1])),
            "catch_ref" => (words[2].parse().unwrap(), tag_count(words[1]) + 1),
            "catch_all" => (words[1].parse().unwrap(), 0),
            "catch_all_ref" => (words[1].parse().unwrap(), 1),
            other => panic!("{other}"),
        };
        out.push(entry);
        rest = &after[close..];
    }
    out
}

/// (pops, pushes, leaf kind or None for an operation) of a plain operator.
fn plain(o: &str) -> Option<(usize, usize, Option<&'static str>)> {
    Some(match o {
        "i32.const" | "i64.const" | "f32.const" | "f64.const" | "ref.func" | "ref.null" => {
            (0, 1, Some("const"))
        }
        "i32.add" | "i64.mul" | "f32.add" | "f64.sub" | "i64.eq" | "f32.lt" => (2, 1, None),
        "i32.eqz" | "i32.wrap_i64" | "i64.extend_i32_s" | "f32.convert_i32_s"
        | "f32.demote_f64" | "f64.promote_f32" | "f64.convert_i64_u" | "ref.is_null" => {
            (1, 1, None)
        }
        _ => return None,
    })
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
            "block" | "loop" | "if" | "try_table" => open.push(i),
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
    // loop index -> (params, locals) carried by back edges
    let mut back: HashMap<usize, (Vec<V>, Vec<V>)> = HashMap::new();
    for _pass in 0..80 {
        let mut rec: HashMap<usize, Vec<V>> = HashMap::new();
        let mut live = vec![false; instrs.len()];
        let mut sinks: Vec<(usize, usize, V)> = Vec::new();
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
        // (address, offset, class, value)
        let mut store: Option<(i64, String, String, V)> = None;
        let mut frames = vec![Frame {
            kind: "func",
            params: 0,
            results: 1,
            height: 0,
            entry: Vec::new(),
            param_values: Vec::new(),
            incoming: Vec::new(),
            reachable_at_entry: true,
            index: 0,
            then: None,
            catches: Vec::new(),
            writes: Vec::new(),
        }];
        let top = |st: &[V], n: usize| st[st.len() - n..].to_vec();
        // Delivers values and locals to the frame at `at`.
        let deliver = |frames: &mut Vec<Frame>,
                       at: usize,
                       i: usize,
                       values: Vec<V>,
                       locals: Vec<V>,
                       sinks: &mut Vec<(usize, usize, V)>,
                       back: &mut HashMap<usize, (Vec<V>, Vec<V>)>,
                       changed: &mut bool| {
            match frames[at].kind {
                "func" => {
                    for (k, value) in values.into_iter().enumerate() {
                        sinks.push((i, k, value));
                    }
                }
                "loop" => {
                    let index = frames[at].index;
                    let merged: (Vec<V>, Vec<V>) = match back.get(&index) {
                        None => (values, locals),
                        Some((op_, ol)) => (
                            op_.iter()
                                .zip(&values)
                                .enumerate()
                                .map(|(n, (a, b))| {
                                    join(&[a.clone(), b.clone()], Prod::LoopPhi(index, 1000 + n))
                                })
                                .collect(),
                            ol.iter()
                                .zip(&locals)
                                .enumerate()
                                .map(|(n, (a, b))| {
                                    join(&[a.clone(), b.clone()], Prod::LoopPhi(index, n))
                                })
                                .collect(),
                        ),
                    };
                    let differs = back.get(&index).is_none_or(|(op_, ol)| {
                        op_.iter()
                            .chain(ol.iter())
                            .zip(merged.0.iter().chain(merged.1.iter()))
                            .any(|(a, b)| a.b != b.b || a.f != b.f)
                    });
                    if differs {
                        *changed = true;
                    }
                    back.insert(index, merged);
                }
                _ => frames[at].incoming.push((values, locals)),
            }
        };
        for i in 0..instrs.len() {
            let o = op(i);
            live[i] = reach;
            if !reach && !matches!(o, "block" | "loop" | "if" | "else" | "end" | "try_table") {
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
                    | "call_indirect"
                    | "call_ref"
                    | "return_call"
                    | "return_call_indirect"
                    | "throw"
                    | "throw_ref"
                    | "try_table"
                    | "i32.atomic.rmw.add"
                    | "i64.atomic.rmw.xchg"
                    | "i32.atomic.store"
                    | "memory.fill"
                    | "memory.copy"
                    | "memory.grow"
                    | "i64.store32"
            ) || o.ends_with(".store")
            {
                // stores set their own fact below
                if !o.ends_with(".store") || o == "i32.atomic.store" {
                    store = None;
                }
            }
            // record writes into every open try_table
            let note_write = |frames: &mut Vec<Frame>, n: usize, v: &V| {
                for frame in frames.iter_mut() {
                    if frame.kind == "try_table" && frame.writes.len() == NLOC {
                        frame.writes[n].push(v.clone());
                    }
                }
            };
            if let Some((pops, pushes, leaf)) = plain(o) {
                let args: Vec<V> = st.split_off(st.len() - pops);
                if pops > 0 {
                    rec.insert(i, args.clone());
                }
                let v = match leaf {
                    Some(kind) => {
                        let cval = if o == "i32.const" {
                            Some(
                                instrs[i]
                                    .split_whitespace()
                                    .nth(1)
                                    .unwrap()
                                    .parse()
                                    .unwrap(),
                            )
                        } else {
                            None
                        };
                        V::leaf((kind, i), Prod::Instr(i), cval)
                    }
                    None => op_join(&args, i),
                };
                for _ in 0..pushes {
                    st.push(v.clone());
                }
                continue;
            }
            match o {
                "local.get" => {
                    let v = locals[arg(i)].renamed(Prod::Instr(i));
                    st.push(v);
                }
                "local.set" | "local.tee" => {
                    let v = st.pop().unwrap();
                    rec.insert(i, vec![v.clone()]);
                    let def = v.renamed(Prod::Instr(i));
                    note_write(&mut frames, arg(i), &def);
                    locals[arg(i)] = def.clone();
                    if o == "local.tee" {
                        st.push(def);
                    }
                }
                "global.get" => st.push(V::leaf(("global", i), Prod::Instr(i), None)),
                "global.set" | "drop" => {
                    let v = st.pop().unwrap();
                    rec.insert(i, vec![v.clone()]);
                    sinks.push((i, 0, v));
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
                _ if o.contains(".load") => {
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    let mut v = V::leaf(("load", i), Prod::Instr(i), None);
                    v.b.extend(a.b.iter().copied());
                    let mut inputs = vec![a.clone()];
                    let class = o.to_owned();
                    let offset = instrs[i].split_whitespace().nth(1).unwrap_or("").to_owned();
                    let full = matches!(o, "i32.load" | "i64.load" | "f32.load" | "f64.load");
                    if let (true, Some((address, soff, sclass, value)), Some(cval), Prod::Instr(p)) =
                        (full, &store, a.cval, a.prod)
                        && op(p) == "i32.const"
                        && *address == cval
                        && *soff == offset
                        && sclass.replace(".store", ".load") == class
                    {
                        v.b.extend(value.b.iter().copied());
                        v.f.extend(value.f.iter().copied());
                        inputs.push(value.clone());
                    }
                    rec.insert(i, inputs);
                    st.push(v);
                }
                "i32.store" | "i64.store" | "f32.store" | "f64.store" | "i64.store32"
                | "i32.atomic.store" => {
                    let v = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    sinks.push((i, 1, v.clone()));
                    store = None;
                    if !matches!(o, "i64.store32" | "i32.atomic.store")
                        && let (Some(cval), Prod::Instr(p)) = (a.cval, a.prod)
                        && op(p) == "i32.const"
                    {
                        let offset = instrs[i].split_whitespace().nth(1).unwrap_or("").to_owned();
                        store = Some((cval, offset, o.to_owned(), v.clone()));
                    }
                    rec.insert(i, vec![a, v]);
                }
                "i32.atomic.rmw.add" | "i64.atomic.rmw.xchg" => {
                    let v = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    sinks.push((i, 1, v.clone()));
                    let mut r = V::leaf(("atomic", i), Prod::Instr(i), None);
                    r.b.extend(a.b.iter().copied());
                    rec.insert(i, vec![a, v]);
                    st.push(r);
                }
                "memory.fill" | "memory.copy" => {
                    let args = st.split_off(st.len() - 3);
                    for (k, v) in args.iter().enumerate() {
                        sinks.push((i, k, v.clone()));
                    }
                    rec.insert(i, args);
                }
                "memory.grow" => {
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    rec.insert(i, vec![a]);
                    st.push(V::leaf(("memory", i), Prod::Instr(i), None));
                }
                "atomic.fence" => {
                    // A fence orders memory with other agents, so a store
                    // before it no longer stands for a load after it.
                    store = None;
                }
                "table.get" => {
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    let mut r = V::leaf(("table", i), Prod::Instr(i), None);
                    r.b.extend(a.b.iter().copied());
                    rec.insert(i, vec![a]);
                    st.push(r);
                }
                "table.size" => st.push(V::leaf(("table", i), Prod::Instr(i), None)),
                "table.set" => {
                    let v = st.pop().unwrap();
                    let a = st.pop().unwrap();
                    sinks.push((i, 0, a.clone()));
                    sinks.push((i, 1, v.clone()));
                    rec.insert(i, vec![a, v]);
                }
                "call" | "call_indirect" | "call_ref" | "return_call" | "return_call_indirect" => {
                    let (pops, pushes) = match (o, instrs[i].as_str()) {
                        ("call", "call 2") => (2, 2),
                        ("call", _) => (1, 1),
                        ("call_indirect", _) | ("call_ref", _) => (2, 1),
                        ("return_call", _) => (1, 0),
                        _ => (2, 0),
                    };
                    let args = st.split_off(st.len() - pops);
                    for (k, v) in args.iter().enumerate() {
                        sinks.push((i, k, v.clone()));
                    }
                    rec.insert(i, args);
                    for _ in 0..pushes {
                        st.push(V::leaf(("call", i), Prod::Instr(i), None));
                    }
                    if pushes == 0 {
                        reach = false;
                        let height = frames.last().unwrap().height;
                        st.truncate(height);
                    }
                }
                "throw" | "throw_ref" => {
                    let pops = match instrs[i].as_str() {
                        "throw 1" => 2,
                        _ => 1,
                    };
                    let args = st.split_off(st.len() - pops);
                    for (k, v) in args.iter().enumerate() {
                        sinks.push((i, k, v.clone()));
                    }
                    rec.insert(i, args);
                    reach = false;
                    let height = frames.last().unwrap().height;
                    st.truncate(height);
                }
                "block" | "loop" | "if" | "try_table" => {
                    let params = group_count(&instrs[i], "(param");
                    let results = group_count(&instrs[i], "(result");
                    if o == "if" && reach {
                        let c = st.pop().unwrap();
                        rec.insert(i, vec![c.clone()]);
                        sinks.push((i, 0, c));
                    }
                    let height = st
                        .len()
                        .saturating_sub(params)
                        .max(frames.last().unwrap().height);
                    let param_values = if reach {
                        st[height..].to_vec()
                    } else {
                        Vec::new()
                    };
                    let catches = if o == "try_table" {
                        catches_of(&instrs[i])
                    } else {
                        Vec::new()
                    };
                    let is_try = o == "try_table";
                    frames.push(Frame {
                        kind: match o {
                            "block" => "block",
                            "loop" => "loop",
                            "if" => "if",
                            _ => "try_table",
                        },
                        params,
                        results,
                        height,
                        entry: locals.clone(),
                        param_values,
                        incoming: Vec::new(),
                        reachable_at_entry: reach,
                        index: i,
                        then: None,
                        catches,
                        writes: if is_try && reach {
                            vec![Vec::new(); NLOC]
                        } else {
                            Vec::new()
                        },
                    });
                    if o == "loop" && reach {
                        let previous = back.get(&i).cloned();
                        for slot in 0..params {
                            let mut values = vec![st[height + slot].clone()];
                            if let Some((pp, _)) = &previous {
                                values.push(pp[slot].clone());
                            }
                            st[height + slot] = join(&values, Prod::LoopPhi(i, 1000 + slot))
                                .renamed(Prod::LoopPhi(i, 1000 + slot));
                        }
                        for &n in writes.get(&i).into_iter().flatten() {
                            let mut values = vec![locals[n].clone()];
                            if let Some((_, pl)) = &previous {
                                values.push(pl[n].clone());
                            }
                            let v = join(&values, Prod::LoopPhi(i, n)).renamed(Prod::LoopPhi(i, n));
                            note_write(&mut frames, n, &v);
                            locals[n] = v;
                        }
                    }
                }
                "else" => {
                    let frame = frames.last_mut().unwrap();
                    if reach {
                        frame.then = Some((top(&st, frame.results), locals.clone()));
                    }
                    st.truncate(frame.height);
                    st.extend(frame.param_values.iter().cloned());
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
                    if frame.kind == "try_table" && frame.reachable_at_entry {
                        let catch_locals: Vec<V> = (0..NLOC)
                            .map(|n| {
                                if frame.writes[n].is_empty() {
                                    frame.entry[n].clone()
                                } else {
                                    let mut values = vec![frame.entry[n].clone()];
                                    values.extend(frame.writes[n].iter().cloned());
                                    join(&values, Prod::Phi(frame.index, 2000 + n))
                                }
                            })
                            .collect();
                        let outer = frames.len() - 1;
                        for (label, count) in frame.catches.clone() {
                            let at = outer - 1 - label;
                            let values: Vec<V> = (0..count)
                                .map(|k| {
                                    V::leaf(("exc", frame.index), Prod::Exc(frame.index, k), None)
                                })
                                .collect();
                            deliver(
                                &mut frames,
                                at,
                                frame.index,
                                values,
                                catch_locals.clone(),
                                &mut sinks,
                                &mut back,
                                &mut changed,
                            );
                        }
                    }
                    frames.pop();
                    if frame.kind == "loop" {
                        if reach {
                            let values = top(&st, frame.results);
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
                        incoming.push((top(&st, frame.results), locals.clone()));
                    }
                    if frame.kind == "if" && frame.reachable_at_entry {
                        incoming.push((frame.param_values.clone(), frame.entry.clone()));
                    }
                    st.truncate(frame.height);
                    if incoming.is_empty() {
                        reach = false;
                        locals = frame.entry.clone();
                        continue;
                    }
                    reach = true;
                    let mut values = Vec::new();
                    for slot in 0..frame.results {
                        let column: Vec<V> = incoming
                            .iter()
                            .map(|(values, _)| values[slot].clone())
                            .collect();
                        values.push(join(&column, Prod::Phi(i, 1000 + slot)));
                    }
                    st.extend(values.iter().cloned());
                    if !values.is_empty() {
                        rec.insert(i, values);
                    }
                    let merged: Vec<V> = (0..NLOC)
                        .map(|n| {
                            let column: Vec<V> = incoming
                                .iter()
                                .map(|(_, locals)| locals[n].clone())
                                .collect();
                            join(&column, Prod::Phi(i, n))
                        })
                        .collect();
                    for n in 0..NLOC {
                        if merged[n].prod != locals[n].prod
                            || merged[n].b != locals[n].b
                            || merged[n].f != locals[n].f
                        {
                            note_write(&mut frames, n, &merged[n]);
                        }
                    }
                    locals = merged;
                }
                "br" => {
                    let depth = arg(i);
                    let at = frames.len() - 1 - depth;
                    let values = top(&st, frames[at].label_arity());
                    rec.insert(i, values.clone());
                    deliver(
                        &mut frames,
                        at,
                        i,
                        values,
                        locals.clone(),
                        &mut sinks,
                        &mut back,
                        &mut changed,
                    );
                    reach = false;
                    let height = frames.last().unwrap().height;
                    st.truncate(height);
                }
                "br_if" => {
                    let depth = arg(i);
                    let at = frames.len() - 1 - depth;
                    let c = st.pop().unwrap();
                    let values = top(&st, frames[at].label_arity());
                    let mut inputs = values.clone();
                    inputs.push(c.clone());
                    sinks.push((i, values.len(), c));
                    rec.insert(i, inputs);
                    deliver(
                        &mut frames,
                        at,
                        i,
                        values,
                        locals.clone(),
                        &mut sinks,
                        &mut back,
                        &mut changed,
                    );
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
                    let at = frames.len() - 1 - *targets.last().unwrap();
                    let values = top(&st, frames[at].label_arity());
                    let mut inputs = values.clone();
                    inputs.push(c.clone());
                    sinks.push((i, values.len(), c));
                    rec.insert(i, inputs);
                    for depth in distinct {
                        let at = frames.len() - 1 - depth;
                        deliver(
                            &mut frames,
                            at,
                            i,
                            values.clone(),
                            locals.clone(),
                            &mut sinks,
                            &mut back,
                            &mut changed,
                        );
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
    let index = || {
        index_of
            .get(&node["byte_offset"].as_u64().unwrap())
            .copied()
            .unwrap_or(usize::MAX)
    };
    match kind {
        "param" => ("param".into(), at("local")),
        "local_init" => ("init".into(), at("local")),
        "const" | "load" | "atomic" | "table" | "memory" => (kind.into(), index()),
        "global_get" => ("global".into(), index()),
        "call" | "import_call" | "call_indirect" | "call_ref" => ("call".into(), index()),
        "exception_value" => ("exc".into(), index()),
        other => (other.into(), node["byte_offset"].as_u64().unwrap() as usize),
    }
}

/// Runs the property over `seeds`; returns (checks, failures).
pub(crate) fn run(seeds: std::ops::Range<u64>, verbose: bool) -> (usize, Vec<String>) {
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut validator_features = wasmparser::WasmFeatures::all();
    validator_features.remove(wasmparser::WasmFeatures::COMPONENT_MODEL);
    let mut skipped = 0;
    for seed in seeds.clone() {
        let body = generate(seed);
        let text = module_text(&body);
        let bytes = match wat::parse_str(&text) {
            Ok(bytes) => bytes,
            Err(error) => panic!("seed {seed}: {error}\n{text}"),
        };
        if let Err(error) =
            wasmparser::Validator::new_with_features(validator_features).validate_all(&bytes)
        {
            panic!("seed {seed} does not validate: {error}\n{text}");
        }
        let module = Module::read(&bytes).unwrap();
        let mut reader = module.bodies[2].get_operators_reader().unwrap();
        let mut offsets = Vec::new();
        while !reader.eof() {
            offsets.push(reader.read_with_offset().unwrap().1 as u64);
        }
        if offsets.len() != body.len() + 1 {
            skipped += 1;
            continue;
        }
        let index_of: HashMap<u64, usize> =
            offsets.iter().enumerate().map(|(i, o)| (*o, i)).collect();
        let mut instrs = body.clone();
        instrs.push("end".into());
        let reference = match std::panic::catch_unwind(|| analyze(&instrs)) {
            Ok(reference) => reference,
            Err(_) => {
                failures.push(format!("seed {seed}: REFERENCE PANIC"));
                continue;
            }
        };
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
            if document["status"] != "computed"
                || document["truncated"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|flag| flag == true)
            {
                failures.push(format!(
                    "seed {seed} {what}: status {} truncated {} omissions {}",
                    document["status"], document["truncated"], document["omissions"]
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
        let mut seeded: Vec<usize> = reference.rec.keys().copied().collect();
        seeded.sort_unstable();
        let mut disagreements = Vec::new();
        for i in seeded {
            let values = &reference.rec[&i];
            let name = instrs[i].split_whitespace().next().unwrap();
            if !reference.live[i] && name != "end" {
                continue;
            }
            let offset = offsets[i];
            let operands = if name.contains(".load") {
                let mut whole = BTreeSet::new();
                for value in values {
                    whole.extend(expected(&value.b));
                }
                let document = ask(format!("function=3&offset={offset}&direction=backward"));
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
                    "function=3&offset={offset}&operand={k}&direction=backward"
                ));
                if let Ok(document) = &backward {
                    let both = ask(format!(
                        "function=3&offset={offset}&operand={k}&direction=both"
                    ));
                    let forward = ask(format!(
                        "function=3&offset={offset}&operand={k}&direction=forward"
                    ));
                    if let (Ok(both), Ok(forward)) = (both, forward) {
                        if ends(&both, "sources") != ends(document, "sources")
                            || ends(&both, "sinks") != ends(&forward, "sinks")
                        {
                            disagreements.push(format!(
                                "seed {seed} {} at {i} operand {k}: both/each direction differ",
                                instrs[i]
                            ));
                        }
                        // A seed node is never its own source unless the
                        // reference shows a cycle back to it.
                        for document in [document, &both] {
                            for id in document["sources"].as_array().unwrap() {
                                let node = &document["nodes"][id.as_u64().unwrap() as usize];
                                if node["role"] == "seed" || node["seed"] == true {
                                    let leaf = leaf_of(node, &index_of);
                                    let cyc = value
                                        .b
                                        .iter()
                                        .any(|(k2, at)| *k2 == leaf.0.as_str() && *at == leaf.1);
                                    if !cyc {
                                        disagreements.push(format!(
                                            "seed {seed} {} at {i} operand {k}: seed listed as its own source without a cycle",
                                            instrs[i]
                                        ));
                                    }
                                }
                            }
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
        // Forward from every live leaf instruction.
        for i in 0..instrs.len() {
            let name = instrs[i].split_whitespace().next().unwrap();
            if !reference.live[i] {
                continue;
            }
            let leaf: Option<&'static str> = if plain(name).is_some_and(|(_, _, l)| l.is_some()) {
                Some("const")
            } else if name.contains(".load") {
                Some("load")
            } else if name == "global.get" {
                Some("global")
            } else if matches!(name, "call" | "call_indirect" | "call_ref") {
                Some("call")
            } else if name.contains(".atomic.rmw") {
                Some("atomic")
            } else if matches!(name, "table.get" | "table.size") {
                Some("table")
            } else if name == "memory.grow" {
                Some("memory")
            } else {
                None
            };
            let Some(leaf) = leaf else { continue };
            let want: BTreeSet<(String, usize)> = reference
                .sinks
                .iter()
                .filter(|(_, _, value)| value.f.iter().any(|(k, at)| *k == leaf && *at == i))
                .map(|(j, _, _)| ("sink".to_owned(), *j))
                .collect();
            let document = ask(format!(
                "function=3&offset={}&direction=forward",
                offsets[i]
            ));
            record(
                format!("{} at {i} forward", instrs[i]),
                document,
                want,
                true,
            );
        }
        // Dead instructions are refused.
        for i in 0..instrs.len() {
            let name = instrs[i].split_whitespace().next().unwrap();
            if !reference.live[i]
                && !matches!(name, "block" | "loop" | "if" | "else" | "end" | "try_table")
            {
                checked += 1;
                match ask(format!(
                    "function=3&offset={}&operand=0&direction=both",
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
        checked += disagreements.len();
        failures.append(&mut disagreements);
        if verbose && seed % 100 == 0 {
            eprintln!("seed {seed}: {checked} checks, {} failures", failures.len());
        }
    }
    eprintln!(
        "extended property: {checked} checks over {} modules ({skipped} skipped)",
        seeds.end - seeds.start
    );
    (checked, failures)
}

#[test]
fn extended_slices_match_the_reference() {
    let var = |name: &str| std::env::var(format!("REB_VALUE_FLOW_EXTENDED_{name}")).ok();
    let from: u64 = var("FROM").and_then(|t| t.parse().ok()).unwrap_or(0);
    let to: u64 = var("TO")
        .and_then(|t| t.parse().ok())
        .unwrap_or(DEFAULT_EXTENDED_SEEDS);
    let (checked, failures) = if let Some(list) = var("LIST") {
        let mut checked = 0;
        let mut failures = Vec::new();
        for seed in list.split(',') {
            let seed: u64 = seed.parse().unwrap();
            let (c, mut f) = run(seed..seed + 1, false);
            checked += c;
            failures.append(&mut f);
        }
        (checked, failures)
    } else {
        run(from..to, false)
    };
    assert!(checked > 0, "no checks ran");
    assert!(
        failures.is_empty(),
        "{} of {checked} checks failed:\n{}",
        failures.len(),
        failures
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
