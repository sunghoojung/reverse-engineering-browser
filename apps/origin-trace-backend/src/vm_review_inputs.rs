//! Owned generators for the large, repetitive review repro inputs. Each one
//! reproduces a reviewer probe byte for byte from its shape, so tests never
//! read anything outside the repository. Small repros are checked-in files
//! under `tools/fixtures/dispatch-review/`. The parametrized shapes below
//! also drive the N-versus-4N classifier scaling test.

/// The interpreter loop the third review appends after its noise.
const VM_TAIL: &str = "while(pc<program.length){switch(program[pc++]){case 0:stack.push(1);break;case 1:stack.pop();break;case 2:return stack;}}}";
const VM_HEAD: &str = "function run(program){var pc=0,stack=[];";

/// `count` copies of one loop statement, one per line.
pub(crate) fn loops(count: usize, body: &str) -> String {
    format!("function f(x){{\n{}}}\n", body.repeat(count))
}

/// Unbalanced brackets in comments before an interpreter.
pub(crate) fn comments(count: usize) -> String {
    let opener = format!("/* {} {} {} */ // {} {} {}\n", '{', '(', '[', '}', ')', ']');
    let noise = format!("/* {0}{0}{0} {1}{1}{1} {2}{2}{2} */", '{', '(', '[');
    format!("{VM_HEAD}{opener}{}\n{VM_TAIL}\n", noise.repeat(count))
}

/// Deeply bracketed calls on one long line before an interpreter.
pub(crate) fn long_line(count: usize) -> String {
    format!(
        "{VM_HEAD}{}{VM_TAIL}\n",
        "a[b[c[d]]](e(f(g)));".repeat(count)
    )
}

/// Unbalanced brackets inside regex literals, which the masker keeps.
pub(crate) fn regex_literals(count: usize) -> String {
    format!(
        "{VM_HEAD}var r=/[(]/,q=/[)]/,b=/[{{]/,c=/[}}]/;\n{}\n{VM_TAIL}\n",
        "x=/[(/;".repeat(count)
    )
}

/// Nested template literals with brackets before an interpreter.
pub(crate) fn templates(count: usize) -> String {
    format!(
        "{VM_HEAD}var t=`${{'{{'}}${{`(${{'['}}`}}`;\n{}\n{VM_TAIL}\n",
        "y=`${(a)=>{return `${'}'}`}}`;".repeat(count)
    )
}

/// Constant writes and trivial switches ahead of the real interpreter in
/// one function region.
pub(crate) fn starve(writes: usize, switches: usize) -> String {
    format!(
        "function run(code){{var pc=0,stack=[],op;\n{}\n{}while(pc<code.length){{switch(code[pc++]){{case 0:stack.push(1);break;case 1:stack.pop();break;case 2:return stack;}}}}}}\n",
        (0..writes)
            .map(|i| format!("op={};", i % 7))
            .collect::<String>(),
        "switch(op){case 0:case 1:case 2:break}\n".repeat(switches)
    )
}

/// Chained writes `a=b=a=b=...`, which once copied a value per write.
pub(crate) fn chained_writes(count: usize) -> String {
    format!("function f(){{var a,b;{}1}}\n", "a=b=".repeat(count))
}

fn switch_arm() -> &'static str {
    "switch(c[p++]){case 1:case 2:case 3:p+=1}"
}

const VM: &str = "function run(code, stack){var pc=0; do switch(code[pc++]){case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;} while(pc<code.length);}";

/// `c=x;` written `defs` times, then `sites` cursor switches in one loop.
fn defs_then_switches(defs: usize, sites: usize) -> String {
    format!(
        "function big(c,x){{var p=0;{}while(p<c.length){{{}}}}}\n",
        "c=x;".repeat(defs),
        switch_arm().repeat(sites)
    )
}

fn noise(index: usize) -> String {
    format!(
        "function big{index}(t,x){{var k;while(x){{{}}}}}\n",
        "k=1;t[k](x);".repeat(12000)
    )
}

/// Every large JavaScript review input, by its reviewer file name.
pub(crate) fn javascript() -> Vec<(&'static str, String)> {
    let mut inputs = vec![
        (
            "p3",
            format!(
                "function big(t,x){{{}}}\n",
                (0..8000)
                    .map(|i| format!("var v{i}=1;t[v{i}](x);"))
                    .collect::<String>()
            ),
        ),
        (
            "p3b",
            format!(
                "function big(t,x){{var k;while(x){{{}}}}}\n",
                "k=1;t[k](x);".repeat(12000)
            ),
        ),
        (
            "p3c",
            format!(
                "function big(c){{var p=0;while(p<c.length){{{}}}}}\n",
                switch_arm().repeat(5000)
            ),
        ),
        (
            "p3d",
            format!(
                "function big(x){{{}while(x){{{}}}}}\n",
                (0..50)
                    .map(|i| format!("var a{i}=x[{i}];"))
                    .collect::<String>(),
                (0..8000)
                    .map(|i| {
                        let a = i % 50;
                        format!("if(a{a}===1||a{a}===2||a{a}===3)x++;")
                    })
                    .collect::<String>()
            ),
        ),
    ];
    for (name, defs, sites) in [
        ("q1_bufkind", 20000, 4000),
        ("q1b_bufkind", 40000, 4000),
        ("q2_d0_s2k", 0, 2000),
        ("q2_d0_s4k", 0, 4000),
        ("q2_d0_s8k", 0, 8000),
        ("q2_d20k_s1k", 20000, 1000),
        ("q2_d20k_s2k", 20000, 2000),
        ("q3_d1k_s4k", 1000, 4000),
        ("q3_d20k_s3k", 20000, 3000),
        ("q3_d20k_s4k", 20000, 4000),
        ("q3_d5k_s4k", 5000, 4000),
        ("q4_d200k_s4k", 200000, 4096),
    ] {
        inputs.push((name, defs_then_switches(defs, sites)));
    }
    for (name, count) in [("q5_pairs", 40000), ("q5b_pairs", 120000)] {
        inputs.push((
            name,
            format!(
                "function big(s,x){{{}{}}}\n",
                "if(/\\(/.test(s))x++;".repeat(count),
                "if(/\\]/.test(s))x++;".repeat(count)
            ),
        ));
    }
    inputs.push(("s1_budget", format!("{}{}{VM}\n", noise(0), noise(1))));
    inputs.push((
        "s1b_budget",
        format!(
            "{}{}function run(code, stack){{var pc=0;{} do switch(code[pc++]){{case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;}} while(pc<code.length);}}\n",
            noise(0),
            noise(1),
            "stack.length;".repeat(12000)
        ),
    ));
    inputs.push((
        "s2_listing",
        format!(
            "{}{VM}\n",
            (0..300)
                .map(|i| format!("function tok{i}(s){{var o=0;for(var i=0;i<s.length;i++){{switch(s.charCodeAt(i)){{case 40:o++;break;case 41:o--;break;case 32:break}}}}return o}}\n"))
                .collect::<String>()
        ),
    ));
    inputs.push((
        "p526_300_calls_then_interpreter",
        format!(
            "function run(code, stack, t, x){{var pc=0; {} while(pc<code.length){{switch(code[pc++]){{case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;}}}}}}",
            (0..300).map(|i| format!("t[n{i}](x);")).collect::<String>()
        ),
    ));
    inputs
}

/// One large input by name.
pub(crate) fn javascript_named(name: &str) -> String {
    javascript()
        .into_iter()
        .find(|(input, _)| *input == name)
        .map(|(_, source)| source)
        .expect("review input")
}

fn interpreter_with_prefix(lines: &[String]) -> String {
    let prefix = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    format!(
        r#"(module (memory 1)
 (func (export "run") (param $code i32) (param $len i32) (result i32)
  (local $pc i32) (local $op i32) (local $acc i32)
  {prefix}
  (block $exit (loop $again
    (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
    (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
    (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
    (block $c (block $b (block $a
      (br_table $a $b $c $exit (local.get $op)))
      (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $again))
      (local.set $acc (i32.sub (local.get $acc) (i32.const 1))) (br $again))
    (local.set $acc (i32.mul (local.get $acc) (i32.const 2))) (br $again)))
  (local.get $acc)))"#
    )
}

/// The review's Wasm cap inputs: constant writes to `$op` before an
/// interpreter loop (alternatives and definitions caps), a control without
/// them, and a function past the old symbolic node cap.
pub(crate) fn wasm() -> Vec<(&'static str, Vec<u8>)> {
    let constants = |count: usize| {
        (0..count)
            .map(|i| format!("(local.set $op (i32.const {}))", i % 7))
            .collect::<Vec<_>>()
    };
    [
        ("w1_manydefs", interpreter_with_prefix(&constants(70))),
        ("w1b_alts", interpreter_with_prefix(&constants(20))),
        ("w1c_control", interpreter_with_prefix(&[])),
        (
            "w2_nodes",
            interpreter_with_prefix(&vec![
                "(local.set $acc (i32.add (local.get $acc) (i32.const 1)))"
                    .to_owned();
                23000
            ]),
        ),
    ]
    .into_iter()
    .map(|(name, text)| (name, wat::parse_str(text).expect("review wat")))
    .collect()
}

/// A store-back loop whose stored local has `writes` copies of a second
/// local, itself written `writes` times, read by `sites` dispatch sites and
/// stored by as many stores.
pub(crate) fn slot_chain(writes: usize, sites: usize) -> Vec<u8> {
    let text = format!(
        "(module (memory 1)\n (func (export \"run\") (param $obj i32) (local $s i32) (local $v i32) (local $w i32)\n{}{}  (loop $l\n   (local.set $s (i32.load offset=4 (local.get $obj)))\n{}{}   (br $l))))\n",
        "  (local.set $v (local.get $w))\n".repeat(writes),
        "  (local.set $w (local.get $obj))\n".repeat(writes),
        "   (block (block (block (br_table 0 1 2 (local.get $s)))))\n".repeat(sites),
        "   (i32.store offset=4 (local.get $obj) (local.get $v))\n".repeat(sites),
    );
    wat::parse_str(text).expect("slot chain wat")
}

/// A noise function of constant writes and trivial branch tables, then a
/// real cursor interpreter.
pub(crate) fn wasm_starve(writes: usize, switches: usize) -> Vec<u8> {
    let text = format!(
        "(module (memory 1)\n (func $noise (param $x i32) (local $op i32)\n{}{} )\n (func $run (export \"run\") (param $code i32) (param $len i32) (result i32)\n    (local $pc i32) (local $acc i32)\n    (block $exit\n      (loop $again\n        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))\n        (block $d (block $c (block $bb (block $aa\n          (br_table $aa $bb $c $d (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))\n          (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $c))\n          (local.set $acc (i32.xor (local.get $acc) (i32.const 7))) (br $c))\n          (local.set $acc (i32.shl (local.get $acc) (i32.const 1))))\n        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))\n        (br $again)))\n    (local.get $acc)))\n",
        (0..writes)
            .map(|i| format!("  (local.set $op (i32.const {}))\n", i % 7))
            .collect::<String>(),
        "  (block $b (block $a (br_table $a $b (local.get $op))))\n".repeat(switches),
    );
    wat::parse_str(text).expect("starve wat")
}

/// A frame-slot interpreter whose stored local has `writes` constant writes
/// before the one write that advances the slot.
pub(crate) fn slot_writes(writes: usize) -> Vec<u8> {
    let text = format!(
        "(module (memory 1)\n (func (export \"run\") (param $obj i32) (result i32) (local $s i32) (local $v i32) (local $acc i32)\n{}  (block $exit\n   (loop $l\n    (local.set $s (i32.load offset=4 (local.get $obj)))\n    (block $d (block $c (block $b (block $a\n      (br_table $a $b $c $d (i32.load8_u (local.get $s))))\n      (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $c))\n      (local.set $acc (i32.xor (local.get $acc) (i32.const 3))) (br $c))\n      (br $exit))\n    (local.set $v (i32.add (local.get $s) (i32.const 1)))\n    (i32.store offset=4 (local.get $obj) (local.get $v))\n    (br $l)))\n  (local.get $acc)))\n",
        "  (local.set $v (i32.const 0))\n".repeat(writes),
    );
    wat::parse_str(text).expect("slot writes wat")
}

/// `sites` call_indirect sites over a table of `slots` placed functions.
pub(crate) fn indirect_sites(slots: usize, sites: usize) -> Vec<u8> {
    let text = format!(
        "(module (type $t (func (param i32) (result i32))) (table {slots} funcref) (func $f (type $t) (local.get 0)) (elem (i32.const 0) func {}) (func (param i32) {}))",
        "$f ".repeat(slots),
        "(drop (call_indirect (type $t) (i32.const 0) (local.get 0)))".repeat(sites),
    );
    wat::parse_str(text).expect("indirect sites wat")
}

/// Two overlapping element segments: base fanout sums their entries, while
/// the placed table holds only the 20 slots they share.
pub(crate) const OVERLAP_WAT: &str = r#"(module
  (type $t (func (param i32)))
  (memory 1)
  (table 40 funcref)
  (func $h (param i32))
  (func $a (param $n i32)
    (loop $l
      (call_indirect (type $t) (local.get $n) (local.get $n))
      (br_if $l (local.tee $n (i32.sub (local.get $n) (i32.const 1))))))
  (func $b (param $code i32) (param $len i32) (result i32)
    (local $pc i32) (local $acc i32)
    (block $exit
      (loop $again
        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
        (block $d (block $c (block $bb (block $aa
          (br_table $aa $bb $c $d (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
          (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $c))
          (local.set $acc (i32.xor (local.get $acc) (i32.const 7))) (br $c))
          (local.set $acc (i32.shl (local.get $acc) (i32.const 1))))
        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
        (br $again)))
    (local.get $acc))
  (elem (i32.const 0) $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h)
  (elem (i32.const 0) $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h $h))
"#;

/// The third review's inputs at the reviewer's sizes, by reviewer file name.
pub(crate) fn third_review_javascript() -> Vec<(&'static str, String)> {
    vec![
        ("j_loops_20000", loops(20000, "while(x)x\n")),
        ("j_loops_80000", loops(80000, "while(x)x\n")),
        ("j_loops_brace", loops(20000, "while(x){x}\n")),
        ("j_loops_semi", loops(20000, "while(x)x;\n")),
        ("j_cmt", comments(20000)),
        ("j_longline", long_line(100000)),
        ("j_regex", regex_literals(20000)),
        ("j_tmpl", templates(5000)),
        ("j_starve", starve(4200, 5000)),
        ("j_chain", chained_writes(1000000)),
    ]
}

pub(crate) fn third_review_wasm() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "w_overlap",
            wat::parse_str(OVERLAP_WAT).expect("overlap wat"),
        ),
        ("w_slot_1_1", slot_chain(4096, 1)),
        ("w_slot_4_4", slot_chain(4096, 4)),
        ("w_slot_16_16", slot_chain(4096, 16)),
        ("w_slot_48_48", slot_chain(4096, 48)),
        ("w_starve", wasm_starve(4200, 5000)),
        ("w_take_10", slot_writes(10)),
        ("w_take_4096", slot_writes(4096)),
        ("w_indirect_sites", indirect_sites(200000, 20000)),
    ]
}

/// One scalable adversarial input: its runtime and its bytes at a size.
pub(crate) type Generator = (&'static str, &'static str, fn(usize) -> Vec<u8>);

/// Every adversarial shape of the four reviews as a function of one size,
/// for the N-versus-4N scaling property: total classifier work and peak
/// retained bytes may grow at most linearly with the input.
pub(crate) fn scaling_generators() -> Vec<Generator> {
    vec![
        ("deep_functions", "javascript", |n| {
            format!("{}{}{}", "function nest(){".repeat(n), VM, "}".repeat(n)).into_bytes()
        }),
        ("scopes_times_identifiers", "javascript", |n| {
            // Independent scopes with repeated references plus deep scopes
            // sharing the same outer bindings challenge semantic resolution.
            format!(
                "let shared=1;{}{}{}",
                "function nest(){shared;".repeat(n),
                "shared;".repeat(n),
                "}".repeat(n)
            )
            .into_bytes()
        }),
        ("block_hoists", "javascript", |n| {
            format!(
                "function f(){{{}{}{}}}",
                "{".repeat(n),
                (0..n).map(|i| format!("var v{i}=0;")).collect::<String>(),
                "}".repeat(n)
            )
            .into_bytes()
        }),
        ("deep_loops", "javascript", |n| {
            format!("function vm(code,stack){{var pc=0;{}{}while(pc<code.length){{switch(code[pc++]){{case 1:stack.push(code[pc++]);break;case 2:stack.pop();break;case 3:return stack;}}}}}}", "while(x){".repeat(n), "switch(code[i++]){case 1:break;}}".repeat(n)).into_bytes()
        }),
        ("wasm_deep", "webassembly", |n| {
            wat::parse_str(format!(
                "(module (memory 1)(func (param $p i32) {}{}))",
                "loop ".repeat(n),
                "local.get $p i32.load8_u br_table 0 0 end ".repeat(n)
            ))
            .expect("deep loops")
        }),
        ("many_tables", "webassembly", |n| {
            wat::parse_str(format!("(module (memory 1)(func $h){}(func (param $p i32)(loop (br_table 0 0 (i32.load8_u (local.get $p))))))", (0..n).map(|i| format!("(table 1 funcref)(elem(table {i})(i32.const 0) func $h)")).collect::<String>())).expect("many tables")
        }),
        ("gate_scopes", "javascript", |n| {
            format!("function vm(code,stack){{var pc=0,ops={{1:function(){{stack.push(code[pc++])}},2:function(){{stack.pop()}},3:function(){{pc=code.length}}}};{}while(pc<code.length){{{}}}}}", (0..n).map(|i| format!("function f{i}(){{return 1;}}")).collect::<String>(), "ops[code[pc++]]();".repeat(n)).into_bytes()
        }),
        ("bracket_memory", "javascript", |n| {
            "{}".repeat(n * 128).into_bytes()
        }),
        ("huge_element", "webassembly", |n| {
            wat::parse_str(format!("(module (table {} funcref)(elem(i32.const 0) func {})(memory 1)(func $h)(func (param $p i32)(loop (br_table 0 0 (i32.load8_u (local.get $p))))))", n, "$h ".repeat(n))).expect("large element")
        }),
        ("loops_braceless", "javascript", |n| {
            loops(n, "while(x)x\n").into_bytes()
        }),
        ("loops_brace", "javascript", |n| {
            loops(n, "while(x){x}\n").into_bytes()
        }),
        ("loops_semi", "javascript", |n| {
            loops(n, "while(x)x;\n").into_bytes()
        }),
        ("comments", "javascript", |n| comments(n).into_bytes()),
        ("long_line", "javascript", |n| long_line(2 * n).into_bytes()),
        ("regex_literals", "javascript", |n| {
            regex_literals(n).into_bytes()
        }),
        ("templates", "javascript", |n| templates(n / 2).into_bytes()),
        ("starve", "javascript", |n| starve(n, n).into_bytes()),
        ("chained_writes", "javascript", |n| {
            chained_writes(20 * n).into_bytes()
        }),
        ("defs_then_switches", "javascript", |n| {
            defs_then_switches(5 * n, n).into_bytes()
        }),
        ("distinct_selectors", "javascript", |n| {
            format!(
                "function big(t,x){{{}}}\n",
                (0..n)
                    .map(|i| format!("var v{i}=1;t[v{i}](x);"))
                    .collect::<String>()
            )
            .into_bytes()
        }),
        ("noise_calls", "javascript", |n| {
            format!(
                "function big(t,x){{var k;while(x){{{}}}}}\n",
                "k=1;t[k](x);".repeat(n)
            )
            .into_bytes()
        }),
        ("if_ladders", "javascript", |n| {
            format!(
                "function big(x){{{}while(x){{{}}}}}\n",
                (0..50)
                    .map(|i| format!("var a{i}=x[{i}];"))
                    .collect::<String>(),
                (0..n)
                    .map(|i| {
                        let a = i % 50;
                        format!("if(a{a}===1||a{a}===2||a{a}===3)x++;")
                    })
                    .collect::<String>()
            )
            .into_bytes()
        }),
        ("bracket_pairs", "javascript", |n| {
            format!(
                "function big(s,x){{{}{}}}\n",
                "if(/\\(/.test(s))x++;".repeat(n),
                "if(/\\]/.test(s))x++;".repeat(n)
            )
            .into_bytes()
        }),
        ("tokenizers", "javascript", |n| {
            format!(
                "{}{VM}\n",
                (0..n / 16)
                    .map(|i| format!("function tok{i}(s){{var o=0;for(var i=0;i<s.length;i++){{switch(s.charCodeAt(i)){{case 40:o++;break;case 41:o--;break;case 32:break}}}}return o}}\n"))
                    .collect::<String>()
            )
            .into_bytes()
        }),
        ("wasm_constants", "webassembly", |n| {
            let lines = (0..n)
                .map(|i| format!("(local.set $op (i32.const {}))", i % 7))
                .collect::<Vec<_>>();
            wat::parse_str(interpreter_with_prefix(&lines)).expect("constants wat")
        }),
        ("wasm_nodes", "webassembly", |n| {
            wat::parse_str(interpreter_with_prefix(&vec![
                "(local.set $acc (i32.add (local.get $acc) (i32.const 1)))".to_owned();
                n
            ]))
            .expect("nodes wat")
        }),
        ("slot_chain", "webassembly", |n| slot_chain(n, n / 16)),
        ("wasm_starve", "webassembly", |n| wasm_starve(n, n)),
        ("slot_writes", "webassembly", slot_writes),
        ("indirect_sites", "webassembly", |n| {
            indirect_sites(10 * n, n)
        }),
        ("wasm_loops", "webassembly", |n| {
            wat::parse_str(format!(
                "(module (memory 1) (func (param $p i32) {}))",
                "(block (loop (br_table 1 1 (i32.load8_u (local.get $p)))))".repeat(n)
            ))
            .expect("loops wat")
        }),
    ]
}

/// Every owned input the differential invariants cover: repository
/// fixtures, dispatch-shape fixtures, review repro copies and generated
/// review inputs, as (name, bytes, kind).
pub(crate) fn differential_inputs() -> Vec<(String, Vec<u8>, &'static str)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut inputs = Vec::new();
    for directory in [
        "tools/fixtures/dispatch-shapes",
        "tools/fixtures/dispatch-review",
        "tools/fixtures/vm-dynamic-debug",
        "tools/fixtures/vm-dynamic-debug/xor-decoded",
        "tools/fixtures/vm-workspace-effects",
        "tools/fixtures/native-vm-dispatch",
        "tools/fixtures/vm-analysis-packs",
        "apps/runtime-hook-demo",
        "apps/runtime-hook-demo/ghostwire-worker",
    ] {
        let mut paths = std::fs::read_dir(root.join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let kind = match path.extension().and_then(|ext| ext.to_str()) {
                Some("js" | "mjs") => "javascript",
                Some("wasm") => "wasm",
                _ => continue,
            };
            inputs.push((
                path.strip_prefix(&root).unwrap().display().to_string(),
                std::fs::read(&path).unwrap(),
                kind,
            ));
        }
    }
    for name in ["wasm-dispatch.json", "wasm-ranked-dispatch.json"] {
        let modules: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("tools/fixtures/vm-dynamic-debug").join(name))
                .unwrap(),
        )
        .unwrap();
        for (key, value) in modules.as_object().unwrap() {
            if let Some(hex) = value.as_str()
                && let Ok(bytes) = hex::decode(hex)
            {
                inputs.push((format!("{name}#{key}"), bytes, "wasm"));
            }
        }
    }
    for (name, source) in javascript().into_iter().chain(third_review_javascript()) {
        inputs.push((format!("review:{name}"), source.into_bytes(), "javascript"));
    }
    for (name, bytes) in wasm().into_iter().chain(third_review_wasm()) {
        inputs.push((format!("review:{name}"), bytes, "wasm"));
    }
    inputs
}
