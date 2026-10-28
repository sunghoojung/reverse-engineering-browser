//! Owned generators for the large, repetitive review repro inputs. Each one
//! reproduces a reviewer probe byte for byte from its shape, so tests never
//! read anything outside the repository. Small repros are checked-in files
//! under `tools/fixtures/dispatch-review/`.

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
