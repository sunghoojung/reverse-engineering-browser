//! Owned review inputs: short interpreter programs and generators for the
//! large, repetitive review repro inputs. Each reproduces a reviewer probe
//! byte for byte, so tests never read anything outside the repository. The
//! parametrized shapes below also drive the N-versus-4N classifier scaling
//! test.

/// The interpreter loop the third review appends after its noise.
const VM_TAIL: &str = "while(pc<program.length){switch(program[pc++]){case 0:stack.push(1);break;case 1:stack.pop();break;case 2:return stack;}}}";
const VM_HEAD: &str = "function run(program){var pc=0,stack=[];";

/// A cursor loop dispatching a three-handler object table.
pub(crate) const CONTROL_VM: &str = "function vm(code,stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc++]]();}return stack;}\n";
/// The same table bound by `let` inside a block.
pub(crate) const BLOCK_LET_VM: &str = "function vm(code,stack){var pc=0;{let ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc++]]();}}return stack;}\n";
/// Handlers advance the program counter themselves.
pub(crate) const HANDLER_PC_VM: &str = "function vm(code,stack){var pc=0;var ops={1:function(){pc+=2;stack.push(1)},2:function(){pc+=1;stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc]]();}return stack;}\n";
/// An inner cursor loop dispatches a shadowing `ops`; the outer table keeps
/// its own handlers.
pub(crate) const SHADOWED_TABLE_VM: &str = "function vm(code, stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};function step(){var ops=[function(){},function(){}];var i=0;while(i<code.length){ops[code[i++]]();}}while(pc<code.length){switch(code[pc]){default:ops[code[pc]]();}}return stack;}\n";
/// Control for [`SHADOWED_TABLE_VM`] with a distinctly named inner table.
pub(crate) const SHADOW_CONTROL_VM: &str = "function vm(code, stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};function step(){var tbl=[function(){},function(){}];var i=0;while(i<code.length){tbl[code[i++]]();}}while(pc<code.length){switch(code[pc]){default:ops[code[pc]]();}}return stack;}\n";
/// The table is dispatched from a nested function the loop calls.
pub(crate) const NESTED_TABLE_VM: &str = "function vm(code, stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};function step(){return ops[code[pc++]]();}while(pc<code.length){switch(code[pc]){default:step();}}return stack;}\n";
/// A loop dispatch beside a one-shot router on the same table.
pub(crate) const LOOP_BODY_ROUTER_VM: &str = "function route(k,code,stack){var pc=0;var handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){}};while(pc<code.length){handlers[code[pc++]](stack);}return handlers[k](stack);}\n";

/// Owned interpreter shapes whose handler claims need a static table, alias,
/// helper or threaded proof, each beside look-alikes that must claim none:
/// (name, source, opcodes the workspace keeps).
pub(crate) const STATIC_SHAPES: &[(&str, &str, &[u64])] = &[
    (
        "array-arrows-and-hole",
        "function run(code){const s={acc:0,h:false};const ops=[(s)=>{s.acc++;},s=>s.acc--,,function(s){s.h=true;}];let pc=0;while(!s.h&&pc<code.length){ops[code[pc++]](s);}return s.acc;}",
        &[0, 1, 3],
    ),
    (
        "array-reassigned",
        "function run(code){const s={acc:0,h:false};let ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];ops=[function(s){s.h=true;}];let pc=0;while(!s.h&&pc<code.length){ops[code[pc++]](s);}return s.acc;}",
        &[],
    ),
    (
        "array-entry-written",
        "function run(code){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];ops[1]=function(s){s.acc+=2;};let pc=0;while(!s.h&&pc<code.length){ops[code[pc++]](s);}return s.acc;}",
        &[],
    ),
    (
        "array-reordered",
        "function run(code){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];ops.reverse();let pc=0;while(!s.h&&pc<code.length){ops[code[pc++]](s);}return s.acc;}",
        &[],
    ),
    (
        "array-after-spread",
        "function run(code,base){const s={acc:0,h:false};const ops=[...base,function(s){s.acc++;},function(s){s.h=true;}];let pc=0;while(!s.h&&pc<code.length){ops[code[pc++]](s);}return s.acc;}",
        &[],
    ),
    (
        "array-router",
        "function route(k,s){const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];for(const v of s.items){log(v);}while(s.busy){s.tick();}return ops[k](s);}",
        &[],
    ),
    (
        "rotated-for-update",
        "function run(code){var pc=0,acc=0,op=code[pc++];for(;op;op=code[pc++]){switch(op){case 1:acc+=1;break;case 2:acc-=1;break;case 3:return acc;}}return acc;}",
        &[1, 2, 3],
    ),
    (
        "rotated-transformed-latch",
        "function run(code,key){let pc=0,acc=0;let op=code[pc++];while(op!==0){switch(op){case 1:acc+=1;break;case 2:acc-=1;break;case 3:return acc;}op=code[pc++]^key;}return acc;}",
        &[],
    ),
    (
        "alias-of-table",
        "function run(code){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];var a=ops,t=a;let pc=0;while(!s.h&&pc<code.length){t[code[pc++]](s);}return s.acc;}",
        &[0, 1, 2],
    ),
    (
        "alias-temporary-call",
        "function run(code){const s={acc:0,h:false};const ops={1:function(s){s.acc++;},2:function(s){s.acc--;},3:function(s){s.h=true;}};let pc=0;while(!s.h&&pc<code.length){const h=ops[code[pc++]];h.call(null,s);}return s.acc;}",
        &[1, 2, 3],
    ),
    (
        "alias-reassigned",
        "function run(code,other){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];var t=ops;t=other;let pc=0;while(!s.h&&pc<code.length){t[code[pc++]](s);}return s.acc;}",
        &[],
    ),
    (
        "alias-shadowed",
        "function run(code,other){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];var t=ops;{let t=other;let pc=0;while(!s.h&&pc<code.length){t[code[pc++]](s);}}return s.acc;}",
        &[],
    ),
    (
        "alias-temporary-hoisted",
        "function run(code){const s={acc:0,h:false};const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];let pc=0;const h=ops[code[pc++]];while(!s.h&&pc<code.length){h(s);pc++;}return s.acc;}",
        &[],
    ),
    (
        "alias-temporary-router",
        "function route(k,s){const ops=[function(s){s.acc++;},function(s){s.acc--;},function(s){s.h=true;}];while(s.busy){s.tick();}const h=ops[k];return h(s);}",
        &[],
    ),
    (
        "helper-closure-fetch",
        "function run(code){let pc=0;const stack=[];function next(){return code[pc++];}while(pc<code.length){switch(next()){case 1:stack.push(code[pc++]);break;case 2:stack.pop();break;case 3:return stack;}}return stack;}",
        &[1, 2, 3],
    ),
    (
        "helper-this-fetch",
        "class VM{constructor(code){this.code=code;this.pc=0;this.stack=[];}fetch(){return this.code[this.pc++];}run(){while(this.pc<this.code.length){switch(this.fetch()){case 1:this.stack.push(this.code[this.pc++]);break;case 2:this.stack.pop();break;case 3:return this.stack;}}return this.stack;}}",
        &[1, 2, 3],
    ),
    (
        "helper-state-fetch",
        "function read(state){return state.code[state.pc++];}function run(code){let pc=0;const state={code:code,pc:pc,stack:[]};while(state.pc<code.length){switch(read(state)){case 1:state.stack.push(code[state.pc]);pc=state.pc++;break;case 2:state.stack.pop();break;case 3:return state.stack;}}return state.stack;}",
        &[1, 2, 3],
    ),
    (
        "helper-loop-advances",
        "function run(code){let pc=0;const stack=[];const at=(code,pc)=>code[pc];while(pc<code.length){const op=at(code,pc);pc++;switch(op){case 1:stack.push(code[pc++]);break;case 2:stack.pop();break;case 3:return stack;}}return stack;}",
        &[1, 2, 3],
    ),
    (
        "helper-reassigned",
        "function run(code){let pc=0;const stack=[];let next=function(){return code[pc++];};next=function(){return 0;};while(pc<code.length){switch(next()){case 1:stack.push(code[pc++]);break;case 2:stack.pop();break;case 3:return stack;}pc++;}return stack;}",
        &[],
    ),
    (
        "helper-parameter-copy",
        "function next(code,pc){return code[pc++];}function run(code){let pc=0;const stack=[];while(stack.length<9){switch(next(code,pc)){case 1:stack.push(code[pc]);break;case 2:stack.pop();break;case 3:return stack;}}return stack;}",
        &[],
    ),
    (
        "helper-overridden",
        "class VM{constructor(code){this.code=code;this.pc=0;this.stack=[];}fetch(){return this.code[this.pc++];}run(){while(this.pc<this.code.length){switch(this.fetch()){case 1:this.stack.push(this.code[this.pc++]);break;case 2:this.stack.pop();break;case 3:return this.stack;}}return this.stack;}}class Replay extends VM{fetch(){return this.code[0];}}",
        &[],
    ),
    (
        "helper-lookup-walk",
        "function run(code,types){let pc=0;const stack=[];function next(){return types[code[pc++]];}while(pc<code.length){switch(next()){case 1:stack.push(code[pc++]);break;case 2:stack.pop();break;case 3:return stack;}}return stack;}",
        &[],
    ),
    (
        "rotated-state-machine",
        "function run(code){let pc=0,acc=0;let op=1;while(op){switch(op){case 1:acc+=code[pc++];op=2;break;case 2:acc-=1;op=3;break;case 3:op=0;break;}}return acc;}",
        &[],
    ),
    (
        "threaded-returned-handler",
        "function run(code){const s={acc:0};let pc=0;const ops=[function(s){s.acc++;return ops[code[pc++]];},function(s){s.acc--;return ops[code[pc++]];},function(s){return null;}];let h=ops[code[pc++]];while(h){h=h(s);}return s.acc;}",
        &[0, 1, 2],
    ),
    (
        "threaded-tail-call",
        "function run(code){const s={acc:0};let pc=0;const ops=[function(s){s.acc++;return ops[code[pc++]](s);},function(s){s.acc--;return ops[code[pc++]](s);},function(s){return s.acc;}];return ops[code[pc++]](s);}",
        &[0, 1, 2],
    ),
    (
        "threaded-shared-next",
        "function run(code){const s={acc:0};let pc=0;function next(s){return ops[code[pc++]](s);}const ops=[function(s){s.acc++;return next(s);},function(s){s.acc--;return next(s);},function(s){return s.acc;}];return ops[code[pc++]](s);}",
        &[0, 1, 2],
    ),
    (
        "threaded-callback-chain",
        "function run(s){const ops=[function(s){s.acc++;return ops[1];},function(s){s.acc--;return ops[2];},function(s){return null;}];let h=ops[0];while(h){h=h(s);}return s.acc;}",
        &[],
    ),
    (
        "threaded-router",
        "function route(k,s){const ops=[function(s){s.acc++;return ops[k](s);},function(s){s.acc--;return null;},function(s){return s.acc;}];return ops[k](s);}",
        &[],
    ),
    (
        "threaded-loop-head-write",
        "function run(code,list){const s={acc:0};let pc=0;const ops=[function(s){s.acc++;return ops[code[pc++]];},function(s){s.acc--;return ops[code[pc++]];},function(s){return null;}];let h=ops[code[pc++]];for(h of list){h=h(s);}return s.acc;}",
        &[],
    ),
    (
        "threaded-reassigned-table",
        "function run(code){const s={acc:0};let pc=0;let ops=[function(s){s.acc++;return ops[code[pc++]];},function(s){s.acc--;return ops[code[pc++]];},function(s){return null;}];ops=[function(s){return null;}];let h=ops[code[pc++]];while(h){h=h(s);}return s.acc;}",
        &[],
    ),
];

/// Owned Wasm shapes for fetch helpers and threaded handler chains and
/// cycles beside look-alikes: a chain of constant handler indexes, a router
/// forwarding its argument, and a table a relative segment may overwrite.
/// (name, module text, instruction, role, through_helper) of the first site
/// with that instruction.
pub(crate) const WASM_STATIC_SHAPES: &[(&str, &str, &str, &str, bool)] = &[
    (
        "helper-global-pc",
        r#"(module (memory 1)
  (global $pc (mut i32) (i32.const 0))
  (func $next (result i32) (local $at i32)
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (i32.load8_u (local.get $at)))
  (func (export "run") (param $n i32) (result i32) (local $acc i32)
    (block $exit (loop $again
      (block $b2 (block $b1 (block $b0
        (br_table $b0 $b1 $b2 $exit (call $next)))
        (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $again))
        (local.set $acc (i32.sub (local.get $acc) (i32.const 1))) (br $again))
      (br $exit)))
    (local.get $acc)))"#,
        "br_table",
        "interpreter-candidate",
        true,
    ),
    (
        "helper-frame-slot-pc",
        r#"(module (memory 1)
  (func $read (param $state i32) (result i32) (local $pc i32)
    (local.set $pc (i32.load offset=4 (local.get $state)))
    (i32.store offset=4 (local.get $state) (i32.add (local.get $pc) (i32.const 1)))
    (i32.load8_u (i32.add (i32.load (local.get $state)) (local.get $pc))))
  (func (export "run") (param $state i32) (result i32) (local $acc i32)
    (block $exit (loop $again
      (block $b2 (block $b1 (block $b0
        (br_table $b0 $b1 $b2 $exit (call $read (local.get $state))))
        (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $again))
        (local.set $acc (i32.sub (local.get $acc) (i32.const 1))) (br $again))
      (br $exit)))
    (local.get $acc)))"#,
        "br_table",
        "interpreter-candidate",
        true,
    ),
    (
        "helper-local-cursor",
        r#"(module (memory 1)
  (func $peek (param $p i32) (result i32) (local $q i32)
    (local.set $q (local.get $p))
    (local.set $q (i32.add (local.get $q) (i32.const 1)))
    (i32.load8_u (local.get $q)))
  (func (export "run") (param $p i32) (result i32) (local $acc i32)
    (block $exit (loop $again
      (block $b2 (block $b1 (block $b0
        (br_table $b0 $b1 $b2 $exit (call $peek (local.get $p))))
        (local.set $acc (i32.add (local.get $acc) (i32.const 1))) (br $again))
        (local.set $acc (i32.sub (local.get $acc) (i32.const 1))) (br $again))
      (br $exit)))
    (local.get $acc)))"#,
        "br_table",
        "other",
        false,
    ),
    (
        "helper-outside-loop",
        r#"(module (memory 1)
  (global $pc (mut i32) (i32.const 0))
  (func $next (result i32) (local $at i32)
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (i32.load8_u (local.get $at)))
  (func (export "run") (result i32)
    (block $b2 (block $b1 (block $b0
      (br_table $b0 $b1 $b2 (call $next)))
      (return (i32.const 1)))
      (return (i32.const 2)))
    (i32.const 3)))"#,
        "br_table",
        "other",
        true,
    ),
    (
        "threaded-tail-call",
        r#"(module (memory 1)
  (type $op (func (param i32) (result i32)))
  (table 3 funcref)
  (global $pc (mut i32) (i32.const 0))
  (func $inc (type $op) (local $at i32)
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (return_call_indirect (type $op)
      (i32.add (local.get 0) (i32.const 1)) (i32.load8_u (local.get $at))))
  (func $dec (type $op) (local $at i32)
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (return_call_indirect (type $op)
      (i32.sub (local.get 0) (i32.const 1)) (i32.load8_u (local.get $at))))
  (func $halt (type $op) (local.get 0))
  (elem (i32.const 0) func $inc $dec $halt))"#,
        "return_call_indirect",
        "interpreter-candidate",
        false,
    ),
    (
        "threaded-returned-index",
        r#"(module (memory 1)
  (type $op (func (result i32)))
  (table 3 funcref)
  (global $pc (mut i32) (i32.const 0))
  (global $acc (mut i32) (i32.const 0))
  (func $inc (type $op) (local $at i32)
    (global.set $acc (i32.add (global.get $acc) (i32.const 1)))
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (i32.load8_u (local.get $at)))
  (func $dec (type $op) (local $at i32)
    (global.set $acc (i32.sub (global.get $acc) (i32.const 1)))
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (i32.load8_u (local.get $at)))
  (func $halt (type $op) (i32.const 2))
  (elem (i32.const 0) func $inc $dec $halt)
  (func (export "run") (result i32) (local $h i32)
    (block $exit (loop $again
      (br_if $exit (i32.eq (local.get $h) (i32.const 2)))
      (local.set $h (call_indirect (type $op) (local.get $h)))
      (br $again)))
    (global.get $acc)))"#,
        "call_indirect",
        "interpreter-candidate",
        false,
    ),
    (
        "threaded-callback-chain",
        r#"(module
  (type $op (func (result i32)))
  (table 3 funcref)
  (func $first (type $op) (i32.const 1))
  (func $second (type $op) (i32.const 2))
  (func $halt (type $op) (i32.const 2))
  (elem (i32.const 0) func $first $second $halt)
  (func (export "run") (result i32) (local $h i32)
    (block $exit (loop $again
      (br_if $exit (i32.eq (local.get $h) (i32.const 2)))
      (local.set $h (call_indirect (type $op) (local.get $h)))
      (br $again)))
    (local.get $h)))"#,
        "call_indirect",
        "other",
        false,
    ),
    (
        "threaded-router",
        r#"(module
  (type $op (func (param i32) (result i32)))
  (table 2 funcref)
  (func $forward (type $op) (return_call_indirect (type $op) (local.get 0) (local.get 0)))
  (func $halt (type $op) (local.get 0))
  (elem (i32.const 0) func $forward $halt))"#,
        "return_call_indirect",
        "other",
        false,
    ),
    (
        "threaded-replaced-table",
        r#"(module
  (import "env" "base" (global $base i32))
  (memory 1)
  (type $op (func (param i32) (result i32)))
  (table 3 funcref)
  (global $pc (mut i32) (i32.const 0))
  (func $inc (type $op) (local $at i32)
    (local.set $at (global.get $pc))
    (global.set $pc (i32.add (global.get $pc) (i32.const 1)))
    (return_call_indirect (type $op)
      (i32.add (local.get 0) (i32.const 1)) (i32.load8_u (local.get $at))))
  (func $halt (type $op) (local.get 0))
  (elem (i32.const 0) func $inc $halt)
  (elem (global.get $base) func $halt $halt))"#,
        "return_call_indirect",
        "other",
        false,
    ),
];

const BINDING_HEAD: &str = "function vm(code, stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};";
const BINDING_TAIL: &str =
    "while(pc<code.length){switch(code[pc]){default:ops[code[pc]]();}}return stack;}";

/// Table bindings the static-binding rule proves despite a neighbouring
/// declaration, name or token that a text matcher would confuse. Every case
/// keeps its three handlers.
pub(crate) fn proven_bindings() -> Vec<(&'static str, String)> {
    let case = |middle: &str| [BINDING_HEAD, middle, BINDING_TAIL].concat();
    let closure = case("function step(){var i=0;while(i<code.length){ops[code[i++]]();}}");
    let wide = format!("var a{}=1;", "\u{96ea}".repeat(100));
    vec![
        (
            "annex-b",
            case(
                "var step=function(){if(false){function ops(){}}var i=0;while(i<code.length){ops[code[i++]]();}};",
            ),
        ),
        ("arguments", closure.replace("ops", "arguments")),
        (
            "class-asi",
            case(
                "var step=function(){var q=1\nclass ops {}\nvar i=0;while(i<code.length){ops[code[i++]]();}};",
            ),
        ),
        (
            "long-name",
            case("function step(){var ops=[];var i=0;while(i<code.length){ops[code[i++]]();}}")
                .replace("ops", &format!("h{}", "a".repeat(300))),
        ),
        (
            "named-expression",
            case("var step=function ops(){var i=0;while(i<code.length){ops[code[i++]]();}};"),
        ),
        (
            "object-shorthand",
            case("var obj={ops};function step(){var i=0;while(i<code.length){ops[code[i++]]();}}"),
        ),
        (
            "direct",
            [
                BINDING_HEAD,
                "while(pc<code.length){ops[code[pc++]]();}return stack;}",
            ]
            .concat(),
        ),
        (
            "irrelevant-arrow",
            [
                BINDING_HEAD,
                "var f=ops=>ops;while(pc<code.length){ops[code[pc++]]();}return stack;}",
            ]
            .concat(),
        ),
        ("wide-name", case(&format!("{wide}var z =x=>x;"))),
        ("wide-name-spaced", case(&format!("{wide}var z  =x=>x;"))),
        ("closure", closure),
    ]
}

/// One named [`proven_bindings`] case.
pub(crate) fn proven_binding(name: &str) -> String {
    proven_bindings()
        .into_iter()
        .find(|(case, _)| *case == name)
        .map(|(_, source)| source)
        .unwrap_or_else(|| panic!("no proven binding {name}"))
}

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

/// Every owned input the differential invariant covers: repository
/// fixtures, dispatch-shape fixtures and the review inputs above, as
/// (name, bytes, kind).
pub(crate) fn differential_inputs() -> Vec<(String, Vec<u8>, &'static str)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut inputs = Vec::new();
    for directory in [
        "tools/fixtures/dispatch-shapes",
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
    for (name, source) in [
        ("control", CONTROL_VM),
        ("block-let", BLOCK_LET_VM),
        ("handler-pc", HANDLER_PC_VM),
        ("shadowed-table", SHADOWED_TABLE_VM),
        ("shadow-control", SHADOW_CONTROL_VM),
        ("nested-table", NESTED_TABLE_VM),
        ("loop-body-router", LOOP_BODY_ROUTER_VM),
    ] {
        inputs.push((
            format!("review:{name}"),
            source.as_bytes().to_vec(),
            "javascript",
        ));
    }
    for (name, source, _) in STATIC_SHAPES {
        inputs.push((
            format!("shape:{name}"),
            source.as_bytes().to_vec(),
            "javascript",
        ));
    }
    for (name, source) in proven_bindings() {
        inputs.push((format!("binding:{name}"), source.into_bytes(), "javascript"));
    }
    for (name, source) in javascript().into_iter().chain(third_review_javascript()) {
        inputs.push((format!("review:{name}"), source.into_bytes(), "javascript"));
    }
    for (name, text, _, _, _) in WASM_STATIC_SHAPES {
        inputs.push((
            format!("shape:{name}"),
            wat::parse_str(text).expect("static shape module"),
            "wasm",
        ));
    }
    for (name, bytes) in wasm().into_iter().chain(third_review_wasm()) {
        inputs.push((format!("review:{name}"), bytes, "wasm"));
    }
    inputs
}

/// Minified owned bundle: independent modules with closures, objects, strings
/// and exports. The real VM sits in the middle, not before the large prefix.
pub(crate) fn owned_bundle(bytes: usize) -> String {
    use std::fmt::Write;
    let vm = HANDLER_PC_VM;
    let mut source = String::from("const ownedModules=[];");
    let mut inserted = false;
    let mut i = 0;
    while source.len() < bytes {
        if !inserted && source.len() >= bytes / 2 {
            source.push_str(vm);
            inserted = true;
        }
        write!(source, "ownedModules.push((function m{i}(seed){{const t=[\"owned-{i}\",\"value\",\"total\",\"reset\"],o={{name:t[0],count:seed}};function f(x){{return(x*33+o.count)>>>0}}return{{name:o.name,step:function(x){{o.count=f(x);return o.count}},reset:()=>{{o.count=seed;return t[3]}},map:x=>x.map(v=>f(v))}}}})({i}));").unwrap();
        i += 1;
    }
    source
}
