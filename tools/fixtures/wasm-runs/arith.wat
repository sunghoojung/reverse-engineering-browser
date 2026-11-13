;; Pure arithmetic: a return, two traps and unbounded recursion.
(module
  (func $run (export "run") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $double (export "double") (param $x i32) (result i32)
    local.get $x
    i32.const 1
    i32.shl)
  (func $divide (export "divide") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.div_s)
  (func $crash (export "crash")
    unreachable)
  (func $recurse (export "recurse") (result i32)
    call $recurse
    i32.const 1
    i32.add))
