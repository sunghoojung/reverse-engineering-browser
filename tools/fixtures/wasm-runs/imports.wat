;; Nondeterministic host imports a run must stub: a clock, a random source
;; that takes an argument, and an imported memory.
(module
  (import "env" "now" (func $now (result f64)))
  (import "env" "random" (func $random (param i32) (result i32)))
  (import "env" "memory" (memory 1))
  (func $mix (export "mix") (param $x i32) (result i32)
    (local $first f64)
    call $now
    local.set $first
    local.get $x
    call $random
    call $now
    i32.trunc_f64_s
    i32.add
    local.get $x
    i32.add))
