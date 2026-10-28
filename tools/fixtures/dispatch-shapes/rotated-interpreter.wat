;; Repository-owned fixture. A rotated interpreter loop, the shape an
;; optimizing compiler emits: the first opcode is fetched in the preheader,
;; and the latch advances pc and fetches the next opcode before branching back.
(module
  (memory (export "memory") 1)
  (func $run (export "run") (param $code i32) (param $len i32) (result i32)
    (local $pc i32) (local $op i32) (local $acc i32)
    (local.set $op (i32.load8_u (local.get $code)))
    (block $exit
      (loop $dispatch
        (block $next
          (block $halt
            (block $dec
              (block $inc
                (br_table $inc $dec $halt (local.get $op)))
              (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
              (br $next))
            (local.set $acc (i32.sub (local.get $acc) (i32.const 1)))
            (br $next))
          (br $exit))
        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
        (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
        (br $dispatch)))
    (local.get $acc)))
