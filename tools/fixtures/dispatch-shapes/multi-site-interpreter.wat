;; Repository-owned fixture. Three dispatch sites in one function: a one-shot
;; mode switch on an argument before the loop, the opcode dispatch, and an
;; operand-mode dispatch that fetches a second byte at the cursor.
(module
  (memory (export "memory") 1)
  (func $run (export "run") (param $mode i32) (param $code i32) (param $len i32) (result i32)
    (local $pc i32) (local $op i32) (local $acc i32) (local $operand i32)
    (block $fast
      (block $slow
        (br_table $slow $fast (local.get $mode)))
      (local.set $acc (i32.const 100)))
    (block $exit
      (loop $dispatch
        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
        (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
        (block $halt
          (block $load
            (block $inc
              (br_table $inc $load $halt (local.get $op)))
            (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
            (br $dispatch))
          (local.set $operand (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
          (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
          (block $wide
            (block $narrow
              (br_table $narrow $wide (local.get $operand)))
            (local.set $acc (i32.add (local.get $acc) (i32.const 2)))
            (br $dispatch))
          (local.set $acc (i32.add (local.get $acc) (i32.const 4)))
          (br $dispatch))
        (br $exit)))
    (local.get $acc)))
