;; Repository-owned fixture. A byte-code interpreter: the opcode is loaded
;; from code + pc, pc advances inside the loop, and br_table dispatches.
(module
  (memory (export "memory") 1)
  (func $run (export "run") (param $code i32) (param $len i32) (result i32)
    (local $pc i32) (local $acc i32) (local $op i32)
    (block $exit
      (loop $dispatch
        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
        (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
        (block $halt
          (block $dec
            (block $inc
              (block $nop
                (br_table $nop $inc $dec $halt $halt (local.get $op)))
              (br $dispatch))
            (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
            (br $dispatch))
          (local.set $acc (i32.sub (local.get $acc) (i32.const 1)))
          (br $dispatch))
        (br $exit)))
    (local.get $acc)))
