;; Repository-owned fixture. The interpreter keeps pc in a frame slot in
;; linear memory: each iteration reloads it, fetches, and stores pc + 1 back.
(module
  (memory (export "memory") 1)
  (func $run (export "run") (param $frame i32) (param $code i32) (result i32)
    (local $pc i32) (local $op i32) (local $acc i32)
    (block $exit
      (loop $dispatch
        (local.set $pc (i32.load offset=8 (local.get $frame)))
        (local.set $op (i32.load8_u (i32.add (local.get $code) (local.get $pc))))
        (i32.store offset=8 (local.get $frame) (i32.add (local.get $pc) (i32.const 1)))
        (block $halt
          (block $dec
            (block $inc
              (br_table $inc $dec $halt (local.get $op)))
            (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
            (br $dispatch))
          (local.set $acc (i32.sub (local.get $acc) (i32.const 1)))
          (br $dispatch))
        (br $exit)))
    (local.get $acc)))
