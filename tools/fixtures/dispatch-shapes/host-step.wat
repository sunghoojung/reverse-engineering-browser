;; Repository-owned fixture. A host-driven step function: each host call
;; reloads pc from the machine frame, executes one opcode, and stores pc + 1.
;; Dispatch fires once per call; the loop lives in the host.
(module
  (memory (export "memory") 1)
  (func $step (export "step") (param $vm i32) (result i32)
    (local $pc i32) (local $op i32)
    (local.set $pc (i32.load offset=8 (local.get $vm)))
    (local.set $op (i32.load8_u (i32.add (i32.load (local.get $vm)) (local.get $pc))))
    (i32.store offset=8 (local.get $vm) (i32.add (local.get $pc) (i32.const 1)))
    (block $halt
      (block $dec
        (block $inc
          (br_table $inc $dec $halt (local.get $op)))
        (i32.store offset=12 (local.get $vm)
          (i32.add (i32.load offset=12 (local.get $vm)) (i32.const 1)))
        (return (i32.const 1)))
      (i32.store offset=12 (local.get $vm)
        (i32.sub (i32.load offset=12 (local.get $vm)) (i32.const 1)))
      (return (i32.const 1)))
    (i32.const 0)))
