;; Repository-owned fixture. Handlers live in a funcref table filled by two
;; active element segments: one at offset 1, one at offset 5. Slot 0 and
;; slot 4 stay empty, and slot 6 holds a function of a different type.
(module
  (type $handler (func (param i32) (result i32)))
  (type $other (func))
  (memory (export "memory") 1)
  (table 8 funcref)
  (func $nop (type $handler) (local.get 0))
  (func $inc (type $handler) (i32.add (local.get 0) (i32.const 1)))
  (func $dec (type $handler) (i32.sub (local.get 0) (i32.const 1)))
  (func $dbl (type $handler) (i32.shl (local.get 0) (i32.const 1)))
  (func $idle (type $other))
  (elem (i32.const 1) func $nop $inc $dec)
  (elem (i32.const 5) func $dbl $idle)
  (func $run (export "run") (param $code i32) (param $len i32) (result i32)
    (local $pc i32) (local $acc i32)
    (block $exit
      (loop $dispatch
        (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
        (local.set $acc
          (call_indirect (type $handler)
            (local.get $acc)
            (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
        (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
        (br $dispatch)))
    (local.get $acc)))
