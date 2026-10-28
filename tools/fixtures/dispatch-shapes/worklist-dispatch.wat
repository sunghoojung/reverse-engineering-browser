;; Repository-owned fixture. A worklist drain, not an interpreter: each item
;; id comes from a pop call, and its kind is looked up in a byte table.
;; Nothing advances the index arithmetically.
(module
  (memory (export "memory") 1)
  (func $pop (param $queue i32) (result i32)
    (i32.store offset=4 (local.get $queue)
      (i32.sub (i32.load offset=4 (local.get $queue)) (i32.const 1)))
    (i32.load (local.get $queue)))
  (func $drain (export "drain") (param $queue i32) (param $kinds i32) (result i32)
    (local $id i32) (local $total i32)
    (block $exit
      (loop $next
        (br_if $exit (i32.eqz (i32.load offset=4 (local.get $queue))))
        (local.set $id (call $pop (local.get $queue)))
        (block $two
          (block $one
            (block $zero
              (br_table $zero $one $two
                (i32.load8_u (i32.add (local.get $kinds) (local.get $id)))))
            (local.set $total (i32.add (local.get $total) (i32.const 1)))
            (br $next))
          (local.set $total (i32.add (local.get $total) (i32.const 2)))
          (br $next))
        (br $next)))
    (local.get $total)))
