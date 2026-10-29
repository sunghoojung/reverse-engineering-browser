;; Repository-owned fixture. Two one-shot routers: the caller's first
;; argument picks one internal function per call. The constants and arm
;; indexes are routing labels, not guest opcodes.
(module
  (func $alpha (param i32) (result i32) (i32.add (local.get 0) (i32.const 3)))
  (func $beta (param i32) (result i32) (i32.mul (local.get 0) (i32.const 5)))
  (func $gamma (param i32) (result i32) (i32.xor (local.get 0) (i32.const 7)))
  (func $delta (param i32) (result i32) (i32.sub (local.get 0) (i32.const 9)))
  (func $route (export "route") (param $key i32) (param $x i32) (result i32)
    (if (i32.eq (local.get $key) (i32.const 0x1a2b))
      (then (return (call $alpha (local.get $x)))))
    (if (i32.eq (local.get $key) (i32.const 0x2c3d))
      (then (return (call $beta (local.get $x)))))
    (if (i32.eq (local.get $key) (i32.const 0x3e4f))
      (then (return (call $gamma (local.get $x)))))
    (if (i32.eq (local.get $key) (i32.const 0x4a5b))
      (then (return (call $delta (local.get $x)))))
    (i32.const -1))
  (func $route_table (export "route_table") (param $key i32) (param $x i32) (result i32)
    (block $d
      (block $c
        (block $b
          (block $a
            (br_table $a $b $c $d (local.get $key)))
          (return (call $alpha (local.get $x))))
        (return (call $beta (local.get $x))))
      (return (call $gamma (local.get $x))))
    (call $delta (local.get $x))))
