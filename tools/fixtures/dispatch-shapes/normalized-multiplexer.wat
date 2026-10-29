;; Repository-owned fixture. One-shot routers whose argument is normalized
;; before dispatch: masked to a byte, or clamped by a bounds guard. The
;; selector is still the caller's argument.
(module
  (func $alpha (param i32) (result i32) (i32.add (local.get 0) (i32.const 3)))
  (func $beta (param i32) (result i32) (i32.mul (local.get 0) (i32.const 5)))
  (func $gamma (param i32) (result i32) (i32.xor (local.get 0) (i32.const 7)))
  (func $route_masked (export "route_masked") (param $key i32) (param $x i32) (result i32)
    (local.set $key (i32.and (local.get $key) (i32.const 255)))
    (if (i32.eq (local.get $key) (i32.const 0x11))
      (then (return (call $alpha (local.get $x)))))
    (if (i32.eq (local.get $key) (i32.const 0x22))
      (then (return (call $beta (local.get $x)))))
    (if (i32.eq (local.get $key) (i32.const 0x33))
      (then (return (call $gamma (local.get $x)))))
    (i32.const -1))
  (func $route_guarded (export "route_guarded") (param $key i32) (param $x i32) (result i32)
    (if (i32.gt_u (local.get $key) (i32.const 2))
      (then (local.set $key (i32.const 0))))
    (block $c
      (block $b
        (block $a
          (br_table $a $b $c (local.get $key)))
        (return (call $alpha (local.get $x))))
      (return (call $beta (local.get $x))))
    (call $gamma (local.get $x))))
