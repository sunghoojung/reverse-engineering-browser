;; Repository-owned value-flow fixture: every shape the wasm-value-flow-v1
;; slice reports, with no third-party code. See README.md for what each
;; function exercises.
(module
  (type $pair (func (param i32 i32) (result i32)))
  (import "env" "send" (func $send (param i32 i32)))
  (import "env" "now" (func $now (result i32)))
  (memory 1)
  (global $g (mut i32) (i32.const 0))
  (table 2 funcref)
  (elem (i32.const 0) $mix $mix)

  ;; Function 2: params, a load with an address expression, a forwarded
  ;; store, a loop join, an if/else join, an import call, a global, a store
  ;; address and the return.
  (func $mix (export "mix") (param $seed i32) (param $len i32) (result i32)
    (local $acc i32) (local $i i32)
    (local.set $acc (i32.xor (local.get $seed) (i32.load offset=8 (local.get $len))))
    (i32.store (i32.const 64) (local.get $acc))
    (local.set $acc (i32.add (i32.load (i32.const 64)) (call $now)))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $acc (i32.add (i32.mul (local.get $acc) (i32.const 31)) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.set $acc
      (if (result i32) (i32.and (local.get $acc) (i32.const 1))
        (then (i32.shl (local.get $acc) (i32.const 1)))
        (else (i32.shr_u (local.get $acc) (i32.const 1)))))
    (call $send (local.get $acc) (local.get $len))
    (global.set $g (local.get $acc))
    (i32.store8 (local.get $acc) (local.get $seed))
    (local.get $acc))

  ;; Function 3: a direct caller of $mix, a br_table selector and a
  ;; call_indirect selector fed by the call's result.
  (func $route (export "route") (param $x i32) (result i32)
    (local $r i32)
    (local.set $r (call $mix (local.get $x) (i32.const 16)))
    (block $b
      (block $a
        (br_table $a $b (local.get $r)))
      (return (i32.const 0)))
    (call_indirect (type $pair) (local.get $r) (i32.const 4) (i32.and (local.get $r) (i32.const 1))))

  ;; Function 4: a block result joined from a br_if value and the fallthrough,
  ;; and a store followed by a call, so the later load is not forwarded.
  (func $pick (export "pick") (param $c i32) (param $v i32) (result i32)
    (i32.store (i32.const 128) (local.get $v))
    (drop (call $now))
    (drop (i32.load (i32.const 128)))
    (block $out (result i32)
      (br_if $out (i32.const 7) (local.get $c))
      (drop)
      (local.get $v))))
