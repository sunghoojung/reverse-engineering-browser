;; Synthetic fixture for wasm-identification-v1. Every byte is authored here;
;; nothing is captured. Rebuild the .wasm with make wasm-identification-fixtures.
;; A Go js/wasm shaped module: gojs runtime and syscall/js imports, the
;; getsp export, a go:buildid section, FNV-1a 64-bit constants and the SHA-1
;; initial state as i64 immediates, as Go keeps 32-bit values in i64.
(module
  (import "gojs" "runtime.wasmExit" (func $wasm_exit (param i32)))
  (import "gojs" "syscall/js.valueGet" (func $value_get (param i32)))
  (memory (export "mem") 1)
  (func $getsp (export "getsp") (result i32)
    i32.const 0)
  (func $hash (@name "hash/fnv.(*sum64a).Write") (param $byte i64) (result i64)
    i64.const 0xcbf29ce484222325
    local.get $byte
    i64.xor
    i64.const 0x100000001b3
    i64.mul)
  (func $sha1_init (@name "crypto/sha1.(*digest).Reset") (param $state i32)
    local.get $state
    i64.const 0x67452301
    i64.store offset=0
    local.get $state
    i64.const 0xefcdab89
    i64.store offset=8
    local.get $state
    i64.const 0x98badcfe
    i64.store offset=16
    local.get $state
    i64.const 0x10325476
    i64.store offset=24
    local.get $state
    i64.const 0xc3d2e1f0
    i64.store offset=32)
  (func $run (export "run") (param i32 i32))
  (@custom "go:buildid" "fixture-build-id"))
