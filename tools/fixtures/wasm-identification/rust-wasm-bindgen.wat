;; Synthetic fixture for wasm-identification-v1. Every byte is authored here;
;; nothing is captured. Rebuild the .wasm with make wasm-identification-fixtures.
;; A Rust and wasm-bindgen shaped module: producers, glue imports, allocator
;; exports, mangled and demangled names, a SHA-256 round-constant table read
;; through its address, SHA-256 initial values as immediates, and a Base64
;; alphabet.
(module
  (@producers
    (language "Rust" "")
    (processed-by "rustc" "1.79.0")
    (processed-by "wasm-bindgen" "0.2.92"))
  (import "wbg" "__wbg_fetch_bd7e4e4b6ad8a1e6" (func $fetch (param i32) (result i32)))
  (import "wbg" "__wbindgen_object_drop_ref" (func $drop_ref (param i32)))
  (memory (export "memory") 17)
  (func $compress (@name "sha2::sha256::soft::compress::h0123456789abcdef") (param $block i32) (result i32)
    ;; K[i] is read from the table's static address plus 4 * i.
    i32.const 1048576
    local.get $block
    i32.const 2
    i32.shl
    i32.add
    i32.load)
  (func $init (@name "sha2::sha256::Sha256::new::h0123456789abcdef") (param $state i32)
    local.get $state
    i32.const 0x6a09e667
    i32.store offset=0
    local.get $state
    i32.const 0xbb67ae85
    i32.store offset=4
    local.get $state
    i32.const 0x3c6ef372
    i32.store offset=8
    local.get $state
    i32.const 0xa54ff53a
    i32.store offset=12
    local.get $state
    i32.const 0x510e527f
    i32.store offset=16
    local.get $state
    i32.const 0x9b05688c
    i32.store offset=20
    local.get $state
    i32.const 0x1f83d9ab
    i32.store offset=24
    local.get $state
    i32.const 0x5be0cd19
    i32.store offset=28)
  (func $encode (@name "base64::engine::encode::h0123456789abcdef") (param $index i32) (result i32)
    local.get $index
    i32.load8_u offset=1049088)
  (func $bindgen_malloc (export "__wbindgen_malloc") (param i32 i32) (result i32)
    i32.const 0)
  (func $bindgen_free (export "__wbindgen_free") (param i32 i32 i32))
  (func $panic (@name "_ZN4core9panicking5panic17h0123456789abcdefE"))
  (func $solve (export "solve") (param i32) (result i32)
    local.get 0
    call $fetch)
  (data (i32.const 1048576)
    "\98\2f\8a\42\91\44\37\71\cf\fb\c0\b5\a5\db\b5\e9\5b\c2\56\39\f1\11\f1\59\a4\82\3f\92\d5\5e\1c\ab"
    "\98\aa\07\d8\01\5b\83\12\be\85\31\24\c3\7d\0c\55\74\5d\be\72\fe\b1\de\80\a7\06\dc\9b\74\f1\9b\c1"
    "\c1\69\9b\e4\86\47\be\ef\c6\9d\c1\0f\cc\a1\0c\24\6f\2c\e9\2d\aa\84\74\4a\dc\a9\b0\5c\da\88\f9\76"
    "\52\51\3e\98\6d\c6\31\a8\c8\27\03\b0\c7\7f\59\bf\f3\0b\e0\c6\47\91\a7\d5\51\63\ca\06\67\29\29\14"
    "\85\0a\b7\27\38\21\1b\2e\fc\6d\2c\4d\13\0d\38\53\54\73\0a\65\bb\0a\6a\76\2e\c9\c2\81\85\2c\72\92"
    "\a1\e8\bf\a2\4b\66\1a\a8\70\8b\4b\c2\a3\51\6c\c7\19\e8\92\d1\24\06\99\d6\85\35\0e\f4\70\a0\6a\10"
    "\16\c1\a4\19\08\6c\37\1e\4c\77\48\27\b5\bc\b0\34\b3\0c\1c\39\4a\aa\d8\4e\4f\ca\9c\5b\f3\6f\2e\68"
    "\ee\82\8f\74\6f\63\a5\78\14\78\c8\84\08\02\c7\8c\fa\ff\be\90\eb\6c\50\a4\f7\a3\f9\be\f2\78\71\c6")
  (data (i32.const 1049088) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
  (@custom "target_features" "\02+\0fmutable-globals+\08sign-ext")
  (@custom "sourceMappingURL" "\1dhttps://cdn.test/app.wasm.map"))
