;; Synthetic fixture for wasm-identification-v1. Every byte is authored here;
;; nothing is captured. Rebuild the .wasm with make wasm-identification-fixtures.
;; An Emscripten and C shaped module: Emscripten, WASI and invoke imports,
;; libc and stack exports, a complete AES S-box read through a load offset,
;; a CRC-32 table cut after 32 of 256 entries, the MD5 initial state, the
;; ChaCha constant, and four MD5 sine values as immediates.
(module
  (@producers
    (language "C11" "")
    (processed-by "clang" "17.0.0")
    (sdk "Emscripten" "3.1.50"))
  (import "env" "emscripten_resize_heap" (func $resize (param i32) (result i32)))
  (import "env" "__syscall_openat" (func $openat (param i32 i32 i32 i32) (result i32)))
  (import "env" "invoke_vii" (func $invoke (param i32 i32 i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func $ctors (export "__wasm_call_ctors"))
  (func $c_malloc (export "malloc") (param i32) (result i32)
    i32.const 0)
  (func $c_free (export "free") (param i32))
  (func $stack_save (export "stackSave") (result i32)
    i32.const 0)
  (func $sub_bytes (param $byte i32) (result i32)
    local.get $byte
    i32.load8_u offset=1024)
  (func $md5_round (param $a i32) (result i32)
    local.get $a
    i32.const 0xd76aa478
    i32.add
    i32.const 0xe8c7b756
    i32.add
    i32.const 0x242070db
    i32.add
    i32.const 0xc1bdceee
    i32.add)
  (data (i32.const 1024)
    "\63\7c\77\7b\f2\6b\6f\c5\30\01\67\2b\fe\d7\ab\76\ca\82\c9\7d\fa\59\47\f0\ad\d4\a2\af\9c\a4\72\c0"
    "\b7\fd\93\26\36\3f\f7\cc\34\a5\e5\f1\71\d8\31\15\04\c7\23\c3\18\96\05\9a\07\12\80\e2\eb\27\b2\75"
    "\09\83\2c\1a\1b\6e\5a\a0\52\3b\d6\b3\29\e3\2f\84\53\d1\00\ed\20\fc\b1\5b\6a\cb\be\39\4a\4c\58\cf"
    "\d0\ef\aa\fb\43\4d\33\85\45\f9\02\7f\50\3c\9f\a8\51\a3\40\8f\92\9d\38\f5\bc\b6\da\21\10\ff\f3\d2"
    "\cd\0c\13\ec\5f\97\44\17\c4\a7\7e\3d\64\5d\19\73\60\81\4f\dc\22\2a\90\88\46\ee\b8\14\de\5e\0b\db"
    "\e0\32\3a\0a\49\06\24\5c\c2\d3\ac\62\91\95\e4\79\e7\c8\37\6d\8d\d5\4e\a9\6c\56\f4\ea\65\7a\ae\08"
    "\ba\78\25\2e\1c\a6\b4\c6\e8\dd\74\1f\4b\bd\8b\8a\70\3e\b5\66\48\03\f6\0e\61\35\57\b9\86\c1\1d\9e"
    "\e1\f8\98\11\69\d9\8e\94\9b\1e\87\e9\ce\55\28\df\8c\a1\89\0d\bf\e6\42\68\41\99\2d\0f\b0\54\bb\16")
  (data (i32.const 2048)
    "\00\00\00\00\96\30\07\77\2c\61\0e\ee\ba\51\09\99\19\c4\6d\07\8f\f4\6a\70\35\a5\63\e9\a3\95\64\9e"
    "\32\88\db\0e\a4\b8\dc\79\1e\e9\d5\e0\88\d9\d2\97\2b\4c\b6\09\bd\7c\b1\7e\07\2d\b8\e7\91\1d\bf\90"
    "\64\10\b7\1d\f2\20\b0\6a\48\71\b9\f3\de\41\be\84\7d\d4\da\1a\eb\e4\dd\6d\51\b5\d4\f4\c7\85\d3\83"
    "\56\98\6c\13\c0\a8\6b\64\7a\f9\62\fd\ec\c9\65\8a\4f\5c\01\14\d9\6c\06\63\63\3d\0f\fa\f5\0d\08\8d")
  (data (i32.const 4096) "\01\23\45\67\89\ab\cd\ef\fe\dc\ba\98\76\54\32\10")
  (data (i32.const 4160) "expand 32-byte k"))
