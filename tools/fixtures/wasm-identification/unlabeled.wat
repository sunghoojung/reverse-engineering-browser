;; Synthetic fixture for wasm-identification-v1. Every byte is authored here;
;; nothing is captured. Rebuild the .wasm with make wasm-identification-fixtures.
;; A module with no toolchain evidence at all: nothing may be concluded.
(module
  (func (export "run") (param i32) (result i32)
    local.get 0
    i32.const 7
    i32.add))
