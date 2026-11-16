;; An import that returns 40 values per call.
(module
  (import "env" "many" (func $many (result
    i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64
    i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)))
  (func (export "run") (result i64)
    call $many
    drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop
    drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop drop))
