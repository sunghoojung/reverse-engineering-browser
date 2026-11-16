;; A loop that only calls an import: cheap in fuel, slow in time.
(module
  (import "env" "tick" (func $tick (result i32)))
  (func (export "run")
    (loop $again
      call $tick
      drop
      br $again)))
