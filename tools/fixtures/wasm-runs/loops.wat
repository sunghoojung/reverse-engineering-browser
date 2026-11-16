;; A start function that never returns, a loop that never returns, and a
;; function that returns 42. The start function runs only when a run asks.
(module
  (func $forever
    (loop $again
      br $again))
  (func $answer (export "answer") (result i32)
    i32.const 42)
  (func $spin (export "spin")
    (loop $again
      br $again))
  (start $forever))
