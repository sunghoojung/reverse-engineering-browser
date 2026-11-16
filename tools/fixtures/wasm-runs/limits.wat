;; Five 64-page memories and three 5,000-element tables: each fits the default
;; limits alone, but the totals (320 pages, 15,000 elements) do not.
(module
  (memory $a 64) (memory $b 64) (memory $c 64) (memory $d 64) (memory $e 64)
  (func (export "run") (result i32) i32.const 1))
