;; Three 5,000-element tables: 15,000 in total, over the default 10,000.
(module
  (table $a 5000 funcref) (table $b 5000 funcref) (table $c 5000 funcref)
  (func (export "run") (result i32) i32.const 1))
