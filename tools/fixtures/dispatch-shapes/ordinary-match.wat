;; Repository-owned fixture. Ordinary compiled branching, not a VM:
;; a 40-arm match on a struct field with no loop, and a small br_table on
;; a loop-invariant argument inside a counting loop.
(module
  (memory (export "memory") 1)
  (func $kind_weight (export "kind_weight") (param $self i32) (result i32)
    (block $d
      (block $c
        (block $b
          (block $a
            (br_table
              $a $b $c $d $a $b $c $d $a $b $c $d $a $b $c $d $a $b $c $d
              $a $b $c $d $a $b $c $d $a $b $c $d $a $b $c $d $a $b $c $d
              $d
              (i32.load8_u offset=4 (local.get $self))))
          (return (i32.const 1)))
        (return (i32.const 2)))
      (return (i32.const 3)))
    (i32.const 4))
  (func $sum (export "sum") (param $mode i32) (param $count i32) (result i32)
    (local $i i32) (local $total i32)
    (block $exit
      (loop $next
        (br_if $exit (i32.ge_u (local.get $i) (local.get $count)))
        (block $double
          (block $single
            (br_table $single $double (local.get $mode)))
          (local.set $total (i32.add (local.get $total) (local.get $i)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next))
        (local.set $total (i32.add (local.get $total) (i32.shl (local.get $i) (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.get $total)))
