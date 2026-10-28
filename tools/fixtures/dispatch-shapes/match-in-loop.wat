;; Repository-owned fixture. Ordinary code: a counting loop advances i, but
;; the branch table selects on a struct field that the loop never advances.
(module
  (memory (export "memory") 1)
  (func $weigh (export "weigh") (param $self i32) (param $count i32) (result i32)
    (local $i i32) (local $total i32)
    (block $exit
      (loop $next
        (br_if $exit (i32.ge_u (local.get $i) (local.get $count)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (block $heavy
          (block $light
            (block $none
              (br_table $none $light $heavy (i32.load8_u offset=4 (local.get $self))))
            (br $next))
          (local.set $total (i32.add (local.get $total) (i32.const 1)))
          (br $next))
        (local.set $total (i32.add (local.get $total) (i32.const 2)))
        (br $next)))
    (local.get $total)))
