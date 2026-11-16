;; Linear memory that is not exported: sum bytes into address 0, and grow.
(module
  (memory 1)
  (func $sum (export "sum") (param $ptr i32) (param $len i32) (result i32)
    (local $total i32)
    (block $done
      (loop $next
        local.get $len
        i32.eqz
        br_if $done
        local.get $total
        local.get $ptr
        i32.load8_u
        i32.add
        local.set $total
        local.get $ptr
        i32.const 1
        i32.add
        local.set $ptr
        local.get $len
        i32.const 1
        i32.sub
        local.set $len
        br $next))
    i32.const 0
    local.get $total
    i32.store
    local.get $total)
  (func $grow (export "grow") (param $pages i32) (result i32)
    local.get $pages
    memory.grow))
