(module
  (type $handler (func (param i32) (result i32)))
  (table 4 funcref)
  (memory 1)
  (data (i32.const 0) "\01\07\02\03\00")
  (func (export "run") (param $pc i32) (result i32)
    (loop $dispatch
      local.get $pc
      i32.load8_u
      call_indirect (type $handler)
      local.get $pc
      i32.const 1
      i32.add
      local.set $pc
      br_table $dispatch $dispatch
    )
    i32.const 0))
