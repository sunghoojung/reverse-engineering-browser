;; Build A of a small synthetic program. Build B (build-b.wat) is the same
;; program after a rebuild: one import added, static data moved, one function
;; edited, one removed, one added and one rewritten. Functions are unnamed so
;; matching cannot lean on a name section; two carry export names.
(module
  (import "env" "log" (func (param i32)))                       ;; 0
  (memory (export "memory") 1)
  (data (i32.const 1024) "origin-trace module diff fixture")
  ;; 1: a mixing step, byte-identical in B
  (func (param i32) (result i32)
    local.get 0 i32.const 0x9e3779b9 i32.mul
    local.get 0 i32.const 16 i32.shr_u i32.xor)
  ;; 2: reads static data, which moves in B
  (func (result i32) i32.const 1024 i32.load)
  ;; 3: a step whose constant changes in B
  (func (param i32) (result i32) local.get 0 call 1 i32.const 7 i32.add)
  ;; 4: the export that calls everything
  (func (export "run") (param i32) (result i32)
    local.get 0 call 3 call 2 i32.add
    local.get 0 call 0)
  ;; 5: removed in B
  (func (param i64) (result i64) local.get 0 i64.const 3 i64.shl)
  ;; 6, 7: identical stubs, so no pair can be chosen
  (func (result i32) i32.const 0)
  (func (result i32) i32.const 0)
  ;; 8: a byte hash loop, rewritten slightly in B
  (func (export "checksum") (param i32 i32) (result i32) (local i32)
    i32.const 5381 local.set 2
    block
      loop
        local.get 1 i32.eqz br_if 1
        local.get 2 i32.const 5 i32.shl local.get 2 i32.add
        local.get 0 i32.load8_u i32.add local.set 2
        local.get 0 i32.const 1 i32.add local.set 0
        local.get 1 i32.const 1 i32.sub local.set 1
        br 0
      end
    end
    local.get 2))
