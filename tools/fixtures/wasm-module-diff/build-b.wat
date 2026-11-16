;; Build B: see build-a.wat. The checksum export is renamed, so its match
;; comes from structure alone.
(module
  (import "env" "log" (func (param i32)))                       ;; 0
  (import "env" "now" (func (result f64)))                      ;; 1, added
  (memory (export "memory") 1)
  (data (i32.const 4096) "origin-trace module diff fixture")
  ;; 2: unchanged
  (func (param i32) (result i32)
    local.get 0 i32.const 0x9e3779b9 i32.mul
    local.get 0 i32.const 16 i32.shr_u i32.xor)
  ;; 3: the same read of moved data
  (func (result i32) i32.const 4096 i32.load)
  ;; 4: the edited step
  (func (param i32) (result i32) local.get 0 call 2 i32.const 9 i32.add)
  ;; 5: the export, renumbered calls only
  (func (export "run") (param i32) (result i32)
    local.get 0 call 4 call 3 i32.add
    local.get 0 call 0)
  ;; 6, 7: the stubs
  (func (result i32) i32.const 0)
  (func (result i32) i32.const 0)
  ;; 8: the hash loop, now xor-folded
  (func (export "digest") (param i32 i32) (result i32) (local i32)
    i32.const 5381 local.set 2
    block
      loop
        local.get 1 i32.eqz br_if 1
        local.get 2 i32.const 5 i32.shl local.get 2 i32.add
        local.get 0 i32.load8_u i32.xor local.set 2
        local.get 0 i32.const 1 i32.add local.set 0
        local.get 1 i32.const 1 i32.sub local.set 1
        br 0
      end
    end
    local.get 2)
  ;; 9: added
  (func (param f32) (result f32) local.get 0 local.get 0 f32.mul))
