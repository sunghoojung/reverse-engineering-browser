;; Float results whose Display form is longer than 64 characters.
(module
  (func (export "run") (result f64) f64.const 1e300)
  (func (export "small") (result f64) f64.const 1.2345678901234567e-50)
  (func (export "echo") (param f64 f32) (result f64 f32) local.get 0 local.get 1))
