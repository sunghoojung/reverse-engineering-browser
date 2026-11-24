;; One function of exception-handling control flow for the block graph.
;; README.md lists the edges its graph must draw. Tags 0 and 1 are imported,
;; so they may be one tag; 2 and 3 are defined here, each its own.
(module
  (import "env" "step" (func $step (param i32) (result i32)))
  (import "env" "error" (tag $error (param i32)))
  (import "env" "other" (tag $other (param i32)))
  (tag $parse (param i32))
  (tag $halt)
  (func (export "run") (param $x i32) (result i32)
    (local $acc i32)
    ;; try_table: the call may raise any tag, so it reaches both clauses; the
    ;; throw of $parse reaches only its own.
    (block $done
      (block $any
        (local.set $acc
          (block $parsed (result i32)
            (try_table (catch $parse $parsed) (catch_all $any)
              (local.set $acc (call $step (local.get $x)))
              (if (i32.eqz (local.get $acc))
                (then (throw $parse (local.get $x)))))
            (br $done)))
        (br $done))
      (local.set $acc (i32.const -1)))
    ;; Legacy try, which the pinned wat parses only in flat form: $error may
    ;; be $other, so its catch may take the throw and catch_all certainly
    ;; does. The rethrow in a catch body is outside the try's body, so nothing
    ;; here catches it.
    try
      (if (i32.gt_s (local.get $acc) (i32.const 100))
        (then (throw $error (local.get $acc))))
    catch $other
      local.set $acc
      (if (i32.eqz (local.get $acc)) (then (rethrow 1)))
    catch_all
      (local.set $acc (i32.const -2))
    end
    ;; delegate 0 hands the inner try's exceptions to the try around it.
    try
      try
        (local.set $acc (call $step (local.get $acc)))
      delegate 0
    catch_all
      (local.set $acc (i32.const -3))
    end
    ;; Only $error is caught, and $other may be $error: it may escape.
    try
      (if (local.get $x) (then (throw $other (local.get $x))))
    catch $error
      local.set $acc
    end
    ;; No handler at all: $halt leaves the function.
    (if (i32.lt_s (local.get $acc) (i32.const 0))
      (then (throw $halt)))
    ;; catch_all_ref keeps the exception; throw_ref raises it again, outside
    ;; any handler.
    (throw_ref
      (block $kept (result exnref)
        (try_table (catch_all_ref $kept)
          (if (i32.eq (local.get $acc) (i32.const 7)) (then (throw $halt))))
        (return (local.get $acc))))))
