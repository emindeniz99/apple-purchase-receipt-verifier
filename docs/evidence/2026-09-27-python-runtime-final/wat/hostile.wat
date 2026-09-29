;; Spike only (2026-09-27, round 11). A hostile guest with aprv.wasm's import
;; and lifecycle shape (imports in aprv.wasm's order, memory, _initialize,
;; aprv_abi_version = 1), plus one export `hostile(op, arg) -> i32` whose ops
;; are the resource-exhaustion cases of py/exhaust.py.
(module
  (import "aprv" "clock_now_ms" (func $clock (result f64)))
  (import "aprv" "random_get" (func $random_get (param i32 i32) (result i32)))
  (memory (export "memory") 27)              ;; aprv.wasm's initial size, no maximum
  (table 1 funcref)
  (type $v_i (func (result i32)))
  (func (export "_initialize"))
  (func (export "aprv_abi_version") (result i32) (i32.const 1))
  (func $recurse (param i32) (result i32)
    (i32.add (call $recurse (i32.add (local.get 0) (i32.const 1))) (i32.const 1)))
  (func $recurse_fat (param i32) (result i32)
    (local i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64
           i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    (local.set 1 (i64.extend_i32_u (local.get 0)))
    (i32.add (call $recurse_fat (i32.add (local.get 0) (i32.const 1))) (i32.wrap_i64 (local.get 1))))
  (func (export "hostile") (param $op i32) (param $arg i32) (result i32)
    (local $n i32)
    ;; 0: benign, returns 42
    (if (i32.eqz (local.get $op)) (then (return (i32.const 42))))
    ;; 1: infinite loop
    (if (i32.eq (local.get $op) (i32.const 1)) (then (loop $l (br $l))))
    ;; 2: unbounded recursion (thin frames)
    (if (i32.eq (local.get $op) (i32.const 2)) (then (return (call $recurse (i32.const 0)))))
    ;; 3: unbounded recursion (33-local frames)
    (if (i32.eq (local.get $op) (i32.const 3)) (then (return (call $recurse_fat (i32.const 0)))))
    ;; 4: grow one page at a time until memory is $arg pages or grow fails; returns the final page count
    (if (i32.eq (local.get $op) (i32.const 4)) (then
      (block $done (loop $g
        (br_if $done (i32.ge_u (memory.size) (local.get $arg)))
        (br_if $done (i32.eq (memory.grow (i32.const 1)) (i32.const -1)))
        ;; touch the new page so it is really committed
        (i32.store (i32.sub (i32.mul (memory.size) (i32.const 65536)) (i32.const 4)) (i32.const 1))
        (br $g)))
      (return (memory.size))))
    ;; 5: one memory.grow of $arg pages; returns grow's result (-1 = refused)
    (if (i32.eq (local.get $op) (i32.const 5)) (then (return (memory.grow (local.get $arg)))))
    ;; 6: aprv.random_get with a negative pointer
    (if (i32.eq (local.get $op) (i32.const 6)) (then (return (call $random_get (i32.const -16) (i32.const 32)))))
    ;; 7: aprv.random_get straddling the end of memory
    (if (i32.eq (local.get $op) (i32.const 7)) (then
      (return (call $random_get (i32.sub (i32.mul (memory.size) (i32.const 65536)) (i32.const 4)) (i32.const 16)))))
    ;; 8: store beyond linear memory
    (if (i32.eq (local.get $op) (i32.const 8)) (then (i32.store (i32.const 0xFFFFFFF0) (i32.const 1)) (return (i32.const 0))))
    ;; 9: call_indirect through an empty table slot
    (if (i32.eq (local.get $op) (i32.const 9)) (then (return (call_indirect (type $v_i) (i32.const 0)))))
    ;; 10: integer divide by zero
    (if (i32.eq (local.get $op) (i32.const 10)) (then (return (i32.div_s (i32.const 1) (local.get $arg)))))
    (unreachable))
)
