;; Spike only (2026-09-27, round 11). aprv.wasm's shape with a second table:
;; more instance resources than the Rust wrapper's StoreLimits (tables = 1) allow.
(module
  (import "aprv" "clock_now_ms" (func (result f64)))
  (import "aprv" "random_get" (func (param i32 i32) (result i32)))
  (memory (export "memory") 27)
  (table 1 funcref)
  (table 1 funcref)
  (func (export "_initialize"))
  (func (export "aprv_abi_version") (result i32) (i32.const 1))
  (func (export "hostile") (param i32 i32) (result i32) (i32.const 42)))
