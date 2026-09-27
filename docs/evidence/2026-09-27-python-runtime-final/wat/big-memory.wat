;; Spike only (2026-09-27, round 11). aprv.wasm's shape declaring 2,048 pages
;; (128 MiB) of initial memory: above the Rust wrapper's 64 MiB cap.
(module
  (import "aprv" "clock_now_ms" (func (result f64)))
  (import "aprv" "random_get" (func (param i32 i32) (result i32)))
  (memory (export "memory") 2048)
  (func (export "_initialize"))
  (func (export "aprv_abi_version") (result i32) (i32.const 1))
  (func (export "hostile") (param i32 i32) (result i32) (i32.const 42)))
