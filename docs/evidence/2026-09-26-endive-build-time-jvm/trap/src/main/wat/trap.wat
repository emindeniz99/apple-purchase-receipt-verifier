;; Spike only (2026-09-26): a throwaway module for the trap/isolation smoke
;; test. It is compiled by the same Endive build-time route as aprv.wasm
;; (scripts/build.sh turns it into trap.wasm with `wasm-tools parse`).
;; Nothing here is part of the verifier.
(module
  (memory (export "memory") 1 1)          ;; exactly one 64 KiB page, no growth

  ;; Reads 4 bytes at any address: past 65,532 it is out of bounds.
  (func (export "load") (param $addr i32) (result i32)
    (i32.load (local.get $addr)))

  (func (export "store") (param $addr i32) (param $v i32)
    (i32.store (local.get $addr) (local.get $v)))

  ;; memory.fill past the end: a bulk-memory out-of-bounds access.
  (func (export "fill_oob")
    (memory.fill (i32.const 65000) (i32.const 7) (i32.const 1000)))

  (func (export "unreachable")
    unreachable)

  ;; Unbounded recursion: call-stack exhaustion.
  (func $deep (export "deep") (param $n i32) (result i32)
    (i32.add (call $deep (i32.add (local.get $n) (i32.const 1))) (i32.const 1)))

  (func (export "div0") (param $a i32) (result i32)
    (i32.div_s (i32.const 1) (local.get $a))))
