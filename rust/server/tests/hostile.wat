;; A component with aprv.wasm's interface whose operations misbehave:
;; init answers {"ok":true}; verify-receipt loops forever; verify-signed-data
;; grows memory by 16,384 pages (1 GiB); verify-receipt-endpoint returns
;; bytes that are not UTF-8 as its string; and with env 1 asks the host
;; for 1 GiB of random bytes first.
;; Used by src/tests.rs (in process) and scripts/hostile-smoke.sh (a real
;; server process). Component text format; wasm-tools parse builds it.
(component
  (import "aprv:verifier/host@1.0.0" (instance $host
    (export "random-get" (func (param "len" u32) (result (list u8))))))
  (core module $libc
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 4096))
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p (global.get $bump))
      (global.set $bump (i32.and (i32.add (i32.add (global.get $bump) (local.get 3)) (i32.const 7)) (i32.const -8)))
      (local.get $p)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $mem))
  (alias core export $libc "cabi_realloc" (core func $realloc))
  (alias export $host "random-get" (func $random-get))
  (core func $random-get-lowered (canon lower (func $random-get) (memory $mem) (realloc $realloc)))
  (core module $m
    (import "libc" "memory" (memory 1))
    (import "host" "random-get" (func $random (param i32 i32)))
    (data (i32.const 16) "{\22ok\22:true}")
    (data (i32.const 64) "\ff\fe")
    (func $ret (param $p i32) (param $l i32) (result i32)
      (i32.store (i32.const 0) (local.get $p))
      (i32.store (i32.const 4) (local.get $l))
      (i32.const 0))
    (func (export "init") (param i32 i32) (result i32)
      (call $ret (i32.const 16) (i32.const 11)))
    (func (export "verify-receipt") (param i64 i32 i32) (result i32)
      (loop $l (br $l))
      (unreachable))
    (func (export "verify-signed-data") (param i64 i32 i32) (result i32)
      (drop (memory.grow (i32.const 16384)))
      (call $ret (i32.const 16) (i32.const 11)))
    (func (export "verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
      (if (i32.eq (local.get 0) (i32.const 1))
        (then (call $random (i32.const 0x40000000) (i32.const 8))))
      (call $ret (i32.const 64) (i32.const 2))))
  (core instance $i (instantiate $m
    (with "libc" (instance $libc))
    (with "host" (instance (export "random-get" (func $random-get-lowered))))))
  (func $init (param "config-json" (list u8)) (result string)
    (canon lift (core func $i "init") (memory $mem) (realloc $realloc)))
  (func $verify-receipt (param "now-ms" u64) (param "receipt-base64" (list u8)) (result string)
    (canon lift (core func $i "verify-receipt") (memory $mem) (realloc $realloc)))
  (func $verify-signed-data (param "now-ms" u64) (param "jws" (list u8)) (result string)
    (canon lift (core func $i "verify-signed-data") (memory $mem) (realloc $realloc)))
  (func $verify-receipt-endpoint (param "env" u32) (param "now-ms" u64) (param "request-json" (list u8)) (result string)
    (canon lift (core func $i "verify-receipt-endpoint") (memory $mem) (realloc $realloc)))
  (instance $verify
    (export "init" (func $init))
    (export "verify-receipt" (func $verify-receipt))
    (export "verify-signed-data" (func $verify-signed-data))
    (export "verify-receipt-endpoint" (func $verify-receipt-endpoint)))
  (export "aprv:verifier/verify@1.0.0" (instance $verify)))
