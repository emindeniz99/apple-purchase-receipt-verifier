;; A test double for aprv.wasm's ABI, aprv:verifier@1.0.0, used by the
;; facade tests to choose the module's answer. It holds no verification
;; logic and is never shipped in the package. After the Go host's
;; go/testdata/mirror/mirror.wat, with the out-of-range cases added.
;;
;;   verify-receipt, verify-signed-data, verify-receipt-endpoint
;;       answer with their input bytes, unchanged, so a test passes the
;;       JSON it wants back. The first input byte selects a misbehaviour:
;;         '!'  trap (unreachable)
;;         '%'  a result pointer outside memory (the return area is fine)
;;         '^'  a return area outside memory
;;         '+'  grow memory by 1,100 pages (about 69 MiB), then echo
;;       The endpoint traps on an env other than 0 or 1, as aprv.wasm does.
;;   init
;;       answers {"ok":true}, or a refusal when the configuration is over
;;       100 bytes.
;;
;; Rebuild with: wasm-tools parse double.wat -o double.wasm
(module
  (memory (export "memory") 2)
  (global $heap (mut i32) (i32.const 4096))
  (data (i32.const 1024) "{\"ok\":true}")
  (data (i32.const 1056) "{\"ok\":false,\"message\":\"the double refuses this configuration\"}")

  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32) (local $end i32) (local $have i32)
    global.get $heap
    local.set $p
    local.get $p
    local.get 3
    i32.add
    local.tee $end
    global.set $heap
    memory.size
    i32.const 65536
    i32.mul
    local.set $have
    local.get $end
    local.get $have
    i32.gt_u
    if
      local.get $end
      local.get $have
      i32.sub
      i32.const 65535
      i32.add
      i32.const 65536
      i32.div_u
      memory.grow
      i32.const -1
      i32.eq
      if unreachable end
    end
    local.get $p)

  ;; answer(ptr, len): the return area at 2048 points at the input itself,
  ;; unless the first byte asks for a misbehaviour.
  (func $answer (param $ptr i32) (param $len i32) (result i32)
    (local $first i32)
    local.get $len
    if
      local.get $ptr
      i32.load8_u
      local.set $first
      ;; '!' traps
      local.get $first
      i32.const 33
      i32.eq
      if unreachable end
      ;; '%' answers a result pointer outside memory
      local.get $first
      i32.const 37
      i32.eq
      if
        i32.const 2048
        i32.const 0xFFFFFF00
        i32.store
        i32.const 2052
        i32.const 64
        i32.store
        i32.const 2048
        return
      end
      ;; '^' answers a return area outside memory
      local.get $first
      i32.const 94
      i32.eq
      if
        i32.const 0xFFFFFFFC
        return
      end
      ;; '+' grows memory past the pool's reuse limit
      local.get $first
      i32.const 43
      i32.eq
      if
        i32.const 1100
        memory.grow
        i32.const -1
        i32.eq
        if unreachable end
      end
    end
    i32.const 2048
    local.get $ptr
    i32.store
    i32.const 2052
    local.get $len
    i32.store
    i32.const 2048)

  (func (export "aprv:verifier/verify@1.0.0#init") (param $ptr i32) (param $len i32) (result i32)
    i32.const 2048
    local.get $len
    i32.const 100
    i32.gt_u
    if (result i32) i32.const 1056 else i32.const 1024 end
    i32.store
    i32.const 2052
    local.get $len
    i32.const 100
    i32.gt_u
    if (result i32) i32.const 62 else i32.const 11 end
    i32.store
    i32.const 2048)

  (func (export "aprv:verifier/verify@1.0.0#verify-receipt") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@1.0.0#verify-signed-data") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@1.0.0#verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
    local.get 0
    i32.const 1
    i32.gt_u
    if unreachable end
    local.get 2
    local.get 3
    call $answer)

  (func (export "cabi_post_aprv:verifier/verify@1.0.0#init") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-receipt") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-signed-data") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-receipt-endpoint") (param i32) i32.const 4096 global.set $heap)
)
