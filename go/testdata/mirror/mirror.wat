;; A test double for aprv.wasm's ABI, aprv:verifier@0.1.0, used by the
;; facade tests to choose the module's answer. It holds no verification
;; logic and is never embedded in the package.
;;
;;   verify-receipt, verify-signed-data, verify-receipt-endpoint
;;       answer with their input bytes, unchanged, so a test passes the
;;       JSON it wants back. An input starting with '!' traps. The endpoint
;;       traps on an env other than 0 or 1, as aprv.wasm does.
;;   init
;;       answers {"ok":true,"max_input_bytes":3145729}, the real module's
;;       answer, or a refusal when the configuration is over 100 bytes (one
;;       caller-supplied root is over 1,000).
;;
;; Rebuild with: wasm-tools parse mirror.wat -o mirror.wasm
(module
  (memory (export "memory") 2)
  (global $heap (mut i32) (i32.const 4096))
  (data (i32.const 1024) "{\"ok\":true,\"max_input_bytes\":3145729}")
  (data (i32.const 1088) "{\"ok\":false,\"message\":\"the double refuses this configuration\"}")

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

  ;; answer(ptr, len): the return area at 2048 points at the input itself.
  (func $answer (param $ptr i32) (param $len i32) (result i32)
    local.get $len
    if
      local.get $ptr
      i32.load8_u
      i32.const 33
      i32.eq
      if unreachable end
    end
    i32.const 2048
    local.get $ptr
    i32.store
    i32.const 2052
    local.get $len
    i32.store
    i32.const 2048)

  (func (export "aprv:verifier/verify@0.1.0#init") (param $ptr i32) (param $len i32) (result i32)
    local.get $len
    i32.const 100
    i32.gt_u
    if (result i32) i32.const 1088 else i32.const 1024 end
    local.set $ptr
    i32.const 2048
    local.get $ptr
    i32.store
    i32.const 2052
    local.get $len
    i32.const 100
    i32.gt_u
    if (result i32) i32.const 62 else i32.const 37 end
    i32.store
    i32.const 2048)

  (func (export "aprv:verifier/verify@0.1.0#verify-receipt") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@0.1.0#verify-signed-data") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@0.1.0#verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
    local.get 0
    i32.const 1
    i32.gt_u
    if unreachable end
    local.get 2
    local.get 3
    call $answer)

  (func (export "cabi_post_aprv:verifier/verify@0.1.0#init") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.1.0#verify-receipt") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.1.0#verify-signed-data") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.1.0#verify-receipt-endpoint") (param i32) i32.const 4096 global.set $heap)
)
