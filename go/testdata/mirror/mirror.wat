;; A test double for aprv.wasm's ABI, aprv:verifier@0.2.0, used by the
;; facade tests to choose the module's answer. It holds no verification
;; logic and is never embedded in the package.
;;
;;   verify-receipt, verify-signed-data, verify-receipt-endpoint
;;       answer with their input bytes, unchanged, so a test passes the
;;       JSON it wants back. An input starting with '!' traps. The endpoint
;;       traps on an env other than 0 or 1 (aprv.wasm reads only the low
;;       byte, so it traps on 2 to 255 but not on 256).
;;   init
;;       answers the real module's answer for the built-in roots when the
;;       configuration is {} (two bytes or fewer): max_input_bytes 3145729,
;;       the four Apple list URLs and a null revocation_valid_until_ms. A
;;       configuration of 3 to 100 bytes gets the same max_input_bytes, two
;;       test URLs and 1795046400000 (2026-11-19T00:00:00Z); one over 100
;;       bytes gets a refusal (one caller-supplied root is over 1,000).
;;
;; Rebuild with: wasm-tools parse mirror.wat -o mirror.wasm
(module
  (memory (export "memory") 2)
  (global $heap (mut i32) (i32.const 4096))
  (data (i32.const 1024) "{\"ok\":true,\"max_input_bytes\":3145729,\"revocation_urls\":[\"http://crl.apple.com/root.crl\",\"http://crl.apple.com/applerootcag3.crl\",\"http://crl.apple.com/wwdrg5.crl\",\"http://crl.apple.com/wwdrg6.crl\"],\"revocation_valid_until_ms\":null}")
  (data (i32.const 1280) "{\"ok\":true,\"max_input_bytes\":3145729,\"revocation_urls\":[\"http://crl.example.test/a.crl\",\"https://crl.example.test/a.crl\"],\"revocation_valid_until_ms\":1795046400000}")
  (data (i32.const 1536) "{\"ok\":false,\"message\":\"the double refuses this configuration\"}")

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

  (func (export "aprv:verifier/verify@0.2.0#init") (param $ptr i32) (param $len i32) (result i32)
    (local $at i32) (local $n i32)
    local.get $len
    i32.const 100
    i32.gt_u
    if
      i32.const 1536
      local.set $at
      i32.const 62
      local.set $n
    else
      local.get $len
      i32.const 2
      i32.le_u
      if
        i32.const 1024
        local.set $at
        i32.const 231
        local.set $n
      else
        i32.const 1280
        local.set $at
        i32.const 164
        local.set $n
      end
    end
    i32.const 2048
    local.get $at
    i32.store
    i32.const 2052
    local.get $n
    i32.store
    i32.const 2048)

  (func (export "aprv:verifier/verify@0.2.0#verify-receipt") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@0.2.0#verify-signed-data") (param i64 i32 i32) (result i32)
    local.get 1
    local.get 2
    call $answer)
  (func (export "aprv:verifier/verify@0.2.0#verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
    local.get 0
    i32.const 1
    i32.gt_u
    if unreachable end
    local.get 2
    local.get 3
    call $answer)

  (func (export "cabi_post_aprv:verifier/verify@0.2.0#init") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.2.0#verify-receipt") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.2.0#verify-signed-data") (param i32) i32.const 4096 global.set $heap)
  (func (export "cabi_post_aprv:verifier/verify@0.2.0#verify-receipt-endpoint") (param i32) i32.const 4096 global.set $heap)
)
