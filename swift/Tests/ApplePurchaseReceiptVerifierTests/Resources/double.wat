;; A test double for aprv.wasm's ABI, aprv:verifier@0.2.0, used by the
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
;;       The endpoint traps on an env other than 0 or 1 (aprv.wasm reads
;;       only the low byte, so it traps on 2 to 255 but not on 256).
;;   init
;;       answers the real module's answer for the built-in roots,
;;       max_input_bytes 3145729, the four Apple list URLs and a null
;;       revocation_valid_until_ms, or a refusal when the configuration is
;;       over 100 bytes. A configuration of 3 to 100 bytes that starts with
;;       '{' gets the same max_input_bytes, two test URLs and
;;       1795046400000 (2026-11-19T00:00:00Z). One whose first byte is 'o'
;;       gets {"ok":true}, the answer of a module older than
;;       max_input_bytes; 'm' gets max_input_bytes and no revocation
;;       members, the answer of a module older than revocation; 's' gets an
;;       input length of 4 bytes, so a test can see the cut in the echoed
;;       input.
;;
;; Rebuild with: wasm-tools parse double.wat -o double.wasm
(module
  (memory (export "memory") 2)
  (global $heap (mut i32) (i32.const 4096))
  (data (i32.const 1024) "{\"ok\":true,\"max_input_bytes\":3145729,\"revocation_urls\":[\"http://crl.apple.com/root.crl\",\"http://crl.apple.com/applerootcag3.crl\",\"http://crl.apple.com/wwdrg5.crl\",\"http://crl.apple.com/wwdrg6.crl\"],\"revocation_valid_until_ms\":null}")
  (data (i32.const 1280) "{\"ok\":true,\"max_input_bytes\":3145729,\"revocation_urls\":[\"http://crl.example.test/a.crl\",\"https://crl.example.test/a.crl\"],\"revocation_valid_until_ms\":1795046400000}")
  (data (i32.const 1472) "{\"ok\":false,\"message\":\"the double refuses this configuration\"}")
  (data (i32.const 1536) "{\"ok\":true}")
  (data (i32.const 1568) "{\"ok\":true,\"max_input_bytes\":4,\"revocation_urls\":[],\"revocation_valid_until_ms\":null}")
  (data (i32.const 1664) "{\"ok\":true,\"max_input_bytes\":3145729}")

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

  (func (export "aprv:verifier/verify@0.2.0#init") (param $ptr i32) (param $len i32) (result i32)
    (local $at i32) (local $n i32) (local $first i32)
    i32.const 1024
    local.set $at
    i32.const 231
    local.set $n
    local.get $len
    if
      local.get $ptr
      i32.load8_u
      local.set $first
      ;; '{' with 3 bytes or more: a configuration that names something
      local.get $first
      i32.const 123
      i32.eq
      local.get $len
      i32.const 2
      i32.gt_u
      i32.and
      if
        i32.const 1280
        local.set $at
        i32.const 164
        local.set $n
      end
      ;; 'o' answers as a module older than max_input_bytes
      local.get $first
      i32.const 111
      i32.eq
      if
        i32.const 1536
        local.set $at
        i32.const 11
        local.set $n
      end
      ;; 'm' answers as a module older than revocation
      local.get $first
      i32.const 109
      i32.eq
      if
        i32.const 1664
        local.set $at
        i32.const 37
        local.set $n
      end
      ;; 's' states an input length of 4 bytes
      local.get $first
      i32.const 115
      i32.eq
      if
        i32.const 1568
        local.set $at
        i32.const 85
        local.set $n
      end
    end
    local.get $len
    i32.const 100
    i32.gt_u
    if
      i32.const 1472
      local.set $at
      i32.const 62
      local.set $n
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
