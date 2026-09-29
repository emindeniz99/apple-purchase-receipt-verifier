;; A test double for aprv.wasm: it speaks ABI 1.0.0 (the four exports, their
;; cabi_post twins, cabi_realloc, the one random-get import) and answers from
;; what it is given, so the tests can drive the host code (pooling, the six
;; outcomes, trap recovery, clock and environment handling) without a real
;; verifier. It verifies nothing.
;;
;; What an input's first byte makes the three verify exports do:
;;   'T'  trap (unreachable)
;;   'B'  answer with a return area outside memory
;;   'L'  answer with a result that runs past the end of memory
;;   'N'  answer text that is not JSON
;;   'G'  grow memory by 1100 pages (68 MiB, past the pool's retire size),
;;        then answer as for any other input
;;   'H'  grow memory by 5000 pages (312 MiB, past the 256 MiB store limit) and
;;        trap when the store refuses
;;   'E'  answer the rest of the input, unchanged (so a test writes the JSON
;;        the module "would have" answered)
;;   else a failure whose message names the call: {"verified":false,
;;        "reason":"MALFORMED","message":"receipt now=<n>"} (or "jws"), and for the
;;        endpoint {"status":21009,"env":<env>,"now":<n>}
;; init answers {"ok":true}, traps when called twice (so a pool that inits an
;; instance twice shows at once), and refuses (ok:false) a configuration
;; whose first root's base64 starts with "R". A verify before init traps.
(module
  (import "aprv:verifier/host@1.0.0" "random-get" (func $random-get (param i32 i32)))
  (memory (export "memory") 16)
  (global $top (mut i32) (i32.const 4096))
  (global $inited (mut i32) (i32.const 0))
  ;; the return area: (ptr, len) at 16
  (data (i32.const 64) "{\"ok\":true}")
  (data (i32.const 96) "{\"ok\":false,\"message\":\"the double refuses this root\"}")
  (data (i32.const 160) "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"receipt now=")
  (data (i32.const 256) "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"jws now=")
  (data (i32.const 352) "\"}")
  (data (i32.const 384) "{\"status\":21009,\"env\":")
  (data (i32.const 416) ",\"now\":")
  (data (i32.const 448) "}")
  (data (i32.const 480) "not json")

  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    (local.set $p (i32.and (i32.add (global.get $top) (i32.const 7)) (i32.const -8)))
    (global.set $top (i32.add (local.get $p) (local.get 3)))
    (local.get $p))

  ;; every result is freed by its post-return, so the bump pointer resets
  (func $free (param i32) (global.set $top (i32.const 4096)))
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#init") (param i32) (call $free (local.get 0)))
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-receipt") (param i32) (call $free (local.get 0)))
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-signed-data") (param i32) (call $free (local.get 0)))
  (func (export "cabi_post_aprv:verifier/verify@1.0.0#verify-receipt-endpoint") (param i32) (call $free (local.get 0)))
  (func (export "_initialize"))

  ;; answer (ptr, len) in the return area and return its address
  (func $ret (param $ptr i32) (param $len i32) (result i32)
    (i32.store (i32.const 16) (local.get $ptr))
    (i32.store (i32.const 20) (local.get $len))
    (i32.const 16))

  ;; copy (src, n) to dst; returns dst + n
  (func $copy (param $dst i32) (param $src i32) (param $n i32) (result i32)
    (memory.copy (local.get $dst) (local.get $src) (local.get $n))
    (i32.add (local.get $dst) (local.get $n)))

  ;; write the decimal digits of $v at $dst; returns the address after them
  (func $itoa (param $v i64) (param $dst i32) (result i32)
    (local $n i32) (local $i i32) (local $tmp i32)
    (local.set $tmp (i32.const 1000))
    (if (i64.eqz (local.get $v))
      (then
        (i32.store8 (local.get $dst) (i32.const 48))
        (return (i32.add (local.get $dst) (i32.const 1)))))
    (block $done
      (loop $digits
        (br_if $done (i64.eqz (local.get $v)))
        (i32.store8 (i32.add (local.get $tmp) (local.get $n))
          (i32.add (i32.const 48) (i32.wrap_i64 (i64.rem_u (local.get $v) (i64.const 10)))))
        (local.set $v (i64.div_u (local.get $v) (i64.const 10)))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $digits)))
    (loop $rev
      (local.set $n (i32.sub (local.get $n) (i32.const 1)))
      (i32.store8 (i32.add (local.get $dst) (local.get $i))
        (i32.load8_u (i32.add (local.get $tmp) (local.get $n))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $rev (i32.gt_s (local.get $n) (i32.const 0))))
    (i32.add (local.get $dst) (local.get $i)))

  ;; the behaviour keyed on the first input byte; $kind 0 receipt, 1 jws, 2 endpoint
  (func $verify (param $kind i32) (param $env i32) (param $now i64) (param $ptr i32) (param $len i32) (result i32)
    (local $first i32) (local $out i32) (local $end i32)
    (if (i32.eqz (global.get $inited)) (then unreachable))
    (if (i32.gt_u (local.get $len) (i32.const 0))
      (then (local.set $first (i32.load8_u (local.get $ptr)))))
    (if (i32.eq (local.get $first) (i32.const 84)) (then unreachable))                    ;; 'T'
    (if (i32.eq (local.get $first) (i32.const 66)) (then (return (i32.const 0x7ffffff0)))) ;; 'B'
    (if (i32.eq (local.get $first) (i32.const 76))                                          ;; 'L'
      (then (return (call $ret (i32.const 0xfffff0) (i32.const 64)))))
    (if (i32.eq (local.get $first) (i32.const 78))                                          ;; 'N'
      (then (return (call $ret (i32.const 480) (i32.const 8)))))
    (if (i32.eq (local.get $first) (i32.const 69))                                          ;; 'E'
      (then (return (call $ret (i32.add (local.get $ptr) (i32.const 1)) (i32.sub (local.get $len) (i32.const 1))))))
    (if (i32.eq (local.get $first) (i32.const 72))                                          ;; 'H'
      (then (if (i32.eq (memory.grow (i32.const 5000)) (i32.const -1)) (then unreachable))))
    (if (i32.eq (local.get $first) (i32.const 71))                                          ;; 'G'
      (then (drop (memory.grow (i32.const 1100)))))
    (local.set $out (call $realloc_top))
    (local.set $end (local.get $out))
    (if (i32.eq (local.get $kind) (i32.const 2))
      (then
        (local.set $end (call $copy (local.get $end) (i32.const 384) (i32.const 22)))
        (local.set $end (call $itoa (i64.extend_i32_u (local.get $env)) (local.get $end)))
        (local.set $end (call $copy (local.get $end) (i32.const 416) (i32.const 7)))
        (local.set $end (call $itoa (local.get $now) (local.get $end)))
        (local.set $end (call $copy (local.get $end) (i32.const 448) (i32.const 1))))
      (else
        (if (i32.eqz (local.get $kind))
          (then (local.set $end (call $copy (local.get $end) (i32.const 160) (i32.const 62))))
          (else (local.set $end (call $copy (local.get $end) (i32.const 256) (i32.const 58)))))
        (local.set $end (call $itoa (local.get $now) (local.get $end)))
        (local.set $end (call $copy (local.get $end) (i32.const 352) (i32.const 2)))))
    (call $ret (local.get $out) (i32.sub (local.get $end) (local.get $out))))

  (func $realloc_top (result i32)
    (local $p i32)
    (local.set $p (i32.and (i32.add (global.get $top) (i32.const 7)) (i32.const -8)))
    (global.set $top (i32.add (local.get $p) (i32.const 512)))
    (local.get $p))

  (func (export "aprv:verifier/verify@1.0.0#init") (param $ptr i32) (param $len i32) (result i32)
    (if (global.get $inited) (then unreachable))
    (if (i32.and
          (i32.gt_u (local.get $len) (i32.const 11))
          (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 11))) (i32.const 82)))
      (then (return (call $ret (i32.const 96) (i32.const 53)))))
    (global.set $inited (i32.const 1))
    (call $ret (i32.const 64) (i32.const 11)))

  (func (export "aprv:verifier/verify@1.0.0#verify-receipt") (param i64 i32 i32) (result i32)
    (call $verify (i32.const 0) (i32.const 0) (local.get 0) (local.get 1) (local.get 2)))
  (func (export "aprv:verifier/verify@1.0.0#verify-signed-data") (param i64 i32 i32) (result i32)
    (call $verify (i32.const 1) (i32.const 0) (local.get 0) (local.get 1) (local.get 2)))
  (func (export "aprv:verifier/verify@1.0.0#verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
    (call $verify (i32.const 2) (local.get 0) (local.get 1) (local.get 2) (local.get 3))))
