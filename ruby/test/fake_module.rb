# frozen_string_literal: true

require "json"

# A stand-in for aprv.wasm that speaks the same canonical ABI and answers from
# a table, so the facade's own behaviour (the six outcomes, trap recovery, the
# clock and `env`, the ABI checks) is tested without depending on which core
# version the shipped module holds. It contains no verification: which answer
# it gives is decided by the first byte of the input.
#
#   verify-receipt / verify-signed-data, by first byte of the input
#     v  verified (a receipt payload in 0.7's "Our JSON"; a JWS payload string)
#     f  failure UNTRUSTED_CHAIN          u  a reason token the wrapper lacks
#     j  an answer that is not JSON       n  JSON with no verified flag
#     t  unreachable (a trap)             e  an answer that is not UTF-8
#     o  a result pointer out of range    r  a return area out of range
#     c  verified only when now-ms is 1234, a trap otherwise
#     m  a memory.grow past the Store's limit, then a verified answer
#     d  random-get(8): traps unless the host answered 8 bytes
#     g  random-get(2 MiB), which the host refuses
#     anything else, or empty: failure MALFORMED
#   verify-receipt-endpoint
#     env 0: {"status":21007}, env 1: {"status":0}, any other env: a trap;
#     input "t": a trap; input "c": as above for now-ms; else as env says
#   init
#     `{"ok":true}`, except a root whose base64 starts with "X" (`ok:false`);
#     a second init, and any verify before init, trap
module FakeModule
  ANSWERS = {
    ok: '{"ok":true}',
    refused: '{"ok":false,"message":"root 0 is not a certificate"}',
    receipt: JSON.generate(
      "verified" => true,
      "payload" => {
        "receipt_type" => "ProductionSandbox", "app_item_id" => "1234567890123456789",
        "bundle_id" => "com.example.app", "bundle_id_bytes" => "Y29tLmV4YW1wbGUuYXBw",
        "application_version" => "7", "opaque_value" => "AAEC", "sha1_hash" => "AwQF",
        "receipt_creation_date_ms" => 1_722_945_600_000, "download_id" => "0",
        "version_external_identifier" => "42",
        "in_app" => [{
          "quantity" => 1, "product_id" => "com.example.pro", "transaction_id" => "70000000000001",
          "purchase_date_ms" => 1_722_945_600_000, "original_transaction_id" => "70000000000001",
          "original_purchase_date_ms" => 1_722_945_600_000, "expires_date_ms" => nil,
          "web_order_line_item_id" => "9000000000000000001", "cancellation_date_ms" => nil,
          "is_trial_period" => false, "is_in_intro_offer_period" => true,
          "unknown_attributes" => { "1799" => ["AQID"] }
        }],
        "original_purchase_date_ms" => nil, "original_application_version" => "1.0",
        "expiration_date_ms" => nil, "unknown_attributes" => { "13" => ["BAU=", "Bg=="] }
      }
    ),
    jws: JSON.generate("verified" => true, "payload" => '{"bundleId":"com.example.app","signedDate":1}'),
    chain: '{"verified":false,"reason":"UNTRUSTED_CHAIN",' \
           '"message":"the chain does not reach a pinned root"}',
    malformed: '{"verified":false,"reason":"MALFORMED","message":"receipt-data is not valid base64"}',
    unknown_reason: '{"verified":false,"reason":"INVALID_CHAIN","message":"an older core"}',
    not_json: "this is not json",
    no_flag: '{"x":1}',
    not_utf8: "\xff\xfe".b,
    production: '{"status":21007}',
    sandbox: '{"status":0}'
  }.freeze

  OUT_OF_RANGE = 0x7FFFFFF0

  class << self
    # @param import [String, nil] an extra import declaration, to test that
    #   the wrapper refuses one
    # @param abi [String] the version in the export names
    # @return [String] WAT text; Wasmtime compiles it directly
    def wat(import: nil, abi: "1.0.0")
      offsets = {}
      cursor = 64
      data = ANSWERS.map do |name, text|
        offsets[name] = [cursor, text.bytesize]
        segment = "(data (i32.const #{cursor}) \"#{text.b.bytes.map { |b| format("\\%02x", b) }.join}\")"
        cursor += ((text.bytesize + 7) / 8) * 8
        segment
      end

      iface = "aprv:verifier/verify@#{abi}"
      <<~WAT
        (module
          (import "aprv:verifier/host@1.0.0" "random-get" (func $random_get (param i32 i32)))
          #{import}
          (memory (export "memory") 64)
          (global $bump (mut i32) (i32.const 8192))
          (global $inited (mut i32) (i32.const 0))
          #{data.join("\n  ")}

          (func $ret (param $ptr i32) (param $len i32) (result i32)
            (i32.store (i32.const 16) (local.get $ptr))
            (i32.store offset=4 (i32.const 16) (local.get $len))
            (i32.const 16))

          (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
            (local $p i32)
            (if (i32.eqz (local.get 3)) (then (return (local.get 2))))
            (local.set $p (global.get $bump))
            (global.set $bump
              (i32.add (local.get $p) (i32.and (i32.add (local.get 3) (i32.const 7)) (i32.const -8))))
            (local.get $p))

          #{%w[init verify-receipt verify-signed-data verify-receipt-endpoint].map do |op|
              "(func (export \"cabi_post_#{iface}##{op}\") (param i32) (global.set $bump (i32.const 8192)))"
            end.join("\n  ")}

          (func (export "#{iface}#init") (param $ptr i32) (param $len i32) (result i32)
            (if (global.get $inited) (then unreachable))
            (if (i32.and (i32.gt_u (local.get $len) (i32.const 11))
                         (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 11))) (i32.const 88)))
              (then (return (call $ret (i32.const #{offsets[:refused][0]}) (i32.const #{offsets[:refused][1]})))))
            (global.set $inited (i32.const 1))
            (call $ret (i32.const #{offsets[:ok][0]}) (i32.const #{offsets[:ok][1]})))

          (func (export "#{iface}#verify-receipt") (param $now i64) (param $ptr i32) (param $len i32) (result i32)
            (local $k i32)
            (if (i32.eqz (global.get $inited)) (then unreachable))
            (if (i32.eqz (local.get $len))
              (then (return (call $ret (i32.const #{offsets[:malformed][0]}) (i32.const #{offsets[:malformed][1]})))))
            (local.set $k (i32.load8_u (local.get $ptr)))
            #{branch(offsets, 118 => :receipt, 102 => :chain, 117 => :unknown_reason, 106 => :not_json,
                              110 => :no_flag, 101 => :not_utf8)}
            #{shared_cases(offsets, :receipt)}
            (call $ret (i32.const #{offsets[:malformed][0]}) (i32.const #{offsets[:malformed][1]})))

          (func (export "#{iface}#verify-signed-data") (param $now i64) (param $ptr i32) (param $len i32) (result i32)
            (local $k i32)
            (if (i32.eqz (global.get $inited)) (then unreachable))
            (if (i32.eqz (local.get $len))
              (then (return (call $ret (i32.const #{offsets[:malformed][0]}) (i32.const #{offsets[:malformed][1]})))))
            (local.set $k (i32.load8_u (local.get $ptr)))
            #{branch(offsets, 118 => :jws, 102 => :chain, 117 => :unknown_reason, 106 => :not_json,
                              110 => :no_flag, 101 => :not_utf8)}
            #{shared_cases(offsets, :jws)}
            (call $ret (i32.const #{offsets[:malformed][0]}) (i32.const #{offsets[:malformed][1]})))

          (func (export "#{iface}#verify-receipt-endpoint")
                (param $env i32) (param $now i64) (param $ptr i32) (param $len i32) (result i32)
            (local $k i32)
            (if (i32.eqz (global.get $inited)) (then unreachable))
            (if (i32.gt_u (local.get $env) (i32.const 1)) (then unreachable))
            (if (i32.gt_u (local.get $len) (i32.const 0))
              (then
                (local.set $k (i32.load8_u (local.get $ptr)))
                (if (i32.eq (local.get $k) (i32.const 116)) (then unreachable))
                (if (i32.eq (local.get $k) (i32.const 99))
                  (then (if (i64.ne (local.get $now) (i64.const 1234)) (then unreachable))))))
            (if (i32.eqz (local.get $env))
              (then (return (call $ret (i32.const #{offsets[:production][0]}) (i32.const #{offsets[:production][1]})))))
            (call $ret (i32.const #{offsets[:sandbox][0]}) (i32.const #{offsets[:sandbox][1]})))
        )
      WAT
    end

    private

    def branch(offsets, table)
      table.map do |code, name|
        "(if (i32.eq (local.get $k) (i32.const #{code})) " \
          "(then (return (call $ret (i32.const #{offsets[name][0]}) (i32.const #{offsets[name][1]})))))"
      end.join("\n    ")
    end

    # The cases both verify operations share: a trap, bad pointers, the
    # clock, the memory limit and random-get.
    def shared_cases(offsets, verified)
      ok = "(call $ret (i32.const #{offsets[verified][0]}) (i32.const #{offsets[verified][1]}))"
      <<~WAT
        (if (i32.eq (local.get $k) (i32.const 116)) (then unreachable))
        (if (i32.eq (local.get $k) (i32.const 111))
          (then (return (call $ret (i32.const #{OUT_OF_RANGE}) (i32.const 100)))))
        (if (i32.eq (local.get $k) (i32.const 114)) (then (return (i32.const #{OUT_OF_RANGE}))))
        (if (i32.eq (local.get $k) (i32.const 99))
          (then
            (if (i64.ne (local.get $now) (i64.const 1234)) (then unreachable))
            (return #{ok})))
        (if (i32.eq (local.get $k) (i32.const 109))
          (then (drop (memory.grow (i32.const 5000))) (return #{ok})))
        (if (i32.eq (local.get $k) (i32.const 100))
          (then
            (call $random_get (i32.const 8) (i32.const 32))
            (if (i32.ne (i32.load offset=4 (i32.const 32)) (i32.const 8)) (then unreachable))
            (return #{ok})))
        (if (i32.eq (local.get $k) (i32.const 103))
          (then (call $random_get (i32.const 2097152) (i32.const 32)) (return #{ok})))
      WAT
    end
  end
end
