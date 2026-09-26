# frozen_string_literal: true

# Spike only (2026-09-26). The ABI v1 round's 33 mandatory ABI tests
# (js/abi-tests.mjs) on wasmtime-rb, plus the facade's contract. Every trap
# is caught, the instance discarded, and a fresh instance must then verify g5.
#   ruby abi_tests.rb calls-cases.jsonl
require_relative "common"

calls = load_calls(ARGV[0])
_, G5 = call_of(calls, G5_ID)
JWS_OP, JWS = call_of(calls, JWS_ID)
R = AprvWasm::OP[:verify_receipt]
$passed = 0
$failed = 0

def ok(name, cond, detail = "")
  cond ? $passed += 1 : $failed += 1
  puts "#{cond ? 'PASS' : 'FAIL'} #{name}#{detail.to_s.empty? ? '' : ": #{detail}"}"
end

def attempt
  i = AprvWasm::Instance.new
  [:ok, yield(i)]
rescue Wasmtime::Trap => e
  [:trap, "Wasmtime::Trap: code #{e.code.inspect}"]
rescue AprvWasm::AbiMismatchError => e
  [:error, e.message]
rescue StandardError => e
  [:error, "#{e.class}: #{e.message.lines.first}"]
end

def g5_verifies
  JSON.parse(AprvWasm::Instance.new.invoke(R, G5))["verified"] == true
end

def traps_then_recovers(name, &blk)
  kind, msg = attempt(&blk)
  after = g5_verifies
  ok(name, kind == :trap && after, "#{kind} (#{msg}); fresh instance verifies g5: #{after}")
end

def with_handle(i)
  i.raw("aprv_call", 1, R, i.raw("aprv_alloc", 4), 4)
end

dec = ->(b) { JSON.parse(b) }
ok("aprv_abi_version() == 1", AprvWasm::Instance.new.raw("aprv_abi_version") == 1)
k, v = attempt { |i| dec.(i.invoke(R, G5)) }
ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", k == :ok && v["verified"] == true && v.dig("payload", "bundleId") == "dev.bonzer.weeka.app",
   "bundleId #{k == :ok ? v.dig('payload', 'bundleId') : v}")
k, v = attempt { |i| dec.(i.invoke(JWS_OP, JWS)) }
ok("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload",
   k == :ok && v["verified"] == true && JSON.parse(v["payloadJson"]) == v["payload"], "payloadJson #{k == :ok ? v['payloadJson'].size : v} chars")
traps_then_recovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard") { |i| i.raw("aprv_call", 0, 0x7FFFFFFF, -16, 0x7FFFFFFF) }
traps_then_recovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard") { |i| i.raw("aprv_call", 2, 0x7FFFFFFF, -16, 0x7FFFFFFF) }
k, msg = attempt { |i| i.invoke(R, G5, 2) }
ok("bridge reports a version mismatch as an ABI error, never verified=false", k == :error && msg.include?("APRV Wasm ABI mismatch: module=1, caller=2"), msg)
k, v = attempt do |i|
  before = AprvWasm::IMPORT_CALLS.dup
  begin
    i.raw("aprv_call", 3, 1, 0, 0)
  rescue Wasmtime::Trap
    nil
  end
  AprvWasm::IMPORT_CALLS.to_h { |n, c| [n, c - before[n]] }
end
ok("a version mismatch runs nothing (no host import called)", k == :ok && v.values.all?(&:zero?), "import calls during the call: #{v}")
[0, 5, 99, 255, 256, 261, -1].each do |op|
  traps_then_recovers("unknown operation #{op} fails hard") { |i| i.raw("aprv_call", 1, op, i.raw("aprv_alloc", 4), 4) }
end
traps_then_recovers("null input pointer with a length fails hard") { |i| i.raw("aprv_call", 1, R, 0, 10) }
traps_then_recovers("input beyond linear memory fails hard") { |i| i.raw("aprv_call", 1, R, i.memory.data_size - 4, 16) }
traps_then_recovers("input range that overflows u32 fails hard") { |i| i.raw("aprv_call", 1, R, -16, 0x20) }
k, v = attempt { |i| dec.(i.invoke(R, "")) }
ok("empty input is a verification failure value", k == :ok && v["verified"] == false && v["reason"] == "INVALID_RECEIPT_FORMAT", v.to_s)
k, v = attempt { |i| [i.raw("aprv_alloc", 0x7FFFFFFF), i.raw("aprv_alloc", 0x7FFFFFF0), dec.(i.invoke(R, G5))["verified"]] }
ok("absurd aprv_alloc lengths return 0, and the instance keeps working", k == :ok && v == [0, 0, true], v.to_s)
{ "aprv_result_ptr(0)" => ["aprv_result_ptr", 0], "aprv_result_len(12345)" => ["aprv_result_len", 12_345],
  "aprv_result_free(0)" => ["aprv_result_free", 0], "aprv_result_free(never issued)" => ["aprv_result_free", 7] }.each do |name, a|
  traps_then_recovers("invalid handle: #{name} fails hard") { |i| i.raw(*a) }
end
traps_then_recovers("double free fails hard") do |i|
  h = with_handle(i)
  i.raw("aprv_result_free", h)
  i.raw("aprv_result_free", h)
end
%w[aprv_result_ptr aprv_result_len].each do |ex|
  traps_then_recovers("use after free (#{ex.sub('aprv_', '')}) fails hard") do |i|
    h = with_handle(i)
    i.raw("aprv_result_free", h)
    i.raw(ex, h)
  end
end
k, v = attempt do |i|
  hs = [with_handle(i), with_handle(i), with_handle(i)]
  i.raw("aprv_result_free", hs[1])
  [hs, with_handle(i)]
end
ok("freed handles are reused and live ones stay valid", k == :ok && v[1] == v[0][1], v.to_s)
k, v = attempt { |i| dec.(i.invoke(R, "not a receipt")) }
ok("garbage receipt -> verified=false value", k == :ok && v["verified"] == false, v.to_s)
k, v = attempt { |i| dec.(i.invoke(AprvWasm::OP[:verify_signed_data], "\xFF\xFE.".b)) }
ok("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT", k == :ok && v["verified"] == false && v["reason"] == "INVALID_JWS_FORMAT", v.to_s)
k, v = attempt { |i| dec.(i.invoke(AprvWasm::OP[:endpoint_sandbox], '{"receipt-data": ')) }
ok("malformed endpoint request JSON -> Apple status 21002 value", k == :ok && v["status"] == 21_002, v.to_s)
msg = begin
  JSON.parse('{"verified":tru')
  ""
rescue JSON::ParserError => e
  "#{e.class}: #{e.message.lines.first.strip}"
end
ok("malformed result JSON is a host decode error (internal failure), not a verdict", msg.start_with?("JSON::ParserError"), msg)
k, v = attempt do |i|
  a = i.invoke(R, G5)
  snap = a.dup
  5.times { |n| i.invoke(R, "x" * (n + 1)) }
  snap == a && !a.frozen?
end
ok("a result is a host-owned copy (unchanged after later calls reuse guest memory)", k == :ok && v == true)
k, v = attempt do |i|
  200.times { i.invoke(R, G5) }
  m1 = i.memory.data_size
  2000.times { i.invoke(R, G5) }
  [m1, i.memory.data_size]
end
ok("no growth of linear memory over 2,000 more calls", k == :ok && v[0] == v[1], v.to_s)

fv = AprvWasm::Verifier.new
kind = begin
  fv.call(R, G5, 2)
  "none"
rescue AprvWasm::AbiMismatchError => e
  e.message
end
ok("facade: a version mismatch raises AbiMismatchError", kind.include?("module=1, caller=2"), kind)
kind = begin
  fv.call(99, "")
  "none"
rescue AprvWasm::WasmTrapError => e
  "WasmTrapError: #{e.message.lines.first.strip}"
end
ok("facade: an unknown operation raises WasmTrapError (internal failure)", kind.start_with?("WasmTrapError"), kind)
ok("facade: after a trap the next call runs on a fresh instance and verifies", fv.verify_receipt(G5)["verified"] == true && fv.traps == 1, "traps #{fv.traps}")
r = fv.verify_receipt("not base64!")
ok("facade: a verification failure is a value", r == { "message" => "receipt-data is not valid base64", "reason" => "INVALID_RECEIPT_FORMAT", "verified" => false }, r.to_s)
puts "summary: #{$passed} passed, #{$failed} failed"
exit($failed.zero? ? 0 : 1)
