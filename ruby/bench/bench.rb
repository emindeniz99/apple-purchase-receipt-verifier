# frozen_string_literal: true

# The cross-port benchmark: the same operations on the same two genuine
# sandbox receipts in every port, named after the Java JMH benchmarks in
# java-bench/ (BENCHMARKS.md at the repository root has the table).
#
#   ruby -Ilib bench/bench.rb > ruby-bench.json
#
# No benchmark gem: benchmark-ips is not in the Gemfile, and the stdlib
# `benchmark` leaves the default gems in Ruby 3.5, so this times with the
# monotonic clock directly. Each benchmark warms up for one second, then takes
# ten samples of at least 100 ms each; the JSON on stdout carries the median,
# minimum and maximum microseconds per operation over those samples.

require "digest"
require "json"
require "apple_purchase_receipt_verifier"

module CrossPortBench
  WARMUP_S = 1.0
  SAMPLES = 10
  MIN_SAMPLE_S = 0.1

  # Any fixed instant (2026-01-01T00:00:00Z): it only feeds request_date,
  # since both fixtures carry a creation date.
  NOW_MILLIS = 1_767_225_600_000

  # File under fixtures/public-receipts, and the bundle id, in-app count and
  # digest fixtures/cases.json pins for it.
  FIXTURES = [
    ["receipt-sandbox-g5", "dev.bonzer.weeka.app", 2,
     "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0"],
    ["receipt-sandbox-legacy", "com.nutcall.alert", 187,
     "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8"]
  ].freeze

  APRV = ApplePurchaseReceiptVerifier

  module_function

  def now
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def measure(benchmark, fixture, &operation)
    start = now
    warmup_ops = 0
    while now - start < WARMUP_S
      operation.call
      warmup_ops += 1
    end
    per_op = (now - start) / warmup_ops
    ops = [1, (MIN_SAMPLE_S / per_op).to_i + 1].max
    samples = Array.new(SAMPLES) do
      t = now
      ops.times { operation.call }
      (now - t) * 1e6 / ops
    end.sort
    median = (samples[(SAMPLES / 2) - 1] + samples[SAMPLES / 2]) / 2
    warn format("%<benchmark>24s %<fixture>-24s %<median>12.1f us/op",
                benchmark: benchmark, fixture: fixture, median: median)
    { benchmark: benchmark, fixture: fixture, us_per_op_median: median,
      us_per_op_min: samples.first, us_per_op_max: samples.last, ops_per_sample: ops }
  end

  # Flips one bit in the middle of the SignerInfo signature, the byte
  # java-bench's flipSignatureByte flips. In both fixtures the signature is a
  # 256-byte OCTET STRING that ends the DER (openssl asn1parse shows it), so
  # its middle byte is 128 from the end; setup proves the flip landed there by
  # requiring INVALID_SIGNATURE.
  def tamper(der)
    tampered = der.dup
    tampered.setbyte(-128, tampered.getbyte(-128) ^ 0x01)
    tampered
  end

  def reject(base64, verifier)
    verifier.verify_receipt(base64)
  end

  def check(condition, message)
    raise message unless condition
  end

  def run_fixture(name, bundle_id, in_app_count, sha256, verifier)
    path = File.expand_path("../../fixtures/public-receipts/#{name}.b64", __dir__)
    der = File.read(path).unpack1("m")
    check(Digest::SHA256.hexdigest(der) == sha256, "#{name} does not match cases.json")
    base64 = [der].pack("m0")
    request_json = JSON.generate({ "receipt-data" => base64 })
    tampered = [tamper(der)].pack("m0")

    # Every call once, with the answer the conformance suite expects, so no
    # benchmark can time a fast failure by accident.
    result = verifier.verify_receipt(base64)
    check(result.verified?, "verifyReceipt")
    check(result.payload.bundle_id == bundle_id && result.payload.in_app.size == in_app_count, "receipt")
    ok = JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_json))
    check(ok["status"].zero? && ok["receipt"]["in_app"].size == in_app_count, "endpointJson")
    first = JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::PRODUCTION, request_json))
    check(first["status"] == 21_007, "retryViaResult first call")
    rejected = reject(tampered, verifier)
    check(!rejected.verified? && rejected.failure.reason == :INVALID_SIGNATURE, "rejectTamperedSignature")

    [
      # There is no separate decode step to time: the module decodes inside
      # verify_receipt, so "decodeBase64" has no row here. 0.7 has no DER
      # entry point either: "core" and "verifierBase64" are both
      # verify_receipt over the base64.
      measure("core", name) { verifier.verify_receipt(base64) },
      measure("verifierBase64", name) { verifier.verify_receipt(base64) },
      measure("endpointJson", name) do
        verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_json)
      end,
      # 21007 on PRODUCTION, then the caller's second, offline call on
      # SANDBOX, as the design routes it.
      measure("retryViaResult", name) do
        verifier.verify_receipt_endpoint(APRV::Environment::PRODUCTION, request_json)
        verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_json)
      end,
      measure("rejectTamperedSignature", name) { reject(tampered, verifier) }
    ]
  end

  def module_sha256
    Digest::SHA256.file(APRV.const_get(:Runtime)::MODULE_PATH).hexdigest
  end

  def main
    # The module is compiled and the roots parsed once, here, and never per call.
    verifier = APRV::Verifier.create(APRV::Config.new(clock: -> { NOW_MILLIS }))
    results = FIXTURES.flat_map { |fixture| run_fixture(*fixture, verifier) }
    puts JSON.pretty_generate(
      port: "ruby",
      tool: "bench/bench.rb (Process.clock_gettime)",
      runtime: "#{RUBY_ENGINE} #{RUBY_VERSION}, wasmtime #{Wasmtime::VERSION}, " \
               "aprv.wasm #{module_sha256[0, 12]}",
      settings: { warmup_s: WARMUP_S, samples: SAMPLES, min_sample_s: MIN_SAMPLE_S },
      results: results
    )
  end
end

CrossPortBench.main if $PROGRAM_NAME == __FILE__
