# frozen_string_literal: true

# Start-up and single-thread cost, in a fresh process: `require`, the first
# Verifier (which compiles aprv.wasm once per process), a later Verifier, the
# first call, and steady per-call times for the genuine G5 sandbox receipt and
# the shared-sandbox JWS.
#
#   ruby -Ilib bench/startup.rb
#
# The calls go through the pool of instances and print the module's raw
# answers' size, not the facade's typed result, so the rows hold for a module
# whose wire is not 0.7's (the migration's stand-in carries the 0.6 core).

require "json"
require "etc"

t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
require "apple_purchase_receipt_verifier"
t_require = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0

APRV = ApplePurchaseReceiptVerifier
FIXTURES = File.expand_path("../../fixtures", __dir__)
CASES = JSON.parse(File.read(File.join(FIXTURES, "cases.json"), encoding: "UTF-8"))
NOW = 1_767_225_600_000

def fixture(id)
  entry = CASES["fixtures"].fetch(id)
  raw = File.binread(File.join(FIXTURES, entry["path"]))
  entry["codec"] == "base64" ? raw.gsub(/\s+/, "").unpack1("m") : raw
end

def timed
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  value = yield
  [Process.clock_gettime(Process::CLOCK_MONOTONIC) - start, value]
end

def micros(iterations, &block)
  elapsed, = timed { iterations.times(&block) }
  (elapsed / iterations * 1e6).round
end

receipt = [fixture("public-receipt-sandbox-g5")].pack("m0")
jws = fixture("transaction")

t_first, first = timed { APRV::Verifier.create(APRV::Config.new(clock: -> { NOW })) }
t_later, = timed { APRV::Verifier.create(APRV::Config.new(clock: -> { NOW })) }
jws_verifier = APRV::Verifier.create(APRV::Config.new(roots: [fixture("jws-root")], clock: -> { NOW }))
pool = first.instance_variable_get(:@pool)
jws_pool = jws_verifier.instance_variable_get(:@pool)

t_call, = timed { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
200.times { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
g5 = micros(500) { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
200.times { jws_pool.with_guest { |g| g.call("verify-signed-data", [NOW], jws) } }
jws_us = micros(300) { jws_pool.with_guest { |g| g.call("verify-signed-data", [NOW], jws) } }

puts JSON.pretty_generate(
  "ruby" => RUBY_VERSION, "wasmtime" => Wasmtime::VERSION, "cpus" => Etc.nprocessors,
  "load_average" => File.read("/proc/loadavg").split.first(3),
  "require_ms" => (t_require * 1000).round(1),
  "first_verifier_ms" => (t_first * 1000).round(1),
  "later_verifier_ms" => (t_later * 1000).round(2),
  "first_call_ms" => (t_call * 1000).round(2),
  "g5_receipt_us" => g5, "shared_sandbox_jws_us" => jws_us
)
