# frozen_string_literal: true

# Start-up and single-thread cost, in a fresh process: `require`, the first
# Verifier (which compiles aprv.wasm once per process), a later Verifier, the
# first call, and steady per-call times for the genuine G5 sandbox receipt and
# the shared-sandbox JWS.
#
#   ruby -Ilib bench/startup.rb
#
# The calls go through the pool of instances and skip the facade's decoding of
# the answer, so the rows hold for a module whose wire is not 0.7's (the
# migration's stand-in carries the 0.6 core).
#
# On a machine that other work is loading, wall-clock times mean little, so
# each row also carries the CPU time the thread (per call) or the process
# (the compile, which runs on several threads) spent. The load average is
# printed for context.

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

def cpu(clock = Process::CLOCK_THREAD_CPUTIME_ID)
  Process.clock_gettime(clock)
end

# Wall and thread-CPU microseconds per call.
def micros(iterations, &)
  wall = cpu(Process::CLOCK_MONOTONIC)
  busy = cpu
  iterations.times(&)
  [((cpu(Process::CLOCK_MONOTONIC) - wall) / iterations * 1e6).round,
   ((cpu - busy) / iterations * 1e6).round]
end

receipt = [fixture("public-receipt-sandbox-g5")].pack("m0")
jws = fixture("transaction")

process_cpu = cpu(Process::CLOCK_PROCESS_CPUTIME_ID)
t_first, first = timed { APRV::Verifier.create(APRV::Config.new(clock: -> { NOW })) }
compile_cpu = cpu(Process::CLOCK_PROCESS_CPUTIME_ID) - process_cpu
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
  "first_verifier_cpu_ms" => (compile_cpu * 1000).round(1),
  "later_verifier_ms" => (t_later * 1000).round(2),
  "first_call_ms" => (t_call * 1000).round(2),
  "g5_receipt_us" => g5[0], "g5_receipt_cpu_us" => g5[1],
  "shared_sandbox_jws_us" => jws_us[0], "shared_sandbox_jws_cpu_us" => jws_us[1]
)
