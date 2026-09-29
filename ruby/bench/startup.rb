# frozen_string_literal: true

# Start-up and single-thread cost, in a fresh process: `require`, the first
# Verifier (which compiles aprv.wasm once per process), a later Verifier, the
# first call, and steady per-call times for the genuine G5 sandbox receipt and
# the shared-sandbox JWS.
#
#   ruby -Ilib bench/startup.rb
#
# The `_us` rows go through the pool of instances and skip the facade's
# decoding of the answer, so they are the host and the module alone; the
# `_verifier_us` rows are the whole `Verifier` call, typed result included.
# Memory: resident set of the process at three points, and the most linear
# memory one instance has used.
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

def rss_mb
  (File.read("/proc/self/status")[/^VmRSS:\s+(\d+) kB/, 1].to_i / 1024.0).round(1)
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

rss_required = rss_mb
process_cpu = cpu(Process::CLOCK_PROCESS_CPUTIME_ID)
t_first, first = timed { APRV::Verifier.create(APRV::Config.new(clock: -> { NOW })) }
compile_cpu = cpu(Process::CLOCK_PROCESS_CPUTIME_ID) - process_cpu
rss_compiled = rss_mb
t_later, = timed { APRV::Verifier.create(APRV::Config.new(clock: -> { NOW })) }
jws_verifier = APRV::Verifier.create(APRV::Config.new(roots: [fixture("jws-root")], clock: -> { NOW }))
pool = first.instance_variable_get(:@pool)
jws_pool = jws_verifier.instance_variable_get(:@pool)

t_call, = timed { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
200.times { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
g5 = micros(500) { pool.with_guest { |g| g.call("verify-receipt", [NOW], receipt) } }
200.times { jws_pool.with_guest { |g| g.call("verify-signed-data", [NOW], jws) } }
jws_us = micros(300) { jws_pool.with_guest { |g| g.call("verify-signed-data", [NOW], jws) } }

g5_verifier = micros(500) { first.verify_receipt(receipt) }
jws_verifier_us = micros(300) { jws_verifier.verify_signed_data(jws) }
linear_memory = pool.with_guest { |g| g.instance_variable_get(:@store).max_linear_memory_consumed }

puts JSON.pretty_generate(
  "ruby" => RUBY_VERSION, "wasmtime" => Wasmtime::VERSION, "cpus" => Etc.nprocessors,
  "load_average" => File.read("/proc/loadavg").split.first(3),
  "require_ms" => (t_require * 1000).round(1),
  "first_verifier_ms" => (t_first * 1000).round(1),
  "first_verifier_cpu_ms" => (compile_cpu * 1000).round(1),
  "later_verifier_ms" => (t_later * 1000).round(2),
  "first_call_ms" => (t_call * 1000).round(2),
  "g5_receipt_us" => g5[0], "g5_receipt_cpu_us" => g5[1],
  "shared_sandbox_jws_us" => jws_us[0], "shared_sandbox_jws_cpu_us" => jws_us[1],
  "g5_verifier_us" => g5_verifier[0], "g5_verifier_cpu_us" => g5_verifier[1],
  "shared_sandbox_jws_verifier_us" => jws_verifier_us[0],
  "shared_sandbox_jws_verifier_cpu_us" => jws_verifier_us[1],
  "rss_after_require_mb" => rss_required, "rss_after_compile_mb" => rss_compiled,
  "rss_at_end_mb" => rss_mb, "instance_linear_memory_mib" => (linear_memory / 1_048_576.0).round(1)
)
