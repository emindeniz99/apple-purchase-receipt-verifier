# frozen_string_literal: true

# Thread scaling: verifications per second at 1, 2 and 4 threads sharing one
# Verifier, for the genuine G5 sandbox receipt and the shared-sandbox JWS.
#
#   ruby -Ilib bench/threads.rb              # print the table
#   ruby -Ilib bench/threads.rb --assert     # and fail unless 4 threads reach 2x one thread
#
# Every call runs the module without the GVL (`to_func(gvl: false)`), and
# each thread gets an instance of its own from the Verifier's pool, so the
# rows scale with the cores. With the GVL held they would not: the spike
# measured 0.9x at four threads.
#
# Next to each rate it prints the calls per CPU-second of the process, which
# does not depend on how many cores other work leaves free.
#
# The rows are measured through the Verifier when the shipped module answers
# in the 0.7 wire, and through the pool of instances (the same module calls,
# without decoding the answer) when it does not, as the migration's stand-in
# module, which carries the 0.6 core, does not. The output says which.
#
# --assert needs the machine's cores: it checks 4-thread throughput only when
# at least 4 CPUs are usable, and otherwise says so and passes nothing.

require "etc"
require "json"
require "apple_purchase_receipt_verifier"

module ThreadBench
  APRV = ApplePurchaseReceiptVerifier
  FIXTURES = File.expand_path("../../fixtures", __dir__)
  SECONDS = 3.0
  NOW = 1_767_225_600_000

  module_function

  def cases
    @cases ||= JSON.parse(File.read(File.join(FIXTURES, "cases.json"), encoding: "UTF-8"))
  end

  def fixture(id)
    entry = cases["fixtures"].fetch(id)
    raw = File.binread(File.join(FIXTURES, entry["path"]))
    entry["codec"] == "base64" ? raw.gsub(/\s+/, "").unpack1("m") : raw
  end

  # Calls per second, and calls per CPU-second of the whole process. The
  # second stays flat as threads are added when nothing serialises them, and
  # does not depend on how many cores other work leaves free.
  def rate(threads)
    count = Thread::Queue.new
    busy = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + SECONDS
    Array.new(threads) do
      Thread.new do
        done = 0
        while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          yield
          done += 1
        end
        count << done
      end
    end.each(&:join)
    total = Array.new(threads) { count.pop }.sum
    cpu = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - busy
    [(total / SECONDS).round(1), (total / cpu).round(1)]
  end

  def main
    receipt = [fixture("public-receipt-sandbox-g5")].pack("m0")
    jws = fixture("transaction")
    g5_verifier = APRV::Verifier.create(APRV::Config.new(clock: -> { NOW }))
    jws_verifier = APRV::Verifier.create(APRV::Config.new(roots: [fixture("jws-root")], clock: -> { NOW }))

    through = "the pool of instances (module answers are not decoded)"
    through = "the Verifier" if g5_verifier.verify_receipt(receipt).verified?
    puts "measured through #{through}; #{Etc.nprocessors} CPUs, Ruby #{RUBY_VERSION}, wasmtime #{Wasmtime::VERSION}"
    call_g5, call_jws =
      if through == "the Verifier"
        [-> { g5_verifier.verify_receipt(receipt) }, -> { jws_verifier.verify_signed_data(jws) }]
      else
        [raw_call(g5_verifier, "verify-receipt", receipt),
         raw_call(jws_verifier, "verify-signed-data", jws)]
      end
    call_g5.call
    call_jws.call

    table = [1, 2, 4].to_h do |n|
      g5, g5_cpu = rate(n, &call_g5)
      jws_rate, jws_cpu = rate(n, &call_jws)
      [n, { g5: g5, g5_cpu: g5_cpu, jws: jws_rate, jws_cpu: jws_cpu }]
    end
    table.each do |n, row|
      puts format("%<n>d thread(s): g5 %<g5>8.1f/s (%<g5_cpu>7.1f per CPU-s)   " \
                  "jws %<jws>8.1f/s (%<jws_cpu>7.1f per CPU-s)", n: n, **row)
    end
    puts format("4 threads / 1 thread: g5 %<g5>.2fx   jws %<jws>.2fx",
                g5: table[4][:g5] / table[1][:g5], jws: table[4][:jws] / table[1][:jws])
    assert!(table) if ARGV.include?("--assert")
  end

  def raw_call(verifier, operation, input)
    pool = verifier.instance_variable_get(:@pool)
    -> { pool.with_guest { |guest| guest.call(operation, [NOW], input) } }
  end

  def assert!(table)
    if Etc.nprocessors < 4
      puts "--assert: fewer than 4 CPUs, scaling not asserted"
      return
    end
    %i[g5 jws].each do |row|
      ratio = table[4][row] / table[1][row]
      abort "#{row}: 4 threads reach only #{ratio.round(2)}x one thread" if ratio < 2.0
    end
    puts "--assert: 4 threads reach at least 2x one thread on both rows"
  end
end

ThreadBench.main if $PROGRAM_NAME == __FILE__
