# frozen_string_literal: true

# Thread scaling: verifications per second at 1, 2 and 4 threads sharing one
# Verifier, for the genuine G5 sandbox receipt and the shared-sandbox JWS.
#
#   ruby -Ilib bench/threads.rb              # print the table
#   ruby -Ilib bench/threads.rb --assert     # and fail unless 4 threads reach 1.5x one thread
#
# Every call runs the module without the GVL (`to_func(gvl: false)`), and
# each thread gets an instance of its own from the Verifier's pool, so the
# rows scale with the cores. With the GVL held they would not: the spike
# measured 0.9x at four threads.
#
# Next to each rate it prints the calls per CPU-second of the process, which
# does not depend on how many cores other work leaves free.
#
# --assert needs the machine's cores: it checks 4-thread throughput only when
# at least 4 CPUs are usable, and otherwise says so and passes nothing.
#
# The threshold is 1.5x at 4 threads, best of three trials, on both rows.
# A GVL held around the module gives about 1.0x (the spike measured 0.9x), a
# free 4-core machine gives 3.3x to 4.1x, and a hosted 4-vCPU runner, whose
# vCPUs are hyper-threads of fewer cores and which other jobs share, gave 1.94x
# and 2.19x, so the former 2.0x failed on noise. 1.5x sits between the GVL
# case and the noisy-runner case; the second and third trials run only when
# the first misses, so a passing run stays short.

require "etc"
require "json"
require "apple_purchase_receipt_verifier"

module ThreadBench
  APRV = ApplePurchaseReceiptVerifier
  FIXTURES = File.expand_path("../../fixtures", __dir__)
  SECONDS = 3.0
  MIN_RATIO = 1.5
  TRIALS = 3
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

    puts "#{Etc.nprocessors} CPUs, Ruby #{RUBY_VERSION}, wasmtime #{Wasmtime::VERSION}"
    call_g5 = -> { g5_verifier.verify_receipt(receipt) }
    call_jws = -> { jws_verifier.verify_signed_data(jws) }
    abort "the genuine receipt did not verify" unless call_g5.call.verified?
    abort "the shared-sandbox JWS did not verify" unless call_jws.call.verified?

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
    assert!(table, { g5: call_g5, jws: call_jws }) if ARGV.include?("--assert")
  end

  def assert!(table, calls)
    if Etc.nprocessors < 4
      puts "--assert: fewer than 4 CPUs, scaling not asserted"
      return
    end
    %i[g5 jws].each do |row|
      ratios = [table[4][row] / table[1][row]]
      while ratios.max < MIN_RATIO && ratios.size < TRIALS
        one, = rate(1, &calls.fetch(row))
        four, = rate(4, &calls.fetch(row))
        ratios << (four / one)
        puts format("--assert: %<row>s trial %<n>d: 4 threads / 1 thread %<ratio>.2fx",
                    row: row, n: ratios.size, ratio: ratios.last)
      end
      best = ratios.max
      next if best >= MIN_RATIO

      abort "#{row}: 4 threads reach only #{best.round(2)}x one thread (best of #{ratios.size})"
    end
    puts "--assert: 4 threads reach at least #{MIN_RATIO}x one thread on both rows"
  end
end

ThreadBench.main if $PROGRAM_NAME == __FILE__
