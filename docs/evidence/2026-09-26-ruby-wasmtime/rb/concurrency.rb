# frozen_string_literal: true

# Spike only (2026-09-26). Warm speed, scaling and isolation for the facade.
#   ruby concurrency.rb calls-cases.jsonl bench       one thread: 200 warm-up + 1,000 timed, g5 and JWS
#   ruby concurrency.rb calls-cases.jsonl threads     1/2/4 threads, one Verifier each
#   ruby concurrency.rb calls-cases.jsonl processes   1/2/4 forked processes, one Verifier each
#   ruby concurrency.rb calls-cases.jsonl isolation   independent instances; traps under concurrency
# Every timed result is checked to be verified=true. The facade calls
# aprv_call with gvl: false; set APRV_GVL=1 to measure the default (GVL held).
require_relative "common"
require "etc"

calls = load_calls(ARGV[0])
ROWS = { G5_ID => call_of(calls, G5_ID), JWS_ID => call_of(calls, JWS_ID) }.freeze
now = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
puts "# ruby #{RUBY_VERSION}, wasmtime #{Gem.loaded_specs['wasmtime'].version}, #{Etc.nprocessors} cores, load average #{File.read('/proc/loadavg').split[0, 3].join(' ')}"

case ARGV[1]
when "bench"
  v = AprvWasm::Verifier.new
  ROWS.each do |id, (op, data)|
    200.times { raise unless v.call(op, data).start_with?(OK) }
    t = now.()
    1000.times { raise unless v.call(op, data).start_with?(OK) }
    us = (now.() - t) / 1000 * 1e6
    puts JSON.generate({ id: id, op: op, warm: 200, n: 1000, mean_us: us.round, per_s: (1e6 / us).round(1) })
  end
when "threads", "processes"
  kind = ARGV[1]
  ROWS.each do |id, (op, data)|
    warm, n = id == G5_ID ? [300, 600] : [150, 300]
    [1, 2, 4].each do |t|
      if kind == "threads"
        q = Queue.new
        go = Queue.new
        bad = Array.new(t, 0)
        ths = Array.new(t) do |k|
          # Block-local `ver`: a plain `v` here would be the script's
          # top-level `v` (from the bench branch), shared by every thread.
          Thread.new do |; ver|
            ver = AprvWasm::Verifier.new
            warm.times { ver.call(op, data) }
            q << :ready
            go.pop
            n.times { bad[k] += 1 unless ver.call(op, data).start_with?(OK) }
          end
        end
        t.times { q.pop }
        t0 = now.()
        t.times { go << :go }
        ths.each(&:join)
        s = now.() - t0
        wrong = bad.sum
      else
        readers = []
        pids = Array.new(t) do
          r, w = IO.pipe
          gr, gw = IO.pipe
          readers << [r, gw]
          fork do |; ver|
            r.close
            gw.close
            ver = AprvWasm::Verifier.new
            warm.times { ver.call(op, data) }
            w.puts "ready"
            w.flush
            gr.gets
            b = 0
            n.times { b += 1 unless ver.call(op, data).start_with?(OK) }
            w.puts b
            w.close
            exit!(0)
          end
        end
        readers.each { |r, _| r.gets }
        t0 = now.()
        readers.each { |_, gw| gw.puts "go"; gw.flush }
        wrong = readers.sum { |r, _| r.gets.to_i }
        s = now.() - t0
        pids.each { |p| Process.wait(p) }
      end
      puts JSON.generate({ id: id, op: op, kind => t, warm_each: warm, n_each: n, seconds: s.round(2),
                           total_per_s: (t * n / s).round(1), not_verified: wrong })
    end
  end
when "isolation"
  op, g5 = ROWS[G5_ID]
  a = AprvWasm::Verifier.new
  b = AprvWasm::Verifier.new
  ref = a.call(op, g5)
  begin
    a.call(99, "")
  rescue AprvWasm::WasmTrapError
    nil
  end
  same_b = b.call(op, g5) == ref
  same_a = a.call(op, g5) == ref
  puts JSON.generate({ test: "independent instances: a trap in A leaves B untouched; A restarts fresh", b_unchanged: same_b,
                       a_after_trap: same_a, a_traps: a.traps, b_traps: b.traps, pass: same_b && same_a && a.traps == 1 && b.traps.zero? })
  results = Array.new(4) do
    Thread.new do |; ver, good, errors|
      ver = AprvWasm::Verifier.new
      good = errors = 0
      210.times do |i|
        if i % 7 == 6
          begin
            ver.call(99, "")
            errors += 1
          rescue AprvWasm::WasmTrapError
            nil
          end
        elsif ver.call(op, g5) == ref
          good += 1
        else
          errors += 1
        end
      end
      [good, ver.traps, errors]
    end
  end.map(&:value)
  puts JSON.generate({ test: "4 threads, one Verifier each, a trap every 7th call", good_calls: results.map(&:first),
                       traps: results.map { |r| r[1] }, errors: results.sum(&:last),
                       pass: results.all? { |g, tr, e| g == 180 && tr == 30 && e.zero? } })
end
