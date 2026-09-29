# frozen_string_literal: true

# Spike only (2026-09-26). Start-up in a fresh process (ms): require, the
# first Verifier (Engine + Cranelift compile + Linker + instantiate +
# _initialize), a second Verifier, the first and second call.
#   ruby startup.rb calls-cases.jsonl
t = ->() { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
t0 = t.()
require_relative "common"
t1 = t.()
v = AprvWasm::Verifier.new
t2 = t.()
AprvWasm::Verifier.new
t3 = t.()
op, g5 = call_of(load_calls(ARGV[0]), G5_ID)
t4 = t.()
raise unless v.call(op, g5).start_with?(OK)

t5 = t.()
raise unless v.call(op, g5).start_with?(OK)

t6 = t.()
ms = ->(a, b) { ((b - a) * 1000).round(1) }
puts JSON.generate({ require_ms: ms.(t0, t1), first_verifier_ms: ms.(t1, t2), second_verifier_ms: ms.(t2, t3),
                     first_call_ms: ms.(t4, t5), second_call_ms: ms.(t5, t6) })
