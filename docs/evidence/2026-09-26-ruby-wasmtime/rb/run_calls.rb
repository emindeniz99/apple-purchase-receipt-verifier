# frozen_string_literal: true

# Spike only (2026-09-26). Runs a calls file (the ABI v1 round's
# py/abi_calls.py) through the facade, one Verifier (a trap discards its
# instance), printing rows in the Node runner's exact format.
#   ruby run_calls.rb calls.jsonl > out.jsonl
require_relative "common"

$stdout.binmode
v = AprvWasm::Verifier.new
rows = traps = 0
out = +""
File.foreach(ARGV[0], encoding: "UTF-8") do |line|
  next if line.strip.empty?

  c = JSON.parse(line)
  rows += 1
  id = quote(c["id"])
  unless c.key?("op")
    out << "{\"id\":#{id},\"map\":#{quote(c["map"])}}\n"
    next
  end
  begin
    res = v.call(c["op"], Base64.strict_decode64(c["input"])).force_encoding(Encoding::UTF_8)
    out << "{\"id\":#{id},\"out\":#{quote(res)}}\n"
  rescue AprvWasm::WasmTrapError, AprvWasm::AbiMismatchError => e
    traps += 1
    out << "{\"id\":#{id},\"trap\":#{quote(e.message)}}\n"
  end
end
$stdout.write(out.b)
warn JSON.generate({ host: "ruby-wasmtime", ruby: RUBY_VERSION, wasmtime: Gem.loaded_specs["wasmtime"].version.to_s, rows: rows, traps: traps })
