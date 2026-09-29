# frozen_string_literal: true

# Runs a canonical-ABI calls file (docs/evidence/2026-09-29-canonical-abi-final/
# py/calls_bytes.py) through the gem's own host code and prints one row per
# call in the format of the spike's Node runner, so the rows can be compared
# byte for byte with the reference rows (py/classify.py).
#
#   ruby -Ilib bench/corpus.rb calls/cases.jsonl > run/ruby-cases.jsonl
#
# It drives the module's raw answers: the facade's typed results would hide
# the JSON the comparison is about. The instance handling is the facade's
# (Guest, one per init configuration, discarded after a trap) and the module
# is the one the gem ships, so what is measured is the gem's host path.
#
# Rows: {"id","out"} for an answer, {"id","trap"} when the call trapped, and
# {"id","map"} for a row that names no call. A configuration `init` refuses
# is the row's answer, as the other hosts' runners report it.

require "json"
require "apple_purchase_receipt_verifier"

module CorpusRun
  APRV = ApplePurchaseReceiptVerifier
  OK = '{"ok":true}'

  module_function

  def now_ms
    (Time.now.to_r * 1000).to_i
  end

  def main(path)
    # APRV_WASM is this script's own option (the library reads no
    # environment variable): it names the module to measure, checked
    # against the same recorded hash.
    override = ENV.fetch("APRV_WASM", "")
    runtime = override.empty? ? APRV::Runtime.shared : APRV::Runtime.new(APRV::Runtime.read_module(override))
    guests = {}
    rows = traps = created = 0
    output = $stdout
    output.binmode
    File.foreach(path, encoding: "UTF-8") do |line|
      next if line.strip.empty?

      call = JSON.parse(line)
      rows += 1
      id = call.fetch("id")
      if call.key?("map")
        output.write(JSON.generate("id" => id, "map" => call["map"]), "\n")
        next
      end

      config = call.fetch("config")
      guest = guests[config]
      answer = nil
      if guest.nil?
        guest = APRV::Guest.new(runtime, nil)
        created += 1
        init = guest.call("init", [], config)
        if init == OK
          guests[config] = guest
        else
          guest.close
          answer = init # `init` refused the configuration: that is the row's answer
        end
      end
      begin
        answer ||= invoke(guest, call)
        output.write(JSON.generate("id" => id, "out" => answer), "\n")
      rescue APRV::TrapError => e
        traps += 1
        guests.delete(config)
        output.write(JSON.generate("id" => id, "trap" => e.message), "\n")
      end
    end
    warn JSON.generate("host" => "ruby #{RUBY_VERSION}, wasmtime #{Wasmtime::VERSION}",
                       "rows" => rows, "traps" => traps, "instances" => created)
  end

  def invoke(guest, call)
    now = call["now"] || now_ms
    text = call.fetch("b64").unpack1("m")
    case call.fetch("fn")
    when "verify-receipt", "verify-signed-data" then guest.call(call["fn"], [now], text)
    else guest.call("verify-receipt-endpoint", [call.fetch("env"), now], text)
    end
  end
end

CorpusRun.main(ARGV.fetch(0)) if $PROGRAM_NAME == __FILE__
