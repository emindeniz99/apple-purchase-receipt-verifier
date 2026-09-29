# frozen_string_literal: true

# Spike only (2026-09-26). Shared helpers for the Ruby harness.
require "base64"
require "json"
require "aprv_wasm"

G5_ID = "receipt/verify-genuine-sandbox-g5-against-apple-roots"
JWS_ID = "transaction/verify-shared-sandbox"
OK = '{"verified":true'.b

def load_calls(path)
  File.foreach(path, encoding: "UTF-8").map { |l| JSON.parse(l) }
end

def call_of(calls, id)
  c = calls.find { |x| x["id"] == id }
  [c["op"], Base64.strict_decode64(c["input"])]
end

# A JSON string literal, escaped the way JSON.stringify escapes.
def quote(s)
  out = +'"'
  s.each_char do |ch|
    out << case ch
           when '"' then '\\"'
           when "\\" then "\\\\"
           when "\n" then '\\n'
           when "\r" then '\\r'
           when "\t" then '\\t'
           when "\b" then '\\b'
           when "\f" then '\\f'
           else ch.ord < 0x20 ? format('\\u%04x', ch.ord) : ch
           end
  end
  out << '"'
end
