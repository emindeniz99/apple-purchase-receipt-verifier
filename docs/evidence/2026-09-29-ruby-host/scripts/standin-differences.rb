# frozen_string_literal: true

# Runs the 311 conformance cases against the module in the tree and says, for
# each case that fails, why. Written for the stand-in module (round 13's, with
# the 0.6 core); after the release module replaces it there should be nothing
# to list.
#
#   cd ruby && OUT=standin-differences.txt bundle exec ruby ../docs/evidence/2026-09-29-ruby-host/scripts/standin-differences.rb
#
# Categories:
#   payload-shape       the module verified, in its 0.6 wire (camelCase, ISO dates), so the
#                       facade cannot read it: INTERNAL_ERROR
#   reason vocabulary   the module refused with a 0.6 reason token that maps onto the
#                       expected 0.7 reason (INVALID_RECEIPT_FORMAT to MALFORMED, ...)
#   verdict             the 0.6 core decided differently, even after mapping its vocabulary
#   decodeBase64        the base64 rule agrees; only the 0.6 reason token differs
$LOAD_PATH.unshift(File.expand_path("lib", Dir.pwd), File.expand_path("test", Dir.pwd))
ARGV.replace(["-n", "/nothing/"]) # keep minitest from running at exit
require "conformance_test"

APRV = ApplePurchaseReceiptVerifier
MAP = {
  "INVALID_RECEIPT_FORMAT" => %w[MALFORMED], "INVALID_JWS_FORMAT" => %w[MALFORMED],
  "MALFORMED_REQUEST" => %w[MALFORMED], "REQUEST_TOO_LARGE" => %w[TOO_LARGE],
  "INVALID_CHAIN" => %w[UNTRUSTED_CHAIN INVALID_CERTIFICATE], "INVALID_SIGNATURE" => %w[INVALID_SIGNATURE],
  "INVALID_CERTIFICATE" => %w[INVALID_CERTIFICATE],
  "INVALID_CERTIFICATE_PURPOSE" => %w[INVALID_CERTIFICATE_PURPOSE],
  "INTERNAL_ERROR" => %w[UNREADABLE_PAYLOAD INTERNAL_ERROR]
}.freeze
CASES = TestSupport.cases["cases"]
pools = {}
rows = []
CASES.each do |kase|
  result = ConformanceTest.new("test_case_#{kase["id"].gsub(/[^a-z0-9]+/i, "_")}").run
  next if result.passed?

  category = "other"
  op = kase["operation"]
  if %w[verifyReceipt verifySignedData].include?(op)
    trusted = kase["config"]["trustedRoots"]
    roots = trusted["source"] == "defaults" ? [] : trusted["fixtures"].map { |f| [TestSupport.fixture_bytes(f)].pack("m0") }
    pool = (pools[roots] ||= APRV::InstancePool.new(APRV::Runtime.shared, JSON.generate("roots" => roots)))
    fixture = kase["input"]["fixture"]
    bytes = TestSupport.fixture_bytes(fixture)
    text = op == "verifyReceipt" && TestSupport.cases["fixtures"][fixture]["codec"] != "text" ? [bytes].pack("m0") : bytes
    now = kase["clock"] ? (Time.iso8601(kase["clock"]["now"]).to_r * 1000).to_i : (Time.now.to_r * 1000).to_i
    operation = op == "verifyReceipt" ? "verify-receipt" : "verify-signed-data"
    raw = pool.with_guest { |guest| JSON.parse(guest.call(operation, [now], text)) }
    expected = kase["expected"]
    if raw["verified"] == true
      wanted_ok = expected["status"] == "ok" || expected["oneOf"]&.include?("ok")
      category = wanted_ok ? "payload-shape (0.6 wire)" : "verdict (the 0.6 core verifies, a refusal is expected)"
    else
      token = raw["reason"]
      wanted = expected["oneOf"] || [expected["reason"]].compact
      category =
        if expected["status"] == "ok" then "verdict (the 0.6 core refuses, ok is expected)"
        elsif (MAP[token] || []).intersect?(wanted) then "reason vocabulary (0.6 token #{token})"
        else "verdict (0.6 #{token}, expected #{wanted.join("|")})"
        end
    end
  elsif op == "verifyReceiptEndpoint"
    category = "endpoint (a 0.7 rule the 0.6 core lacks)"
  else
    category = "decodeBase64 (the rule agrees; the 0.6 reason token differs)"
  end
  rows << [kase["id"], category]
end
File.write(ENV.fetch("OUT", "standin-differences.txt"), "#{rows.map { |row| row.join("\t") }.join("\n")}\n")
rows.group_by(&:last).transform_values(&:size).sort_by { |_, n| -n }.each { |category, n| puts "#{n}\t#{category}" }
puts "failing: #{rows.size} of #{CASES.size}"
