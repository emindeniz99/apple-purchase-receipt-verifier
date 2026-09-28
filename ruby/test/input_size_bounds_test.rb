# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The input size caps, one row of the cross-port table at a time.
#
# A cap exists so that an unauthenticated caller cannot make the library
# decode or parse an arbitrarily large input: base64 decoding, the CMS parse
# and JSON parsing all allocate in proportion to what they are given, and all
# of it happens before any signature is checked. So each row pins three
# things: one unit over the cap is refused WITHOUT the expensive step running
# (a spy fails the test if it does), exactly at the cap the cap does not
# refuse (the input goes on to be judged on its merits), and the exact answer
# a caller branches on. The receipt and request numbers are Apple's: its
# verifyReceipt answers a 3,145,728-byte body and refuses a 3,145,729-byte one
# with HTTP 413, counting UTF-8 bytes (measured 2026-09-23).
class InputSizeBoundsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  RECEIPT_CAP = 3_145_728
  REQUEST_CAP = 3_145_728
  JWS_CAP = 262_144
  DEPTH_CAP = 64

  # Counts calls to `split` and then does what String does, so a test can
  # tell whether the JWS was split without changing how it is split.
  class SplitCountingString < String
    attr_reader :splits

    def split(*)
      @splits = (@splits || 0) + 1
      super
    end
  end

  def setup
    @root = TestPki.receipt_pki.root
    @jws_pki = TestPki.jws_pki
    @clock = APRV::ClockOnce.new(-> { Time.now.to_i * 1000 })
  end

  def verify_receipt(text)
    APRV::Receipt.verify(text, [@root], @clock)
  end

  def verify_jws(text)
    APRV::Jws.verify(text, [@jws_pki.root], @clock)
  end

  def verify_endpoint(request_json)
    verifier = APRV::Verifier.create(APRV::Config.new(roots: [@root]))
    JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_json))
  end

  def assert_reason(reason, &)
    error = assert_raises(APRV::VerificationError, &)
    assert_equal reason, error.reason, error.message
    error
  end

  # Runs the block with the singleton method `name` of `target` replaced by
  # `spy`, and puts the original back afterwards. Written out rather than
  # taken from minitest/mock, which minitest 6 moved to a separate gem.
  def replacing(target, name, spy)
    original = target.method(name)
    target.define_singleton_method(name, &spy)
    yield
  ensure
    target.define_singleton_method(name, original)
  end

  # The block runs with `name` failing the test if anything calls it.
  def forbidding(target, name, &)
    replacing(target, name, ->(*) { flunk "#{target}.#{name} ran on an input over the cap" }, &)
  end

  # The block runs with `name` counting its calls and otherwise behaving as
  # before; returns the count.
  def counting(target, name, &)
    original = target.method(name)
    calls = 0
    replacing(target, name, lambda { |*args|
      calls += 1
      original.call(*args)
    }, &)
    calls
  end

  def forbidding_base64_decode(&)
    forbidding(APRV::Receipt, :decode_canonical_base64, &)
  end

  # -- the constants themselves ---------------------------------------------

  def test_the_caps_are_public_and_carry_the_cross_port_numbers
    assert_equal RECEIPT_CAP, APRV::Receipt::MAX_RECEIPT_BASE64_BYTES
    assert_equal REQUEST_CAP, APRV::Endpoint::MAX_REQUEST_BYTES
    assert_equal JWS_CAP, APRV::Jws::MAX_JWS_BYTES
    assert_equal DEPTH_CAP, APRV::Json::MAX_NESTING_DEPTH
  end

  # -- receipt base64 string -------------------------------------------------

  def test_a_base64_receipt_one_byte_over_the_cap_is_refused_before_decoding
    text = "A" * (RECEIPT_CAP + 1)
    forbidding_base64_decode do
      error = assert_reason(:TOO_LARGE) { verify_receipt(text) }
      assert_equal "receipt exceeds the maximum accepted size of 3145728 bytes", error.message
    end
  end

  # Bytes, not characters, as Apple counts them. Half the cap in two-byte
  # characters is exactly the cap and passes it (then fails as not base64);
  # one more byte is refused by the cap although it is far fewer characters.
  def test_the_base64_cap_counts_utf8_bytes_not_characters
    at_cap = "é" * (RECEIPT_CAP / 2)
    assert_equal RECEIPT_CAP, at_cap.bytesize
    error = assert_reason(:MALFORMED) { verify_receipt(at_cap) }
    refute_match(/maximum accepted size/, error.message)

    over = "#{at_cap}A"
    assert_operator over.length, :<, RECEIPT_CAP
    forbidding_base64_decode do
      error = assert_reason(:TOO_LARGE) { verify_receipt(over) }
      assert_match(/maximum accepted size of 3145728 bytes/, error.message)
    end
  end

  def test_a_base64_receipt_exactly_at_the_cap_is_decoded
    # Valid base64 of 2.25 MiB of zero bytes: past the cap check it decodes,
    # and the DER scan is what refuses it.
    text = "A" * RECEIPT_CAP
    error = nil
    calls = counting(APRV::Receipt, :decode_canonical_base64) do
      error = assert_reason(:MALFORMED) { verify_receipt(text) }
    end
    assert_equal 1, calls
    refute_match(/maximum accepted size/, error.message)
  end

  # The contract's byte floor (1 MiB of DER, 1.38 MB of base64) is far under
  # both caps and must keep verifying through every entry point, the JSON
  # body included.
  def test_the_byte_floor_receipt_verifies_through_every_entry_point
    der = TestSupport.fixture_bytes("receipt-byte-floor")
    root = TestSupport.fixture_certificate("large-receipt-root")
    base64 = [der].pack("m0")
    payload = APRV::Receipt.verify(base64, [root], @clock)
    assert_equal 2300, payload.in_app.size

    verifier = APRV::Verifier.create(APRV::Config.new(roots: [root]))
    result = verifier.verify_receipt(base64)
    assert_predicate result, :verified?
    assert_equal 2300, result.payload.in_app.size

    body = JSON.generate({ "receipt-data" => base64 })
    assert_operator body.bytesize, :<=, REQUEST_CAP
    response = JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, body))
    assert_equal 0, response["status"]
  end

  # -- the endpoint's receipt-data ------------------------------------------

  def test_receipt_data_over_the_cap_answers_21002_without_decoding
    data = "A" * (RECEIPT_CAP + 1)
    forbidding_base64_decode do
      response = verify_endpoint(JSON.generate({ "receipt-data" => data }))
      assert_equal({ "status" => 21_002 }, response)
    end
  end

  # -- the endpoint's raw JSON body -----------------------------------------

  # A well-formed request whose JSON text is exactly `size` bytes.
  def body_of(size)
    frame = '{"receipt-data":""}'.bytesize
    JSON.generate({ "receipt-data" => "A" * (size - frame) })
  end

  def test_a_body_one_byte_over_the_cap_answers_21002_without_parsing
    body = body_of(REQUEST_CAP + 1)
    assert_equal REQUEST_CAP + 1, body.bytesize
    forbidding(APRV::Json, :parse_leading_object) do
      assert_equal({ "status" => 21_002 }, verify_endpoint(body))
    end
  end

  # The size is decided before the JSON is looked at, so a body that is both
  # too large and not JSON still answers 21002 (Apple's own status for this).
  def test_an_oversized_malformed_body_answers_21002_without_parsing
    body = "[" * (REQUEST_CAP + 1)
    forbidding(APRV::Json, :parse_leading_object) do
      assert_equal({ "status" => 21_002 }, verify_endpoint(body))
    end
  end

  def test_a_body_exactly_at_the_cap_is_parsed
    body = body_of(REQUEST_CAP)
    assert_equal REQUEST_CAP, body.bytesize
    # Parsed, so the answer is about the receipt it carries (3 MiB of "A" is
    # base64 of zero bytes, which is no receipt), not about the body.
    assert_equal({ "status" => 21_002 }, verify_endpoint(body))
  end

  # The request cap is in bytes, as Apple counts it: a body of two-byte
  # characters exactly at the cap in bytes is parsed, and one byte more is
  # refused although it is barely half the cap in characters. Counting
  # characters would let the second one through.
  def test_the_body_cap_counts_utf8_bytes_not_characters
    frame = '{"receipt-data":"AQIDBA==","password":""}'.bytesize
    padding = "é" * ((REQUEST_CAP - frame) / 2)
    at_cap = JSON.generate({ "receipt-data" => "AQIDBA==", "password" => padding })
    at_cap = "#{at_cap} " while at_cap.bytesize < REQUEST_CAP
    assert_equal REQUEST_CAP, at_cap.bytesize
    # Parsed, and read as far as receipt-data (four bytes of no receipt).
    assert_equal 21_002, verify_endpoint(at_cap)["status"]

    over = "#{at_cap} "
    assert_equal REQUEST_CAP + 1, over.bytesize
    assert_operator over.length, :<=, REQUEST_CAP
    assert_equal 21_002, verify_endpoint(over)["status"]
  end

  # A body in another encoding, such as the ASCII-8BIT String Rack hands over,
  # is measured in its own bytes: the bytes that arrived on the wire.
  def test_a_binary_body_is_measured_in_its_bytes
    over = body_of(REQUEST_CAP + 1).b
    assert_equal Encoding::BINARY, over.encoding
    assert_equal 21_002, verify_endpoint(over)["status"]
    at_cap = body_of(REQUEST_CAP).b
    assert_equal 21_002, verify_endpoint(at_cap)["status"]
  end

  # -- JSON nesting depth ----------------------------------------------------

  # A request `depth` containers deep: the envelope object, then arrays in its
  # "x" member, the innermost one holding `inner`. An empty innermost
  # container is the shape newer json gems forget to count.
  def request_of_depth(depth, inner: "")
    arrays = depth - 1
    arrays -= 1 if inner == "{}"
    %({"receipt-data":"AQIDBA==","x":#{"[" * arrays}#{inner}#{"]" * arrays}})
  end

  def test_a_body_nested_exactly_64_deep_is_read
    ["", "1", "{}"].each do |inner|
      # Read all the way to receipt-data, which is four bytes of no receipt.
      assert_equal 21_002, verify_endpoint(request_of_depth(DEPTH_CAP, inner: inner))["status"], inner
    end
  end

  def test_a_body_nested_65_deep_answers_21002_without_decoding
    forbidding_base64_decode do
      ["", "1", "{}"].each do |inner|
        body = request_of_depth(DEPTH_CAP + 1, inner: inner)
        assert_equal({ "status" => 21_002 }, verify_endpoint(body), inner)
      end
    end
  end

  # -- JWS compact string ----------------------------------------------------

  def test_a_jws_one_character_over_the_cap_is_refused_before_it_is_split
    jws = SplitCountingString.new("a" * (JWS_CAP + 1))
    error = assert_reason(:TOO_LARGE) { verify_jws(jws) }
    assert_equal "jws exceeds the maximum accepted size of 262144 bytes", error.message
    assert_nil jws.splits
  end

  def test_a_jws_exactly_at_the_cap_is_split
    jws = SplitCountingString.new("a" * JWS_CAP)
    error = assert_reason(:MALFORMED) { verify_jws(jws) }
    assert_equal 1, jws.splits
    assert_equal "expected 3 dot-separated segments, got 1", error.message
  end

  # -- JWS header and payload depth -----------------------------------------

  # A member value that makes the header or payload `depth` containers deep:
  # the segment's own object, then arrays, the innermost holding `inner`
  # (which counts as one more level when it is itself a container).
  def member_of_depth(depth, inner)
    arrays = depth - 1
    arrays -= 1 if inner.is_a?(Hash) || inner.is_a?(Array)
    arrays.times.reduce(inner) { |value, _| [value] }
  end

  def test_a_jws_header_or_payload_nested_exactly_64_deep_verifies
    header = TestPki.sign_jws(@jws_pki, TestPki.default_claims,
                              header_overrides: { "x" => member_of_depth(DEPTH_CAP, []) })
    payload = TestPki.sign_jws(@jws_pki, TestPki.default_claims("x" => member_of_depth(DEPTH_CAP, [])))
    [header, payload].each do |jws|
      claims = JSON.parse(verify_jws(jws).json)
      assert_equal "com.example.app", claims["bundleId"]
    end
  end

  def test_a_jws_header_nested_65_deep_is_malformed
    [[], [1], {}].each do |inner|
      header = TestPki.sign_jws(@jws_pki, TestPki.default_claims,
                                header_overrides: { "x" => member_of_depth(DEPTH_CAP + 1, inner) })
      error = assert_reason(:MALFORMED) { verify_jws(header) }
      assert_match(/header is not a JSON object/, error.message)
    end
  end

  # A payload nested past the bound does not parse, but that is carried past
  # the signature check rather than rejected outright (docs/design/
  # 0.7-api.md): the signature here is genuine, so the verdict is
  # UNREADABLE_PAYLOAD, not MALFORMED.
  def test_a_jws_payload_nested_65_deep_is_unreadable_after_a_genuine_signature
    [[], [1], {}].each do |inner|
      claims = TestPki.default_claims("x" => member_of_depth(DEPTH_CAP + 1, inner))
      payload = TestPki.sign_jws(@jws_pki, claims)
      error = assert_reason(:UNREADABLE_PAYLOAD) { verify_jws(payload) }
      assert_equal "signed payload is not a JSON object", error.message
    end
  end
end
