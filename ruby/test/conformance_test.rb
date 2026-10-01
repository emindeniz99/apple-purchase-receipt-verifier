# frozen_string_literal: true

require_relative "helper"

# Runs fixtures/cases.json — the normative cross-language conformance
# vectors for the 0.7 API (docs/design/0.7-api.md) — against this
# implementation.
#
# The adapter below knows nothing about any individual case. It loads the
# file, resolves fixture ids to bytes and checks their recorded digest,
# builds a {Verifier} from the generic config, dispatches on "operation",
# evaluates the JSON the verified payload (or the endpoint response) prints,
# and reads the reason off a failure. There is no skip list, no case id
# anywhere, and no per-case fixup: a vector that disagrees with the library
# is a bug report against one of the two, never something to special-case
# here.
class ConformanceTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  CASES = TestSupport.cases
  BRACKET_TOKEN = /\A\[(.+)=(.*)\]\z/

  # A key comes back either as this pointer form's own key, or as its
  # snake_case Ruby reader name — `unknown_attributes` values are objects
  # keyed by attribute TYPE, so a bare-digit key is never snake_cased.
  def snake_case(name)
    name.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
  end

  VERIFIERS = {} # rubocop:disable Style/MutableConstant

  # The module with Apple's roots, for the decodeBase64 cases, which read its
  # raw answers.
  RAW_POOL = Internals::InstancePool.new(Internals::Runtime.shared, '{"roots":[]}')

  # Mutable on purpose: the coverage self-check below records what actually
  # ran, which is the point.
  EXECUTED = [] # rubocop:disable Style/MutableConstant

  # Read before any case runs: a fixture no case happens to reference would
  # otherwise drift unnoticed, and the registry is the thing being guarded.
  def test_every_registered_fixture_matches_its_recorded_content_sha256
    ids = CASES["fixtures"].keys
    refute_empty ids, "cases.json must register fixtures"
    ids.each { |id| TestSupport.fixture_bytes(id) }
  end

  # Asserts against the parsed length, never a literal: a silently dropped
  # operation cannot hide behind a hardcoded count.
  def test_a_test_method_exists_for_every_case
    expected = CASES["cases"].map { |kase| kase["id"] }.sort
    defined = self.class.instance_methods.grep(/\Atest_case_/).map do |name|
      self.class.case_id_for(name)
    end.compact.sort
    assert_equal expected, defined
  end

  class << self
    def case_ids
      @case_ids ||= {}
    end

    def case_id_for(method_name)
      case_ids[method_name.to_sym]
    end

    def define_case(kase)
      name = :"test_case_#{kase["id"].gsub(/[^a-z0-9]+/i, "_")}"
      case_ids[name] = kase["id"]
      define_method(name) do
        EXECUTED << kase["id"]
        run_case(kase)
      end
    end
  end

  private

  # --- fixtures and roots ---------------------------------------------------

  def fixture_entry(id)
    CASES["fixtures"].fetch(id) { raise "harness error: cases.json registers no fixture #{id.inspect}" }
  end

  # verifyReceipt / the endpoint's receipt-data: a text fixture is handed
  # over verbatim; a raw or base64 fixture holds DER, encoded as canonical
  # standard base64 with padding.
  def receipt_data_string(fixture_id)
    bytes = TestSupport.fixture_bytes(fixture_id)
    fixture_entry(fixture_id)["codec"] == "text" ? bytes : [bytes].pack("m0")
  end

  # verifySignedData: the fixture's logical bytes as a String.
  def jws_string(fixture_id)
    TestSupport.fixture_bytes(fixture_id).dup.force_encoding(Encoding::UTF_8)
  end

  # The trust anchors a case pins, as the DER bytes of their fixtures; nil
  # is Apple's three, which the module carries.
  def trusted_roots(spec)
    return nil if spec["source"] == "defaults"

    spec["fixtures"].map { |id| TestSupport.fixture_bytes(id) }
  end

  # One verifier per distinct configuration, shared by the cases that use it
  # the way a service shares one: it holds a pool of wasm instances, each
  # with 2 MiB or more of linear memory, and 311 of them would be gigabytes
  # for the collector to find.
  def build_verifier(config_spec, clock_spec)
    key = [config_spec["trustedRoots"], clock_spec&.fetch("now")]
    VERIFIERS[key] ||= begin
      clock = clock_spec.nil? ? nil : -> { (Time.iso8601(clock_spec["now"]).to_r * 1000).to_i }
      config = APRV::Config.new(roots: trusted_roots(config_spec["trustedRoots"]), clock: clock)
      APRV::Verifier.create(config)
    end
  end

  # --- dispatch --------------------------------------------------------------

  def dispatch(kase)
    case kase["operation"]
    when "verifyReceipt"
      verifier = build_verifier(kase["config"], kase["clock"])
      verifier.verify_receipt(receipt_data_string(kase["input"]["fixture"]))
    when "verifySignedData"
      verifier = build_verifier(kase["config"], kase["clock"])
      verifier.verify_signed_data(jws_string(kase["input"]["fixture"]))
    else
      raise "harness error: no adapter for operation #{kase["operation"].inspect}"
    end
  end

  def endpoint_request_body(kase)
    input = kase["input"]
    if input.key?("requestBody")
      return TestSupport.fixture_bytes(input["requestBody"]).dup.force_encoding(Encoding::UTF_8)
    end

    JSON.generate({ "receipt-data" => receipt_data_string(input["fixture"]) })
  end

  def run_endpoint_case(kase)
    verifier = build_verifier(kase["config"], kase["clock"])
    body = endpoint_request_body(kase)
    response = measured(kase) { verifier.verify_receipt_endpoint(kase["config"]["environment"], body) }
    actual = JSON.parse(response, allow_duplicate_key: true)
    assert_fields(kase["expected"], actual, kase["id"])
  end

  # --- running one case --------------------------------------------------

  def run_case(kase)
    return run_decode_base64(kase) if kase["operation"] == "decodeBase64"
    return run_endpoint_case(kase) if kase["operation"] == "verifyReceiptEndpoint"

    expected = kase["expected"]
    result = measured(kase) { dispatch(kase) }

    if expected["oneOf"]
      outcome = result.verified? ? "ok" : result.failure.reason.to_s
      assert_includes expected["oneOf"], outcome, "#{kase["id"]}: answered #{outcome}"
      return
    end

    if expected["status"] == "error"
      refute_predicate result, :verified?, "#{kase["id"]}: expected #{expected["reason"]} but it verified"
      assert_equal expected["reason"], result.failure.reason.to_s, "#{kase["id"]}: reason"
      assert_message_excludes(expected["messageMustNotContain"], result.failure.message, kase["id"])
      return
    end

    assert_predicate result, :verified?,
                     "#{kase["id"]}: expected ok but got #{result.failure&.reason} " \
                     "(#{result.failure&.message})"
    actual = JSON.parse(result.payload.respond_to?(:json) ? result.payload.json : result.payload.to_json,
                        allow_duplicate_key: true)
    assert_fields(expected, actual, kase["id"])

    return unless expected.key?("toJson")

    # Same value, not same bytes (docs/design/0.7-api.md, "Our JSON").
    assert_equal JSON.parse(expected["toJson"]), actual, "#{kase["id"]}: toJson value"
  end

  # Runs the case's operation, measuring the SECOND call (after one
  # warm-up) against `maxMillis` when the case carries one. The timing
  # budget is a coarse backstop: the bounds themselves are the module's.
  def measured(kase, &block)
    return yield unless kase["maxMillis"]

    yield # warm-up, not measured
    # The monotonic clock, not the benchmark gem: it left the default gems
    # in Ruby 4.0 and is not in the Gemfile (bench/bench.rb does the same).
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = block.call
    millis = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
    assert_operator millis, :<=, kase["maxMillis"],
                    "#{kase["id"]}: took #{millis.round(1)}ms, budget #{kase["maxMillis"]}ms"
    result
  end

  def assert_message_excludes(codepoints, message, case_id)
    return if codepoints.nil?

    present = message.codepoints & codepoints
    assert_empty present,
                 "#{case_id}: message #{message.inspect} contains forbidden code points #{present.inspect}"
  end

  def assert_fields(expected, actual, case_id)
    (expected["fields"] || {}).each do |pointer, want|
      got = resolve_pointer(actual, pointer)
      if want.nil?
        assert_nil got, "#{case_id}: #{pointer}: expected absent, got #{got.inspect}"
      else
        assert_equal want, got, "#{case_id}: #{pointer}"
      end
    end
    (expected["lengths"] || {}).each do |pointer, want|
      got = resolve_pointer(actual, pointer)
      assert_kind_of Array, got, "#{case_id}: #{pointer}: not an array"
      assert_equal want, got.length, "#{case_id}: #{pointer} length"
    end
  end

  # --- decodeBase64 -----------------------------------------------------

  # The cases pin the two base64 rules (`receipt-data`, `x5c`) by calling
  # each decoder directly. Through a host there is no decoder to call: the
  # receipt-data rule runs inside the module's `verify-receipt`, so each text
  # is handed to it and must land on its group's side of the rule
  # (docs/rust-core/SURFACE.md, section 6). An accepted text decodes to bytes
  # that are no receipt, so the module refuses it further on, never with the
  # base64 refusal; a refused text carries the base64 refusal and the
  # group's reason. The answer is read raw, since the facade would hide
  # which stage refused.
  #
  # The x5c rule needs a JWS whose header carries the text, which the
  # migration's Phase 1 builds for the runners; until then only the
  # receipt-data decoder runs through the host here.
  def run_decode_base64(kase)
    texts = kase["input"]["texts"]
    raise "harness error: #{kase["id"]}: no texts or no decoders" if texts.empty? || kase["decoders"].empty?
    return unless kase["decoders"].include?("receipt-data")

    expected = kase["expected"]
    texts.each_with_index do |text, index|
      where = "#{kase["id"]}: receipt-data texts[#{index}] #{text.inspect}"
      answer = raw_receipt_answer(text)
      # The module words the empty text's refusal "receipt is empty" (it is
      # refused before any decoding); every other text carries "base64".
      refused = answer["verified"] == false && answer["message"].to_s.match?(/base64|\Areceipt is empty\z/)
      if expected["status"] == "ok"
        refute refused, "#{where}: refused by the base64 rule, want #{expected["bytesHex"]}"
      else
        assert refused, "#{where}: not refused by the base64 rule: #{answer.inspect}"
        assert_equal expected["reason"], answer["reason"], "#{where}: reason"
      end
    end
  end

  def raw_receipt_answer(text)
    RAW_POOL.with_guest do |guest|
      JSON.parse(guest.call("verify-receipt", [Time.now.to_i * 1000], text))
    end
  end

  # --- JSON Pointer, with the [key=value] extension -----------------------

  def resolve_pointer(root, pointer)
    return root if pointer.empty?

    tokens = pointer.split("/", -1)[1..].map { |t| t.gsub("~1", "/").gsub("~0", "~") }
    tokens.reduce(root) { |current, token| resolve_token(current, token, pointer) }
  end

  def resolve_token(current, token, pointer)
    return nil if current.nil?

    match = BRACKET_TOKEN.match(token)
    return resolve_bracket(current, match[1], match[2], pointer) if match

    if current.is_a?(Array)
      index = Integer(token, exception: false)
      return nil if index.nil?

      current[index]
    elsif current.is_a?(Hash)
      return current[token] if current.key?(token)

      snake = snake_case(token)
      current.key?(snake) ? current[snake] : nil
    else
      raise "harness error: #{pointer}: .#{token} does not select from an object"
    end
  end

  def resolve_bracket(current, key, wanted, pointer)
    unless current.is_a?(Array)
      raise "harness error: #{pointer}: [#{key}=#{wanted}] does not select from an array"
    end

    matches = current.select do |element|
      element.is_a?(Hash) && (element[key] || element[snake_case(key)]) == wanted
    end
    unless matches.size == 1
      raise "harness error: #{pointer}: [#{key}=#{wanted}] must select exactly one element, " \
            "selected #{matches.size}"
    end

    matches.first
  end

  CASES["cases"].each { |kase| define_case(kase) }
end

# The coverage self-check a defined-but-never-run case could still evade:
# every case in the file must actually have executed. Asserted against the
# parsed length, never a literal, so a silently dropped operation cannot
# hide behind a hardcoded count.
CONFORMANCE_RUN_WAS_FILTERED = ARGV.any? { |argument| argument.match?(/\A(-n|--name|--seed=)/) }

Minitest.after_run do
  unless CONFORMANCE_RUN_WAS_FILTERED
    expected = TestSupport.cases["cases"].map { |kase| kase["id"] }.sort
    ran = ConformanceTest::EXECUTED.sort.uniq
    unless ran == expected
      warn "conformance coverage gap: #{(expected - ran).inspect} never ran"
      exit(1)
    end
  end
end
