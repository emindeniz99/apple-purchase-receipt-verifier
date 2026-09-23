# frozen_string_literal: true

require_relative "helper"

# VerifyReceiptResult: one verification, then any number of renders.
#
# What matters here is what a caller builds a retry on. The receipt must
# survive a 21007/21008 so the other environment can be rendered without a
# second verification, and that re-render must recompute the status from the
# receipt itself: a result from a production endpoint must never be turned
# into a production 0 for a sandbox receipt, or the 21007 routing that keeps
# sandbox purchases out of production would be one method call away from
# being bypassed.
class VerifyReceiptResultTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  PRODUCTION = APRV::Environment::PRODUCTION
  SANDBOX = APRV::Environment::SANDBOX
  ENVIRONMENTS = [PRODUCTION, SANDBOX].freeze
  CLOCK_NOW = Time.utc(2026, 1, 1)
  EXPLICIT = Time.utc(2025, 6, 15, 12, 34, Rational(56_789, 1000))

  # A fixed clock that counts how often the endpoint reads it.
  class CountingClock
    attr_reader :calls

    def initialize
      @calls = 0
    end

    def call
      @calls += 1
      CLOCK_NOW
    end
  end

  def generated(name)
    File.binread(File.join(TestSupport.fixtures_root, "generated", name))
  end

  def b64(name)
    [generated(name)].pack("m0")
  end

  def endpoint(environment, root: "receipt-root.der", clock: CountingClock.new)
    APRV::VerifyReceiptEndpoint.new(trusted_roots: [generated(root)], environment: environment,
                                    clock: clock)
  end

  # A request Hash whose lookup raises: an unexpected failure inside the
  # pipeline, reached through the public API.
  def broken_request(error)
    Hash.new { raise error }
  end

  def assert_invariant(result, label)
    refute_equal result.receipt.nil?, result.failure_reason.nil?,
                 "#{label}: exactly one of receipt and failure_reason must be set"
    assert_equal !result.receipt.nil?, result.verified?, label
    assert_equal result.failure_reason == APRV::Reason::INTERNAL_ERROR, !result.failure_cause.nil?,
                 "#{label}: failure_cause is set exactly for INTERNAL_ERROR"
    assert_equal result.status, result.to_response["status"], label
    assert_predicate result.request_date, :utc?, label
    assert_predicate result, :frozen?, label
  end

  def test_exactly_one_of_receipt_and_failure_reason_for_every_status
    results = {
      "0 sandbox" => endpoint(SANDBOX).verify_receipt_data(b64("receipt.der")),
      "0 production" => endpoint(PRODUCTION).verify_receipt_data(b64("receipt-type-production.der")),
      "21007" => endpoint(PRODUCTION).verify_receipt_data(b64("receipt.der")),
      "21008" => endpoint(SANDBOX).verify_receipt_data(b64("receipt-type-production.der")),
      "21002" => endpoint(SANDBOX).verify_receipt_data("AQIDBA=="),
      "21003" => endpoint(SANDBOX).verify_receipt_data(b64("receipt-foreign.der")),
      "21009" => endpoint(SANDBOX).verify_receipt_result(broken_request(RuntimeError.new("boom")))
    }
    results.each do |label, result|
      assert_invariant(result, label)
      assert_equal label.split.first.to_i, result.status, label
    end
    # 21007 and 21008 are routing answers, not failures: the receipt
    # verified, so verified? is not the same check as status.zero?.
    ["0 sandbox", "0 production", "21007", "21008"].each do |label|
      assert_predicate results[label], :verified?, label
      refute_nil results[label].receipt, label
    end
    %w[21002 21003 21009].each { |label| refute_predicate results[label], :verified?, label }
  end

  def test_re_renders_for_either_environment_from_the_receipts_own_type
    # A production receipt is 0 on Production and 21008 on Sandbox; a sandbox
    # one (and one with no receipt_type, which fails closed as sandbox) is
    # 21007 on Production and 0 on Sandbox; a failure keeps its status. The
    # same whichever environment verified it.
    table = [
      ["receipt-type-production.der", "receipt-root.der", 0, 21_008],
      ["receipt-type-vpp.der", "receipt-root.der", 0, 21_008],
      ["receipt.der", "receipt-root.der", 21_007, 0],
      ["receipt-type-vpp-sandbox.der", "receipt-root.der", 21_007, 0],
      ["receipt-no-type.der", "receipt-root.der", 21_007, 0],
      ["receipt-foreign.der", "receipt-root.der", 21_003, 21_003],
      ["receipt-tampered-payload.der", "gaps-receipt-root.der", 21_003, 21_003]
    ]
    table.each do |fixture, root, on_production, on_sandbox|
      ENVIRONMENTS.each do |own|
        label = "#{fixture} from a #{own} endpoint"
        result = endpoint(own, root: root).verify_receipt_data(b64(fixture), now: EXPLICIT)
        assert_equal on_production, result.to_response(PRODUCTION)["status"], label
        assert_equal on_sandbox, result.to_response(SANDBOX)["status"], label
        ENVIRONMENTS.each do |target|
          # Each render is byte for byte what an endpoint of that environment
          # answers on its own.
          direct = endpoint(target, root: root).verify_receipt_data(b64(fixture), now: EXPLICIT).to_json
          assert_equal direct, result.to_json(target), "#{label} for #{target}"
        end
      end
    end
  end

  def test_a_sandbox_receipt_never_renders_a_production_zero
    %w[receipt.der receipt-type-vpp-sandbox.der receipt-no-type.der].each do |fixture|
      ENVIRONMENTS.each do |own|
        result = endpoint(own).verify_receipt_data(b64(fixture))
        assert_predicate result, :verified?, fixture
        assert_equal '{"status":21007}', result.to_json(PRODUCTION), fixture
        assert_equal({ "status" => 21_007 }, result.to_response(PRODUCTION), fixture)
      end
    end
  end

  def test_rendering_for_an_environment_apple_does_not_have_is_refused
    result = endpoint(SANDBOX).verify_receipt_data(b64("receipt.der"))
    bad_environments = [APRV::Environment::XCODE, APRV::Environment::LOCAL_TESTING, "production", "",
                        :Sandbox, 1]
    bad_environments.each do |bad|
      assert_raises(ArgumentError, bad.inspect) { result.to_response(bad) }
      assert_raises(ArgumentError, bad.inspect) { result.to_json(bad) }
    end
  end

  def test_an_explicit_now_sets_request_date_and_the_clock_is_read_once
    clock = CountingClock.new
    sandbox = endpoint(SANDBOX, clock: clock)
    receipt_data = b64("receipt.der")
    body = JSON.generate({ "receipt-data" => receipt_data })

    explicit = sandbox.verify_receipt_result({ "receipt-data" => receipt_data }, now: EXPLICIT)
    assert_equal 0, clock.calls, "an explicit now replaces the clock"
    assert_equal EXPLICIT, explicit.request_date
    receipt = explicit.to_response["receipt"]
    assert_equal "2025-06-15 12:34:56 Etc/GMT", receipt["request_date"]
    assert_equal "1749990896789", receipt["request_date_ms"]
    assert_equal "2025-06-15 05:34:56 America/Los_Angeles", receipt["request_date_pst"]
    # Any offset names the same instant, and the caller's Time is not changed.
    eastern = EXPLICIT.getlocal("-04:00")
    assert_equal explicit.to_json, sandbox.verify_receipt_data(receipt_data, now: eastern).to_json
    assert_equal(-4 * 3600, eastern.utc_offset)
    assert_equal explicit.to_json, sandbox.verify_receipt_result(body, now: EXPLICIT).to_json
    assert_equal 0, clock.calls

    # Without one, each call reads the clock exactly once, and rendering (in
    # either environment, any number of times) never reads it again, so one
    # result cannot carry two request dates.
    [
      -> { sandbox.verify_receipt_result({ "receipt-data" => receipt_data }) },
      -> { sandbox.verify_receipt_result(body) },
      -> { sandbox.verify_receipt_data(receipt_data) },
      -> { sandbox.verify_receipt_data(nil) },
      -> { sandbox.verify_receipt_result("not json") }
    ].each_with_index do |call, index|
      before = clock.calls
      result = call.call
      result.to_json
      result.to_json(PRODUCTION)
      result.to_response
      assert_equal before + 1, clock.calls, "call #{index}"
      assert_equal CLOCK_NOW, result.request_date, "call #{index}"
    end
    before = clock.calls
    sandbox.verify_receipt_json(body)
    assert_equal before + 1, clock.calls

    ["2025-06-15", 1_749_990_896, Date.new(2025, 6, 15)].each do |bad|
      assert_raises(ArgumentError, bad.inspect) { sandbox.verify_receipt_data(receipt_data, now: bad) }
    end
  end

  def test_an_explicit_now_does_not_move_certificate_validity
    # receipt-expired-fresh.der was created after its signing certificate
    # expired; 2020-06-01 is inside that certificate's window. A `now` that
    # reached the chain check would rescue it.
    sandbox = endpoint(SANDBOX, root: "receipt-expired-root.der")
    assert_predicate sandbox.verify_receipt_data(b64("receipt-expired-historical.der")), :verified?
    result = sandbox.verify_receipt_data(b64("receipt-expired-fresh.der"), now: Time.utc(2020, 6, 1))
    assert_equal 21_003, result.status
    assert_equal APRV::Reason::INVALID_CHAIN, result.failure_reason
  end

  def test_the_bare_receipt_answers_as_the_json_body_over_every_receipt_fixture
    # Every receipt the repository has, including the base64 contract strings
    # verbatim (whitespace, base64url, bad padding), through both the bare
    # entry point and a JSON body carrying it.
    root = TestSupport.fixtures_root
    roots = APRV.apple_receipt_roots +
            Dir[File.join(root, "generated", "*receipt*root.der")].map { |path| File.binread(path) }
    receipts = Dir[File.join(root, "generated", "receipt*.der")]
               .reject { |path| path.end_with?("root.der") }
               .map { |path| [File.binread(path)].pack("m0") }
    texts = Dir[File.join(root, "generated", "receipt-b64", "*.txt")] +
            Dir[File.join(root, "public-receipts", "*.b64")]
    receipt_data = receipts + texts.map { |path| File.read(path) }
    assert_operator receipt_data.size, :>, 40

    statuses = []
    ENVIRONMENTS.each do |environment|
      pinned = APRV::VerifyReceiptEndpoint.new(trusted_roots: roots, environment: environment,
                                               clock: CountingClock.new)
      receipt_data.each do |data|
        json = JSON.generate({ "receipt-data" => data })
        body = pinned.verify_receipt_json(json)
        bare = pinned.verify_receipt_data(data)
        # Every corpus body fits Apple's request cap, the byte-floor
        # receipt's 1.38 MB of base64 included, so the JSON path and the
        # bare path must give the same answer for all of them.
        assert_operator json.bytesize, :<=, APRV::VerifyReceiptEndpoint::MAX_REQUEST_BYTES, data[0, 40]
        assert_equal body, bare.to_json, data[0, 40]
        statuses << bare.status
        refute_equal APRV::Reason::INTERNAL_ERROR, bare.failure_reason, data[0, 40]
      end
    end
    # The corpus reaches every status except the internal error.
    assert_equal [0, 21_002, 21_003, 21_007, 21_008], statuses.uniq.sort
  end

  def test_each_failure_names_its_reason
    sandbox = endpoint(SANDBOX)
    {
      "body not JSON" => sandbox.verify_receipt_result("not json"),
      "body a JSON array" => sandbox.verify_receipt_result('[{"receipt-data":"AQIDBA=="}]'),
      "body JSON null" => sandbox.verify_receipt_result("null"),
      "body nested too deep" => sandbox.verify_receipt_result("[" * 100_000),
      "nil body" => sandbox.verify_receipt_result(nil),
      "an Array body" => sandbox.verify_receipt_result([]),
      "receipt-data missing" => sandbox.verify_receipt_result({}),
      "receipt-data empty" => sandbox.verify_receipt_result({ "receipt-data" => "" }),
      "receipt-data a number" => sandbox.verify_receipt_result('{"receipt-data":5}'),
      "receipt-data a list" => sandbox.verify_receipt_result({ "receipt-data" => ["AQIDBA=="] }),
      "bare receipt nil" => sandbox.verify_receipt_data(nil),
      "bare receipt empty" => sandbox.verify_receipt_data(""),
      "bare receipt a number" => sandbox.verify_receipt_data(42)
    }.each do |label, result|
      assert_equal APRV::Reason::MALFORMED_REQUEST, result.failure_reason, label
      assert_equal 21_002, result.status, label
      assert_invariant(result, label)
    end
    assert_equal '{"status":21002}', sandbox.verify_receipt_json("[" * 100_000)
    assert_equal '{"status":21002}', sandbox.verify_receipt_json({ "receipt-data" => b64("receipt.der") })

    {
      "not base64" => sandbox.verify_receipt_result({ "receipt-data" => "not base64!" }),
      "whitespace only" => sandbox.verify_receipt_data("  \n"),
      "not a receipt" => sandbox.verify_receipt_result({ "receipt-data" => "AQIDBA==" })
    }.each do |label, result|
      assert_equal APRV::Reason::INVALID_RECEIPT_FORMAT, result.failure_reason, label
      assert_equal 21_002, result.status, label
      assert_invariant(result, label)
    end

    foreign = sandbox.verify_receipt_data(b64("receipt-foreign.der"))
    assert_equal APRV::Reason::INVALID_CHAIN, foreign.failure_reason
    assert_equal 21_003, foreign.status
    tampered = endpoint(SANDBOX, root: "gaps-receipt-root.der")
               .verify_receipt_data(b64("receipt-tampered-payload.der"))
    assert_equal APRV::Reason::INVALID_SIGNATURE, tampered.failure_reason
    assert_equal 21_003, tampered.status
  end

  # The endpoint promises never to raise on a request, so a bug inside it
  # must come back as 21009 with the error kept for logging.
  def test_an_unexpected_error_is_an_internal_error_not_a_raise
    boom = RuntimeError.new("broken request hash")
    ENVIRONMENTS.each do |environment|
      result = endpoint(environment).verify_receipt_result(broken_request(boom))
      assert_equal APRV::Reason::INTERNAL_ERROR, result.failure_reason
      assert_same boom, result.failure_cause
      assert_nil result.receipt
      [result.to_json, *ENVIRONMENTS.map { |target| result.to_json(target) }].each do |render|
        assert_equal '{"status":21009}', render
      end
    end

    # A clock that fails is contained the same way, for every entry point.
    clock_error = IOError.new("clock unavailable")
    broken_clock = endpoint(SANDBOX, clock: -> { raise clock_error })
    not_a_time = endpoint(SANDBOX, clock: -> { "2026-01-01" })
    [broken_clock.verify_receipt_data(b64("receipt.der")),
     broken_clock.verify_receipt_result({}),
     not_a_time.verify_receipt_data(b64("receipt.der"))].each do |result|
      assert_equal APRV::Reason::INTERNAL_ERROR, result.failure_reason
      assert_invariant(result, result.failure_cause.inspect)
    end
    assert_same clock_error, broken_clock.verify_receipt_data(b64("receipt.der")).failure_cause
    assert_equal '{"status":21009}', broken_clock.verify_receipt_json("{}")

    # Inside verification itself, including an error that is not a
    # StandardError.
    original = APRV::Receipt.method(:verify)
    [NoMethodError.new("parser bug"), SystemStackError.new("deep")].each do |error|
      APRV::Receipt.define_singleton_method(:verify) { |*| raise error }
      begin
        sandbox = endpoint(SANDBOX)
        result = sandbox.verify_receipt_data(b64("receipt.der"))
        assert_equal APRV::Reason::INTERNAL_ERROR, result.failure_reason
        assert_same error, result.failure_cause
        assert_equal '{"status":21009}',
                     sandbox.verify_receipt_json(JSON.generate({ "receipt-data" => b64("receipt.der") }))
      ensure
        APRV::Receipt.define_singleton_method(:verify, original)
      end
    end
    assert_predicate endpoint(SANDBOX).verify_receipt_data(b64("receipt.der")), :verified?
  end

  def test_to_json_is_what_verify_receipt_json_answers
    sandbox = endpoint(SANDBOX)
    body = JSON.generate({ "receipt-data" => b64("receipt.der") })
    assert_equal sandbox.verify_receipt_json(body), sandbox.verify_receipt_result(body).to_json
    assert_equal sandbox.verify_receipt_json(body), sandbox.verify_receipt_result(body).to_json(SANDBOX)
    # The Hash is a copy: a caller editing it cannot change a later render.
    result = sandbox.verify_receipt_result(body)
    result.to_response["status"] = 21_003
    result.to_response["receipt"]["bundle_id"] = "com.example.other"
    assert_equal 0, result.to_response["status"]
    assert_equal "com.example.app", result.to_response["receipt"]["bundle_id"]
    assert_equal JSON.parse(result.to_json), result.to_response
  end

  # Defining to_json joins the json library's protocol: a result nested in
  # another value, or handed to Rails' `render json:`, is called with a
  # JSON::State or an options Hash, not an environment. Both must embed the
  # endpoint's own response rather than raise.
  def test_a_result_serializes_inside_other_json
    result = endpoint(PRODUCTION).verify_receipt_data(b64("receipt.der"))
    assert_equal '[{"status":21007}]', JSON.generate([result])
    pretty = JSON.pretty_generate({ "result" => result })
    assert_equal({ "result" => { "status" => 21_007 } }, JSON.parse(pretty))
    assert_equal '{"status":21007}', result.to_json({ prefixes: ["receipts"], template: "create" })
  end

  def test_only_the_endpoint_creates_a_result_and_it_cannot_be_changed
    # A caller must not be able to fabricate or edit a status 0.
    assert_raises(NoMethodError) do
      APRV::VerifyReceiptResult.new(PRODUCTION, nil, nil, nil, Time.now)
    end
    result = endpoint(PRODUCTION).verify_receipt_data(b64("receipt.der"))
    assert_predicate result, :frozen?
    assert_raises(FrozenError) { result.instance_variable_set(:@environment, SANDBOX) }
    assert_equal 21_007, result.status
  end

  def test_the_hash_in_hash_out_method_is_gone
    # Breaking change: verify_receipt(body) is now
    # verify_receipt_result(body).to_response.
    refute_respond_to endpoint(SANDBOX), :verify_receipt
  end
end
