# frozen_string_literal: true

require_relative "helper"

# Runs fixtures/cases.json — the normative cross-language conformance vectors —
# against this implementation.
#
# The adapter below knows nothing about any individual case. It loads the file,
# resolves fixture ids to bytes and checks their recorded digest, builds a
# verifier from the generic config, dispatches on "operation", normalizes the
# result and reads the reason off a failure. There is no skip list, no case id
# anywhere, and no per-case fixup: a vector that disagrees with the library is
# a bug report against one of the two, never something to special-case here.
class ConformanceTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  CASES = TestSupport.cases

  # verifyRaw enforces no claim, so its cases may omit bundleId and
  # acceptedEnvironments — but JwsVerifier still demands both. These
  # placeholders match nothing any fixture carries, so a claim check that
  # leaked into verify_raw surfaces as a failure rather than as a silent pass.
  # An empty string, a wildcard or "all four environments" would hide it.
  UNMATCHABLE_BUNDLE_ID = "conformance.unset.bundle.id"
  UNMATCHABLE_ENVIRONMENTS = [ApplePurchaseReceiptVerifier::Environment::LOCAL_TESTING].freeze

  BUILTIN_ROOTS = {
    "apple-jws-roots" => -> { APRV.apple_jws_roots },
    "apple-receipt-roots" => -> { APRV.apple_receipt_roots }
  }.freeze

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

  # A step is either a name (`bundleId`, `length`) or a bracket (`[9999]`,
  # `[0]`, `[productId=com.example.app.vip]`). Bracket contents hold dots, so
  # a plain split on "." is wrong.
  PATH_STEP = /\.?([^.\[\]]+)|\[([^\]]+)\]/

  private

  def trusted_roots(spec)
    if spec["source"] == "builtin"
      builder = BUILTIN_ROOTS[spec["name"]]
      raise "harness error: unknown builtin root set #{spec["name"].inspect}" if builder.nil?

      return builder.call
    end
    spec["fixtures"].map { |id| TestSupport.fixture_certificate(id) }
  end

  # The case's pinned instant, handed to the library's clock option. No global
  # time is faked: a case carrying a clock that runs against the system clock
  # is not running the case.
  def case_clock(kase)
    pinned = kase["clock"]
    return nil if pinned.nil?

    instant = Time.iso8601(pinned["now"]).utc
    -> { instant }
  end

  def jws_verifier(config, clock)
    APRV::JwsVerifier.new(
      trusted_roots: trusted_roots(config["trustedRoots"]),
      bundle_id: config["bundleId"] || UNMATCHABLE_BUNDLE_ID,
      accepted_environments: config["acceptedEnvironments"] || UNMATCHABLE_ENVIRONMENTS,
      app_apple_id: config["appAppleId"],
      # cases.json states seconds and so does this port: the conversion that
      # would be the one place a unit bug is invisible does not exist here.
      max_signed_age_seconds: config["maxSignedAgeSeconds"],
      clock: clock
    )
  end

  def require_no_clock(clock, operation)
    return if clock.nil?

    raise "harness error: #{operation} has no clock seam, but the case pins one"
  end

  def dispatch(kase, input, clock)
    config = kase["config"]
    case kase["operation"]
    when "verifyTransaction"
      jws_verifier(config, clock).verify_transaction(input.force_encoding(Encoding::UTF_8))
    when "verifyAppTransaction"
      jws_verifier(config, clock).verify_app_transaction(input.force_encoding(Encoding::UTF_8))
    when "verifyRaw"
      jws_verifier(config, clock).verify_raw(input.force_encoding(Encoding::UTF_8))
    when "verifyReceipt"
      require_no_clock(clock, "verifyReceipt")
      verifier = APRV::ReceiptVerifier.new(
        trusted_roots: trusted_roots(config["trustedRoots"]), bundle_id: config["bundleId"]
      )
      guid = config["deviceGuidHex"] && [config["deviceGuidHex"]].pack("H*")
      verifier.verify_der(input, device_guid: guid)
    when "verifyReceiptBase64"
      require_no_clock(clock, "verifyReceiptBase64")
      verifier = APRV::ReceiptVerifier.new(
        trusted_roots: trusted_roots(config["trustedRoots"]), bundle_id: config["bundleId"]
      )
      guid = config["deviceGuidHex"] && [config["deviceGuidHex"]].pack("H*")
      verifier.verify_base64(input, device_guid: guid)
    when "verifyReceiptEndpoint"
      fixture = kase["input"]["fixture"]
      # A text fixture is what a client would put in receipt-data as-is; a
      # raw or base64 fixture is decoded bytes this harness re-encodes, since
      # nothing recorded what a client would have sent for those.
      receipt_data =
        if CASES["fixtures"][fixture]["codec"] == "text"
          input
        else
          [input].pack("m0")
        end
      APRV::VerifyReceiptEndpoint.new(
        trusted_roots: trusted_roots(config["trustedRoots"]),
        environment: config["environment"], clock: clock
      ).verify_receipt({ "receipt-data" => receipt_data })
    else
      raise "harness error: no adapter for operation #{kase["operation"].inspect}"
    end
  end

  def run_case(kase)
    input = TestSupport.fixture_bytes(kase["input"]["fixture"]).dup
    expected = kase["expected"]
    begin
      result = dispatch(kase, input, case_clock(kase))
    rescue APRV::VerificationError => e
      # Only a VerificationError carries a canonical Reason. Anything else is a
      # defect in the library or in this harness and is reported as such — it
      # is never read as one of the expected reasons.
      assert_equal "error", expected["status"],
                   "expected success but raised #{e.reason}"
      assert_equal expected["reason"], e.reason.to_s, "reason"
      return
    rescue StandardError, SystemStackError => e
      raise "harness error: #{kase["operation"]} raised #{e.class} (#{e.message}), " \
            "which is not a VerificationError"
    end

    assert_equal "ok", expected["status"],
                 "expected #{expected["reason"]} but the call returned a value"
    actual = normalize(result)
    expected["fields"].each do |path, want|
      got = resolve_path(actual, path)
      if want.nil?
        assert_nil got, "#{path}: expected absent, got #{got.inspect}"
      else
        assert_equal want, got, path
      end
    end
  end

  # --- result normalization ------------------------------------------------

  # Renders a returned value into the language-neutral shape the field paths
  # are written against: Time as ISO-8601 UTC, binary Strings as lowercase hex
  # (mirrored under "<name>_hex", the spelling cases.json reaches through
  # `opaqueValueHex`), Hash keys stringified, value objects through #to_h.
  def normalize(value)
    case value
    when nil then nil
    when Time then iso_utc(value)
    when Array then value.map { |element| normalize(element) }
    when Hash then normalize_hash(value)
    when String then value.encoding == Encoding::BINARY ? value.unpack1("H*") : value
    when Integer, Float, TrueClass, FalseClass then value
    else
      raise "harness error: cannot normalize #{value.class}" unless value.respond_to?(:to_h)

      normalize_hash(value.to_h)
    end
  end

  def normalize_hash(hash)
    out = {}
    hash.each do |key, value|
      name = key.to_s
      out[name] = normalize(value)
      out["#{name}_hex"] = out[name] if value.is_a?(String) && value.encoding == Encoding::BINARY
    end
    out
  end

  def iso_utc(time)
    utc = time.utc? ? time : time.getutc
    utc.nsec.zero? ? utc.strftime("%Y-%m-%dT%H:%M:%SZ") : utc.iso8601(3)
  end

  # --- field paths ---------------------------------------------------------

  def path_steps(path)
    steps = []
    consumed = 0
    path.scan(PATH_STEP) do
      match = Regexp.last_match
      raise "harness error: unparseable field path #{path.inspect}" if match.begin(0) != consumed

      consumed += match[0].length
      steps << (match[1].nil? ? [:bracket, match[2]] : [:name, match[1]])
    end
    raise "harness error: unparseable field path #{path.inspect}" if consumed != path.length

    steps
  end

  def resolve_path(root, path)
    current = root
    path_steps(path).each do |kind, value|
      return nil if current.nil?

      current = kind == :name ? resolve_name(current, value, path) : resolve_bracket(current, value, path)
    end
    current
  end

  # Names arrive in the vectors' language-neutral camelCase. Apple's own claim
  # maps are keyed that way already; this port's value objects use Ruby's
  # snake_case. One generic fallback covers both — no per-case knowledge.
  def resolve_name(current, name, path)
    return current.length if name == "length" && current.is_a?(Array)
    raise "harness error: #{path}: .#{name} does not select from an object" unless current.is_a?(Hash)
    return current[name] if current.key?(name)

    snake = snake_case(name)
    current.key?(snake) ? current[snake] : nil
  end

  def snake_case(name)
    name.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
  end

  def resolve_bracket(current, value, path)
    separator = value.index("=")
    if separator&.positive?
      key = value[0...separator]
      wanted = value[(separator + 1)..]
      raise "harness error: #{path}: [#{value}] does not select from a list" unless current.is_a?(Array)

      matches = current.select do |element|
        element.is_a?(Hash) && (element[key] || element[snake_case(key)]) == wanted
      end
      unless matches.size == 1
        raise "harness error: #{path}: [#{value}] must select exactly one element, " \
              "selected #{matches.size}"
      end

      return matches.first
    end

    return current[value.to_i] if current.is_a?(Array)
    raise "harness error: #{path}: [#{value}] does not select from a map" unless current.is_a?(Hash)

    current[value]
  end

  CASES["cases"].each { |kase| define_case(kase) }
end

# The coverage self-check a defined-but-never-run case could still evade: every
# case in the file must actually have executed. Asserted against the parsed
# length, never a literal, so a silently dropped operation cannot hide.
#
# A deliberately filtered run (`-n`, `--name`) is not a coverage claim, so it is
# exempt — and only that spelling is exempt, not an empty result.
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
