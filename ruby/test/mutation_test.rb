# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# A seeded, deterministic mutation sweep over the genuine corpus.
#
# The invariant it exists for is not "mutations are rejected" — most are, and
# some land in bytes nothing depends on. It is that **nothing else ever
# escapes**: no ArgumentError from OpenSSL, no NoMethodError on a nil, no
# SystemStackError from a nesting bomb the mutation happened to create. That is
# the whole of cross-port rule S8, measured rather than asserted in a comment.
#
# The seed is fixed and printed on failure, so any finding is reproducible.
class MutationTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  SEED = 20_260_904
  RECEIPT_MUTATIONS = Integer(ENV.fetch("APRV_MUTATIONS", "1000"))
  JWS_MUTATIONS = Integer(ENV.fetch("APRV_JWS_MUTATIONS", "500"))

  def mutate(random, bytes)
    copy = bytes.dup
    if random.rand < 0.15
      cut = random.rand(1..copy.bytesize)
      return copy.byteslice(0, cut)
    end
    random.rand(1..4).times do
      index = random.rand(copy.bytesize)
      copy.setbyte(index, copy.getbyte(index) ^ (1 << random.rand(8)))
    end
    copy
  end

  # Runs `count` mutations and returns the reason histogram. Any escape is a
  # failure naming the seed, the iteration and the concrete class.
  # Value objects reduced to primitives, so two results can be compared.
  def deep(value)
    case value
    when Array then value.map { |element| deep(element) }
    when Hash then value.to_h { |key, element| [key, deep(element)] }
    else value.respond_to?(:to_h) && !value.is_a?(Time) ? deep(value.to_h) : value
    end
  end

  def sweep(label, bytes, count, &verify)
    random = Random.new(SEED)
    baseline = deep(verify.call(bytes.dup))
    histogram = Hash.new(0)
    slowest = 0.0
    count.times do |iteration|
      mutated = mutate(random, bytes)
      started = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
      begin
        # A mutation that still verifies landed in a byte nothing signed
        # depends on — an embedded certificate this path never walks, say. It
        # must then say exactly what the unmutated input says.
        assert_equal baseline, deep(verify.call(mutated)),
                     "#{label}: iteration #{iteration} verified but decoded differently"
        histogram[:accepted] += 1
      rescue APRV::VerificationError => e
        assert_includes APRV::Reason::ALL, e.reason,
                        "#{label}: iteration #{iteration} raised an unknown reason #{e.reason}"
        histogram[e.reason] += 1
      rescue Exception => e # rubocop:disable Lint/RescueException
        flunk "#{label}: iteration #{iteration} (seed #{SEED}) escaped as " \
              "#{e.class}: #{e.message}\n#{e.backtrace&.first(5)&.join("\n")}"
      end
      elapsed = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - started
      slowest = elapsed if elapsed > slowest
    end
    # CPU time, not wall time. The point of the bound is to catch a mutation
    # that makes verification blow up algorithmically; wall time on a shared
    # runner also measures the scheduler. Measured here: a 1.46 s wall-clock
    # outlier on this container had 10 ms of CPU behind it, while the genuinely
    # slowest mutation of the 79 KB / 187-purchase receipt costs about 35 ms.
    assert_operator slowest, :<, 1.0,
                    "#{label}: slowest mutation burned #{(slowest * 1000).round(2)}ms of CPU"
    histogram
  end

  def test_mutations_of_the_genuine_legacy_receipt_never_escape
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "com.nutcall.alert")
    bytes = TestSupport.fixture_bytes("public-receipt-sandbox-legacy")
    histogram = sweep("legacy receipt", bytes, RECEIPT_MUTATIONS) { |m| verifier.verify_der(m) }
    assert_equal histogram.values.sum, RECEIPT_MUTATIONS
    assert_operator histogram[:INVALID_RECEIPT_FORMAT] + histogram[:INVALID_SIGNATURE] +
                    histogram[:INVALID_CHAIN], :>, 0
  end

  def test_mutations_of_the_genuine_sandbox_receipt_never_escape
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "dev.bonzer.weeka.app")
    bytes = TestSupport.fixture_bytes("public-receipt-sandbox-g5")
    histogram = sweep("g5 receipt", bytes, RECEIPT_MUTATIONS) { |m| verifier.verify_der(m) }
    assert_equal RECEIPT_MUTATIONS, histogram.values.sum
  end

  def test_mutations_of_a_generated_receipt_never_escape
    pki = TestPki.receipt_pki
    verifier = APRV::ReceiptVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app")
    bytes = TestPki.sign_receipt(pki, TestPki.default_payload)
    histogram = sweep("generated receipt", bytes, RECEIPT_MUTATIONS) { |m| verifier.verify_der(m) }
    assert_equal RECEIPT_MUTATIONS, histogram.values.sum
  end

  def test_mutations_of_the_shared_transaction_jws_never_escape
    verifier = APRV::JwsVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("jws-root")],
      bundle_id: "com.example.app", accepted_environments: [APRV::Environment::SANDBOX]
    )
    bytes = TestSupport.fixture_bytes("transaction")
    histogram = sweep("transaction jws", bytes, JWS_MUTATIONS) do |m|
      verifier.verify_transaction(m.force_encoding(Encoding::UTF_8))
    end
    assert_equal JWS_MUTATIONS, histogram.values.sum
  end

  def test_segment_swaps_and_reorderings_of_a_jws_never_escape
    verifier = APRV::JwsVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("jws-root")],
      bundle_id: "com.example.app", accepted_environments: [APRV::Environment::SANDBOX]
    )
    header, payload, signature = TestSupport.fixture_bytes("transaction")
                                            .force_encoding(Encoding::UTF_8).strip.split(".")
    [header, payload, signature].permutation.each do |a, b, c|
      combined = "#{a}.#{b}.#{c}"
      next if combined == "#{header}.#{payload}.#{signature}"

      error = assert_raises(APRV::VerificationError) { verifier.verify_transaction(combined) }
      assert_includes APRV::Reason::ALL, error.reason
    end
  end

  # A mutation that still verifies landed in a byte nothing signed depends on;
  # the payload it returns must then be identical to the unmutated one.
  def test_a_mutation_that_still_verifies_returns_an_identical_payload
    pki = TestPki.receipt_pki
    verifier = APRV::ReceiptVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app")
    bytes = TestPki.sign_receipt(pki, TestPki.default_payload)
    baseline = verifier.verify_der(bytes).to_h
    random = Random.new(SEED)
    accepted = 0
    400.times do
      mutated = mutate(random, bytes)
      begin
        assert_equal baseline, verifier.verify_der(mutated).to_h
        accepted += 1
      rescue APRV::VerificationError
        next
      end
    end
    # Not an assertion about how many: only that whichever survive say the
    # same thing.
    assert_operator accepted, :>=, 0
  end

  def test_random_bytes_never_escape
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "com.example.app")
    random = Random.new(SEED)
    2000.times do |iteration|
      bytes = random.bytes(random.rand(0..512))
      begin
        verifier.verify_der(bytes)
      rescue APRV::VerificationError => e
        assert_includes APRV::Reason::ALL, e.reason
      rescue Exception => e # rubocop:disable Lint/RescueException
        flunk "random bytes iteration #{iteration} escaped as #{e.class}: #{e.message}"
      end
    end
  end

  def test_random_strings_never_escape_the_jws_path
    verifier = APRV::JwsVerifier.new(
      trusted_roots: APRV.apple_jws_roots, bundle_id: "com.example.app",
      accepted_environments: [APRV::Environment::SANDBOX]
    )
    random = Random.new(SEED)
    2000.times do |iteration|
      text = random.bytes(random.rand(0..128)).unpack1("H*")
      candidate = [text[0, 20], text[20, 60], text[60..]].compact.join(".")
      begin
        verifier.verify_raw(candidate)
      rescue APRV::VerificationError => e
        assert_includes APRV::Reason::ALL, e.reason
      rescue Exception => e # rubocop:disable Lint/RescueException
        flunk "random jws iteration #{iteration} escaped as #{e.class}: #{e.message}"
      end
    end
  end

  def test_the_endpoint_never_raises_across_the_same_sweep
    endpoint = APRV::VerifyReceiptEndpoint.new(trusted_roots: APRV.apple_receipt_roots,
                                               environment: APRV::Environment::SANDBOX)
    bytes = TestSupport.fixture_bytes("public-receipt-sandbox-g5")
    random = Random.new(SEED)
    500.times do |iteration|
      mutated = mutate(random, bytes)
      response = endpoint.verify_receipt({ "receipt-data" => [mutated].pack("m0") })
      assert_includes [0, 21_002, 21_003, 21_007, 21_008, 21_009], response["status"],
                      "iteration #{iteration}"
    end
  end
end
