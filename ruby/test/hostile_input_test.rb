# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"
require "tempfile"

# Hostile and malformed input. The load-bearing claim is not just "it is
# rejected" but "it is rejected as a VerificationError, quickly, and without
# `OpenSSL::ASN1.decode` ever having seen the bytes".
class HostileInputTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
    @verifier = APRV::ReceiptVerifier.new(trusted_roots: [@pki.root], bundle_id: "com.example.app")
  end

  def assert_format_error(bytes, message = nil)
    # Only pass the message when there is one. assert_raises treats a
    # trailing String as the failure message and everything else as an
    # exception class, so a nil here becomes `rescue VerificationError, nil`
    # and minitest raises TypeError instead of running the assertion.
    expected = message ? [APRV::VerificationError, message] : [APRV::VerificationError]
    error = assert_raises(*expected) { @verifier.verify_der(bytes) }
    assert_equal :INVALID_RECEIPT_FORMAT, error.reason, error.message
    error
  end

  # CPU time, not wall time: on a shared runner wall time also measures the
  # scheduler, and the claim here is about work done, not seconds elapsed.
  def elapsed
    started = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    yield
    (Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - started) * 1000
  end

  # OpenSSL::ASN1.decode recurses in C and raises SystemStackError — which is
  # not a StandardError and walks straight through `rescue => e`. The bounded
  # scanner is what keeps those bytes away from it. This asserts both halves:
  # the scanner rejects, and OpenSSL would not have.
  def test_indefinite_length_nesting_bomb
    bomb = "\x30\x80".b * 500_000
    milliseconds = elapsed { assert_format_error(bomb) }
    assert_operator milliseconds, :<, 250, "bomb took #{milliseconds.round(2)}ms"

    raised = begin
      OpenSSL::ASN1.decode(bomb)
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      e.class
    end
    assert_equal SystemStackError, raised,
                 "the premise of the bounded scanner no longer holds on this Ruby"
  end

  def test_definite_length_nesting_bomb
    bomb = +"\x04\x00".b
    100_000.times { bomb = "\x30\x84".b + [bomb.bytesize].pack("N") + bomb }
    milliseconds = elapsed { assert_format_error(bomb) }
    assert_operator milliseconds, :<, 250, "bomb took #{milliseconds.round(2)}ms"
  end

  # The scanner has to reject BEFORE OpenSSL is reached, not merely alongside
  # it: that is what makes SystemStackError unreachable rather than merely
  # rescued.
  def test_the_scanner_rejects_before_openssl_is_reached
    bomb = "\x30\x80".b * 500_000
    error = assert_raises(APRV::Asn1::Error) { APRV::Asn1.scan!(bomb) }
    assert_match(/too deep/, error.message)
  end

  def test_depth_thirty_two_is_accepted_and_thirty_three_is_not
    build = lambda do |containers|
      bytes = +"\x04\x00".b
      containers.times { bytes = "\x30".b + [bytes.bytesize].pack("C") + bytes }
      bytes
    end
    assert_equal 33, APRV::Asn1.scan!(build.call(32))
    error = assert_raises(APRV::Asn1::Error) { APRV::Asn1.scan!(build.call(33)) }
    assert_match(/too deep/, error.message)
  end

  def test_a_length_claiming_two_gigabytes_on_a_forty_byte_input
    assert_format_error("\x30\x84\x7f\xff\xff\xff".b + ("\x00" * 34))
  end

  def test_an_unterminated_indefinite_length_container
    assert_format_error("\x30\x80\x04\x01A".b)
  end

  def test_an_end_of_contents_with_no_open_container
    assert_format_error("#{"\x30\x03\x04\x01A".b}\x00\x00")
  end

  def test_multi_byte_tags_are_refused_rather_than_interpreted
    assert_raises(APRV::Asn1::Error) { APRV::Asn1.scan!("\x3f\x81\x01\x00".b) }
  end

  def test_length_fields_wider_than_four_octets_are_refused
    assert_raises(APRV::Asn1::Error) { APRV::Asn1.scan!("\x30\x85\x00\x00\x00\x00\x01\x00".b) }
  end

  def test_truncation_at_every_offset_of_a_genuine_receipt_is_contained
    der = TestSupport.fixture_bytes("public-receipt-sandbox-g5")
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "dev.bonzer.weeka.app")
    (0...der.bytesize).step(97) do |cut|
      verifier.verify_der(der.byteslice(0, cut))
      flunk "a receipt truncated at #{cut} verified"
    rescue APRV::VerificationError => e
      assert_includes APRV::Reason::ALL, e.reason
    end
  end

  def test_trailing_bytes_after_a_genuine_receipt
    der = TestSupport.fixture_bytes("public-receipt-sandbox-g5")
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "dev.bonzer.weeka.app")
    ["\x00", "\x00\x00", "junk", "\x30\x00"].each do |tail|
      error = assert_raises(APRV::VerificationError) { verifier.verify_der(der + tail) }
      assert_equal :INVALID_RECEIPT_FORMAT, error.reason
    end
  end

  def test_a_payload_with_invalid_utf8_in_the_bundle_id
    payload = TestPki.receipt_payload([[2, "\x0c\x03\xff\xfe\xfd".b]])
    assert_format_error(TestPki.sign_receipt(@pki, payload))
  end

  def test_a_message_digest_attribute_that_does_not_match_the_content
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    content = APRV::Cms.parse(der).content
    forged = der.b.sub(content, content.dup.tap { |c| c.setbyte(0, c.getbyte(0) ^ 0xff) })
    refute_equal der, forged
    error = assert_raises(APRV::VerificationError) { @verifier.verify_der(forged) }
    assert_includes %i[INVALID_SIGNATURE INVALID_RECEIPT_FORMAT], error.reason
  end

  # Cross-port rule S1, mechanised. `set_default_paths` is the classic Ruby
  # mistake: copied from a TLS example, it silently turns pinned trust into
  # trust-anything-a-public-CA-signed.
  def test_no_source_file_can_reach_the_operating_systems_trust_store
    forbidden = %w[set_default_paths add_path add_file DEFAULT_CERT_FILE DEFAULT_CERT_DIR]
    assert_no_code_mentions(forbidden)
  end

  def test_no_source_file_performs_network_io
    forbidden = %w[Net::HTTP net/http open-uri Socket URI.open OCSP CRL X509::Store.new]
    assert_no_code_mentions(forbidden, except: ["receipt.rb"])
  end

  # The strongest form of the pinning claim available offline: make a rogue CA
  # genuinely trusted by the platform's default trust store for the duration of
  # the test, prove the platform accepts its chain, and show the library still
  # refuses it.
  def test_a_chain_the_platform_trust_store_accepts_is_still_rejected
    rogue = TestPki.receipt_pki(leaf_oids: [TestPki::LEAF_OID], not_before: Time.utc(2020, 1, 1))
    der = TestPki.sign_receipt(rogue, TestPki.default_payload)

    Tempfile.create(["rogue-ca", ".pem"]) do |file|
      file.write(rogue.root.to_pem)
      file.flush
      with_env("SSL_CERT_FILE" => file.path) do
        platform = OpenSSL::X509::Store.new
        platform.set_default_paths
        context = OpenSSL::X509::StoreContext.new(platform, rogue.leaf,
                                                  [rogue.intermediate, rogue.root])
        context.time = Time.utc(2024, 8, 6)
        assert context.verify,
               "premise failed: the platform default store did not accept the rogue chain"

        error = assert_raises(APRV::VerificationError) do
          APRV.verify_receipt_core(der, trusted_roots: APRV.apple_receipt_roots)
        end
        assert_equal :INVALID_CHAIN, error.reason
      end
    end
  end

  def test_the_same_pinning_holds_on_the_jws_path
    rogue = TestPki.jws_pki
    jws = TestPki.sign_jws(rogue, TestPki.default_claims)
    subject = APRV::JwsVerifier.new(
      trusted_roots: APRV.apple_jws_roots, bundle_id: "com.example.app",
      accepted_environments: [APRV::Environment::SANDBOX]
    )
    error = assert_raises(APRV::VerificationError) { subject.verify_transaction(jws) }
    assert_equal :INVALID_CHAIN, error.reason
  end

  def test_a_receipt_whose_payload_is_a_huge_flat_set_is_bounded
    attributes = Array.new(5000) { |i| [9000 + i, TestPki.utf8("x")] }
    payload = TestPki.receipt_payload(attributes)
    receipt = APRV.verify_receipt_core(TestPki.sign_receipt(@pki, payload),
                                       trusted_roots: [@pki.root])
    assert_equal 5000, receipt.unknown_attributes.size
  end

  # The constructed-OCTET-STRING branch for attribute values is the one place
  # `each_attribute` hands bytes to the general tree parser instead of walking
  # them by offset, so it inherits that parser's budgets rather than escaping
  # them: `octet_value` recurses over the chunks, and only MAX_DEPTH keeps that
  # finite.
  def test_a_ber_chunked_attribute_value_is_bounded
    tlv = ->(tag, body) { [tag].pack("C") + der_length(body.bytesize) + body }

    deep = tlv.call(0x04, "")
    40.times { deep = tlv.call(0x24, deep) }
    attribute = tlv.call(0x30, TestPki.integer(2) + TestPki.integer(1) + deep)
    payload = tlv.call(0x31, attribute)

    milliseconds = elapsed { assert_format_error(TestPki.sign_receipt(@pki, payload)) }
    assert_operator milliseconds, :<, 250, "40-deep chunk nest took #{milliseconds.round(2)}ms"

    # 60,000 one-byte chunks that concatenate to one valid UTF8String: the
    # legitimate shape at scale, which must stay linear rather than rejected.
    text = "x" * 60_000
    inner = TestPki.utf8(text)
    chunks = inner.each_byte.map { |b| tlv.call(0x04, b.chr) }.join
    wide = tlv.call(0x30, TestPki.integer(3) + TestPki.integer(1) + tlv.call(0x24, chunks))
    bundle = tlv.call(0x30, TestPki.integer(2) + TestPki.integer(1) +
                                tlv.call(0x04, TestPki.utf8("com.example.app")))

    receipt = nil
    milliseconds = elapsed do
      receipt = @verifier.verify_der(TestPki.sign_receipt(@pki, tlv.call(0x31, bundle + wide)))
    end
    assert_equal text, receipt.app_version
    assert_operator milliseconds, :<, 250, "60k chunks took #{milliseconds.round(2)}ms"
  end

  # Definite-length DER length octets.
  def der_length(size)
    return [size].pack("C") if size < 0x80

    octets = []
    remaining = size
    while remaining.positive?
      octets.unshift(remaining & 0xff)
      remaining >>= 8
    end
    [0x80 | octets.size].pack("C") + octets.pack("C*")
  end

  # What the declared budgets actually cost when a caller sits on them.
  #
  # Every structural check runs before any cryptographic one — the payload is
  # parsed to learn the creation date the chain is judged at (PLAN.md §2.2
  # step 2), so an unauthenticated caller can spend this per request with a
  # blob that carries no signature. That is the same ordering as every other
  # port; what is pinned here is that the ceiling stays LINEAR in the input.
  # For scale: node's `der.parse` takes 252 ms on this same blob and declares
  # no node budget at all, so nothing there stops a larger one.
  def test_the_node_budget_ceiling_costs_a_bounded_amount
    flood = "\x30\x84".b + [199_000 * 2].pack("N") + ("\x05\x00".b * 199_000)
    milliseconds = elapsed { assert_format_error(flood) }
    assert_operator milliseconds, :<, 1500, "node-budget ceiling took #{milliseconds.round(2)}ms"

    half = "\x30\x84".b + [99_500 * 2].pack("N") + ("\x05\x00".b * 99_500)
    halved = elapsed { assert_format_error(half) }
    assert_operator halved, :<, milliseconds * 0.9,
                    "halving the input did not halve the work " \
                    "(#{halved.round(2)}ms of #{milliseconds.round(2)}ms)"
  end

  # The node/attribute budgets count structural elements, so nothing in them
  # bounds the work spent inside ONE element. A date attribute is the element
  # where that mattered: an unbounded run of fractional-second digits used to
  # be turned into an exact Rational, which is superlinear in the digit count,
  # and `ReceiptPayload.parse` runs before the certificate bound, the chain
  # walk and the signature check — so the cost was reachable with a blob that
  # never carried a signature at all.
  #
  # The ceiling is loose on purpose. A linear scan of a million digits costs
  # well under a millisecond and the rest of the call is fixed overhead (the
  # macOS CI runner measured 27 ms for a million digits and 27 ms for half a
  # million), so a ratio against a half-size input cannot hold there; the
  # exact-Rational conversion this guards against costs seconds at this size,
  # which one second catches with a wide margin on any runner.
  def test_a_date_with_a_million_fractional_digits_is_not_superlinear
    milliseconds = elapsed { assert_core_rejects_fraction_of("1" * 1_000_000) }
    assert_operator milliseconds, :<, 1000, "1e6-digit fraction took #{milliseconds.round(2)}ms"
  end

  def assert_core_rejects_fraction_of(digits)
    long = TestPki.default_payload(creation_date: "2024-01-01T00:00:00.#{digits}Z")
    der = TestPki.sign_receipt(@pki, long).dup
    der.setbyte(der.bytesize - 1, der.getbyte(der.bytesize - 1) ^ 0xff)
    assert_raises(APRV::VerificationError) do
      APRV.verify_receipt_core(der, trusted_roots: [@pki.root])
    end
  end

  # The same input through the endpoint the README advertises for Rails, which
  # is the surface an unauthenticated caller actually reaches.
  def test_the_endpoint_is_not_superlinear_on_a_long_fractional_second
    milliseconds = elapsed { assert_endpoint_accepts_fraction_of("9" * 2_000_000) }
    assert_operator milliseconds, :<, 2000, "2e6-digit fraction took #{milliseconds.round(2)}ms"
  end

  def assert_endpoint_accepts_fraction_of(digits)
    long = TestPki.default_payload(creation_date: "2024-01-01T00:00:00.#{digits}Z")
    der = TestPki.sign_receipt(@pki, long)
    endpoint = APRV::VerifyReceiptEndpoint.new(trusted_roots: [@pki.root],
                                               environment: APRV::Environment::SANDBOX)
    response = endpoint.verify_receipt({ "receipt-data" => [der].pack("m0") })
    assert_equal 0, response["status"]
  end

  # Cross-port rule S8 and decision C8: containment is categorical, and it
  # covers SystemStackError, which is not a StandardError and would otherwise
  # walk through a caller's `rescue` and kill their request. The bounded
  # scanner makes it unreachable; this is the net under it, and "loud" is a red
  # test rather than a crashed process.
  def test_the_containment_boundary_converts_every_foreign_error
    [RuntimeError, TypeError, NoMethodError, ArgumentError, IndexError].each do |klass|
      error = assert_raises(APRV::VerificationError) do
        APRV::Receipt.contained { raise klass, "boom" }
      end
      assert_equal :INVALID_RECEIPT_FORMAT, error.reason
      assert_includes error.message, klass.name
    end
  end

  def test_the_containment_boundary_covers_system_stack_error
    error = assert_raises(APRV::VerificationError) do
      APRV::Receipt.contained { raise SystemStackError, "stack level too deep" }
    end
    assert_equal :INVALID_RECEIPT_FORMAT, error.reason
    refute_kind_of SystemStackError, error
  end

  def test_a_verification_error_passes_through_the_boundary_unchanged
    original = APRV::VerificationError.new(APRV::Reason::INVALID_CHAIN, "detail")
    error = assert_raises(APRV::VerificationError) { APRV::Receipt.contained { raise original } }
    assert_same original, error
  end

  def test_the_jws_boundary_contains_foreign_errors_too
    pki = TestPki.jws_pki
    verifier = APRV::JwsVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app",
                                     accepted_environments: [APRV::Environment::SANDBOX])
    deep = "\x30\x80".b * 200_000
    error = assert_raises(APRV::VerificationError) do
      verifier.verify_transaction([deep].pack("m0").delete("=").tr("+/", "-_"))
    end
    assert_includes APRV::Reason::ALL, error.reason
  end

  private

  # Comments are allowed to name what the code must not do — that is how the
  # rule stays explained. The grep is over code.
  def assert_no_code_mentions(forbidden, except: [])
    Dir.glob(File.expand_path("../lib/**/*.rb", __dir__)).each do |path|
      next if except.include?(File.basename(path))

      code = File.read(path, encoding: Encoding::UTF_8).lines.grep_v(/\A\s*#/).join
      forbidden.each do |symbol|
        refute_includes code, symbol, "#{path} names #{symbol} outside a comment"
      end
    end
  end

  def with_env(values)
    previous = values.keys.to_h { |key| [key, ENV.fetch(key, nil)] }
    values.each { |key, value| ENV[key] = value }
    yield
  ensure
    previous.each { |key, value| ENV[key] = value }
  end
end
