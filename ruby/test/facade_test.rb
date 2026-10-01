# frozen_string_literal: true

require_relative "helper"
require_relative "fake_module"
require "tmpdir"
require "openssl"

# The facade's own behaviour, against a module that answers from a table
# (fake_module.rb), so none of it depends on which core version the shipped
# aprv.wasm holds: the six outcomes, trap recovery, the clock and `env`, the
# roots that reach `init`, and the checks on the module itself.
#
# The six outcomes of docs/rust-core/ARCHITECTURE.md, section 4:
#   verified, verification failure, caller misuse, ABI mismatch,
#   trap or internal failure, server process failure (not applicable here).
class FacadeTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  FAKE = APRV::Runtime.new(FakeModule.wat)

  def verifier(config = APRV::Config.defaults, runtime: FAKE)
    APRV::Verifier.send(:new, config, runtime: runtime)
  end

  def idle_instances(verifier)
    verifier.instance_variable_get(:@pool).idle_count
  end

  # --- outcome 1: verified ------------------------------------------------

  def test_a_verified_receipt_is_decoded_into_the_payload_types
    result = verifier.verify_receipt("v")
    assert_predicate result, :verified?
    assert_nil result.failure
    receipt = result.payload
    assert_instance_of APRV::ReceiptPayload, receipt
    assert_equal "com.example.app", receipt.bundle_id
    assert_equal "com.example.app".b, receipt.bundle_id_bytes
    assert_equal 1_234_567_890_123_456_789, receipt.app_item_id, "64-bit ids come back as Integers"
    assert_equal 0, receipt.download_id
    assert_equal 1_722_945_600_000, receipt.receipt_creation_date_ms
    assert_nil receipt.expiration_date_ms
    assert_equal "\x00\x01\x02".b, receipt.opaque_value
    assert_equal({ 13 => ["\x04\x05".b, "\x06".b] }, receipt.unknown_attributes, "receipt order is kept")
    purchase = receipt.in_app.fetch(0)
    assert_equal 9_000_000_000_000_000_001, purchase.web_order_line_item_id
    assert_same false, purchase.is_trial_period
    assert_same true, purchase.is_in_intro_offer_period
    assert_equal({ 1799 => ["\x01\x02\x03".b] }, purchase.unknown_attributes)
  end

  def test_to_json_writes_the_payload_the_module_answered_with
    payload = JSON.parse(FakeModule::ANSWERS.fetch(:receipt))["payload"]
    assert_equal payload, JSON.parse(verifier.verify_receipt("v").payload.to_json)
  end

  def test_a_verified_jws_is_the_signed_payload_exactly
    result = verifier.verify_signed_data("v")
    assert_predicate result, :verified?
    assert_equal '{"bundleId":"com.example.app","signedDate":1}', result.payload.json
  end

  # --- outcome 2: a verification failure is a value -------------------------

  def test_a_verification_failure_is_a_value_with_the_modules_reason
    result = verifier.verify_receipt("f")
    refute_predicate result, :verified?
    assert_nil result.payload
    assert_equal APRV::Reason::UNTRUSTED_CHAIN, result.failure.reason
    assert_equal "the chain does not reach a pinned root", result.failure.message
    assert_nil result.failure.cause
  end

  def test_a_verification_failure_is_not_a_fault_and_keeps_the_instance
    v = verifier
    v.verify_receipt("f")
    v.verify_signed_data("f")
    assert_equal 1, idle_instances(v)
  end

  # --- outcome 3: caller misuse ---------------------------------------------

  def test_an_empty_root_list_is_refused_at_create_and_not_taken_for_the_defaults
    assert_raises(ArgumentError) { APRV::Verifier.create(APRV::Config.new(roots: [])) }
    assert_raises(ArgumentError) { APRV::Verifier.create(APRV::Config.new(roots: APRV::Config.defaults.roots)) }
  end

  def test_a_root_the_module_refuses_is_an_argument_error_at_create
    # The fake refuses a root whose base64 starts with "X".
    refused = APRV::Config.new(roots: ["\x5f\xff\xff".b])
    error = assert_raises(ArgumentError) { verifier(refused) }
    assert_match(/refused config\.roots/, error.message)
    assert_match(/root 0 is not a certificate/, error.message)
  end

  def test_the_roots_reach_init_as_base64_der
    der = "not really a certificate".b
    certificate = Struct.new(:to_der).new(der)
    config = APRV::Config.new(roots: [der, certificate])
    assert_equal [der, der], config.roots
    assert_predicate verifier(config).verify_receipt("v"), :verified?
    assert_equal [], APRV::Config.defaults.roots
  end

  # Roots are DER in every package (docs/rust-core/DECISIONS.md R39). A PEM
  # String is refused at Config.new with a pointer to the README, not
  # unwrapped here and not passed on for the module to refuse at create.
  def test_a_pem_string_root_is_refused_with_a_pointer_to_the_readme
    der = File.binread(File.join(TestSupport.repo_root, "certs", "AppleRootCA-G3.cer"))
    pem = "-----BEGIN CERTIFICATE-----\n#{[der].pack("m")}-----END CERTIFICATE-----\n"
    [pem, "junk before it\n#{pem}"].each do |root|
      error = assert_raises(ArgumentError) { APRV::Config.new(roots: [der, root]) }
      assert_match(/DER Strings; convert a PEM certificate first \(see README\)/, error.message)
    end
    assert_raises(ArgumentError) { APRV::Config.builder.roots([pem]).build }
    # The README's conversion works: the certificate object's DER is the root.
    assert_equal [der], APRV::Config.new(roots: [OpenSSL::X509::Certificate.new(pem)]).roots
  end

  def test_config_refuses_what_is_neither_a_certificate_nor_a_string
    assert_raises(ArgumentError) { APRV::Config.new(roots: [nil]) }
    assert_raises(ArgumentError) { APRV::Config.new(roots: [1.5]) }
    assert_raises(ArgumentError) { APRV::Config.new(roots: ["-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"]) }
    assert_raises(ArgumentError) { APRV::Config.new(clock: 42) }
  end

  def test_the_builder_builds_the_same_config
    clock = -> { 1 }
    built = APRV::Config.builder.roots(["x".b]).clock(clock).build
    assert_equal ["x".b], built.roots
    assert_same clock, built.clock
    assert_equal APRV::Config.defaults.roots, APRV::Config.builder.build.roots
  end

  # --- outcome 4: ABI mismatch -----------------------------------------------

  def test_a_module_of_another_abi_version_fails_at_create_naming_both_versions
    other = APRV::Runtime.new(FakeModule.wat(abi: "2.0.0"))
    error = assert_raises(APRV::AbiMismatchError) { verifier(runtime: other) }
    assert_includes error.message, "aprv:verifier/verify@0.1.0"
    assert_includes error.message, "aprv:verifier/verify@2.0.0#init"
  end

  def test_a_module_that_imports_anything_but_random_get_is_refused
    import = '(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))'
    wat = FakeModule.wat(import: import)
    error = assert_raises(APRV::AbiMismatchError) { APRV::Runtime.new(wat) }
    assert_includes error.message, "wasi_snapshot_preview1#fd_write"
  end

  def test_a_module_that_is_not_a_module_is_an_abi_mismatch
    assert_raises(APRV::AbiMismatchError) { APRV::Runtime.new("this is not wasm".b) }
  end

  def test_the_module_is_checked_against_its_recorded_hash
    Dir.mktmpdir do |dir|
      wasm = File.join(dir, "aprv.wasm")
      File.binwrite(wasm, "\0asm\1\0\0\0".b)
      hash = File.join(dir, "aprv.wasm.sha256")
      File.write(hash, "#{Digest::SHA256.hexdigest("\0asm\1\0\0\0".b)}  aprv.wasm\n")
      assert_equal "\0asm\1\0\0\0".b, APRV::Runtime.read_module(wasm, hash)

      File.binwrite(wasm, "\0asm\1\0\0\1".b)
      assert_raises(APRV::ModuleIntegrityError) { APRV::Runtime.read_module(wasm, hash) }
      File.write(hash, "not a hash\n")
      assert_raises(APRV::ModuleIntegrityError) { APRV::Runtime.read_module(wasm, hash) }
    end
  end

  # The module is not tracked in git: it is copied into place (this harness
  # may point at another copy with APRV_WASM). It must be there, and it must
  # be the pinned one.
  def test_the_module_in_use_matches_its_recorded_hash
    bytes = TestSupport.read_module
    assert_operator bytes.bytesize, :>, 1_000_000
  end

  def test_a_missing_module_is_a_clear_error_naming_where_it_belongs
    Dir.mktmpdir do |dir|
      error = assert_raises(APRV::ModuleIntegrityError) do
        APRV::Runtime.read_module(File.join(dir, "aprv.wasm"), File.join(dir, "aprv.wasm.sha256"))
      end
      assert_includes error.message, "lib/apple_purchase_receipt_verifier/aprv.wasm"
    end
  end

  # --- outcome 5: a trap or an internal failure ---------------------------------

  def test_a_trap_is_internal_error_with_the_trap_as_its_cause_and_the_instance_is_discarded
    v = verifier
    assert_equal 1, idle_instances(v)
    result = v.verify_receipt("t")
    assert_equal APRV::Reason::INTERNAL_ERROR, result.failure.reason
    assert_instance_of APRV::TrapError, result.failure.cause
    assert_match(/unreachable/, result.failure.cause.message)
    assert_equal 0, idle_instances(v), "the trapped instance is not put back"
    assert_predicate v.verify_receipt("v"), :verified?, "the next call makes a fresh instance"
    assert_equal 1, idle_instances(v)
  end

  # Each of these is an answer the wrapper cannot use. None reaches the caller
  # as a verdict or as a raise, and none leaves the instance in the pool.
  def test_an_answer_the_wrapper_cannot_read_is_internal_error_and_discards_the_instance
    {
      "u" => /reason this wrapper does not know \(INVALID_CHAIN\)/,
      "j" => /not JSON/,
      "n" => /no verified flag/,
      "e" => /not JSON/,
      "o" => /result is out of range/,
      "r" => /return area is out of range/,
      "m" => /memory limit/
    }.each do |input, expected|
      v = verifier
      result = v.verify_receipt(input)
      assert_equal APRV::Reason::INTERNAL_ERROR, result.failure.reason, input
      assert_match expected, result.failure.message, input
      assert_kind_of APRV::TrapError, result.failure.cause, input
      assert_equal 0, idle_instances(v), "#{input}: the instance is discarded"
    end
  end

  def test_a_trap_at_the_endpoint_is_status_21009_and_never_a_raise
    v = verifier
    assert_equal({ "status" => 21_009 },
                 JSON.parse(v.verify_receipt_endpoint(APRV::Environment::SANDBOX, "t")))
    assert_equal 0, idle_instances(v)
    assert_equal({ "status" => 0 }, JSON.parse(v.verify_receipt_endpoint(APRV::Environment::SANDBOX, "{}")))
  end

  def test_random_get_is_answered_from_the_host_and_a_wrong_length_answer_traps
    assert_predicate verifier.verify_receipt("d"), :verified?

    short = APRV::Runtime.new(FakeModule.wat, random: ->(length) { SecureRandom.random_bytes(length - 1) })
    result = verifier(runtime: short).verify_receipt("d")
    assert_equal APRV::Reason::INTERNAL_ERROR, result.failure.reason
    assert_match(/unreachable/, result.failure.cause.message)
  end

  def test_random_get_refuses_a_request_no_verification_needs
    v = verifier
    result = v.verify_signed_data("g")
    assert_equal APRV::Reason::INTERNAL_ERROR, result.failure.reason
    assert_kind_of APRV::TrapError, result.failure.cause
    assert_equal 0, idle_instances(v)
  end

  def test_a_guest_that_trapped_refuses_further_calls
    guest = APRV::Guest.new(FAKE, "{}")
    assert_raises(APRV::TrapError) { guest.call("verify-receipt", [0], "t") }
    assert_predicate guest, :broken?
    error = assert_raises(APRV::TrapError) { guest.call("verify-receipt", [0], "v") }
    assert_match(/has trapped/, error.message)
  end

  # --- the clock ----------------------------------------------------------------

  def test_the_clock_is_read_once_per_call_and_its_value_reaches_the_module
    reads = 0
    v = verifier(APRV::Config.new(clock: -> { (reads += 1) && 1234 }))
    # The fake answers "c" only when now-ms is exactly 1234.
    assert_predicate v.verify_receipt("c"), :verified?
    assert_equal 1, reads
    assert_predicate v.verify_signed_data("c"), :verified?
    assert_equal 2, reads
    assert_equal({ "status" => 0 }, JSON.parse(v.verify_receipt_endpoint(APRV::Environment::SANDBOX, "c")))
    assert_equal 3, reads

    other = verifier(APRV::Config.new(clock: -> { 1235 }))
    assert_equal APRV::Reason::INTERNAL_ERROR, other.verify_receipt("c").failure.reason
  end

  def test_the_clock_is_read_before_the_input_is_looked_at
    reads = 0
    v = verifier(APRV::Config.new(clock: -> { (reads += 1) && 1234 }))
    v.verify_receipt(nil)
    v.verify_signed_data(42)
    v.verify_receipt_endpoint(APRV::Environment::SANDBOX, nil)
    assert_equal 3, reads

    failing = verifier(APRV::Config.new(clock: -> { raise "boom" }))
    assert_equal APRV::Reason::INTERNAL_ERROR, failing.verify_receipt(nil).failure.reason,
                 "a clock that raises is INTERNAL_ERROR whatever the input"
  end

  def test_a_clock_that_raises_or_answers_nonsense_is_internal_error
    [-> { raise "boom" }, -> { Time.utc(2024, 1, 1) }, -> { "1234" }, -> { 12.5 }, -> { -1 }, lambda {
      2**63
    }].each do |clock|
      v = verifier(APRV::Config.new(clock: clock))
      result = v.verify_receipt("v")
      assert_equal APRV::Reason::INTERNAL_ERROR, result.failure.reason
      assert_match(/clock/, result.failure.message)
      assert_equal({ "status" => 21_009 },
                   JSON.parse(v.verify_receipt_endpoint(APRV::Environment::SANDBOX, "v")))
      assert_equal 1, idle_instances(v), "the module was never called, so nothing was discarded"
    end
  end

  def test_the_clock_may_answer_the_largest_instant_the_module_takes
    v = verifier(APRV::Config.new(clock: -> { (2**63) - 1 }))
    assert_predicate v.verify_receipt("v"), :verified?
    v = verifier(APRV::Config.new(clock: -> { 0 }))
    assert_predicate v.verify_receipt("v"), :verified?
  end

  def test_the_default_clock_is_the_system_clock_in_epoch_milliseconds
    before = (Time.now.to_r * 1000).to_i
    now = APRV::Config.defaults.clock.call
    after = (Time.now.to_r * 1000).to_i
    assert_operator now, :>=, before
    assert_operator now, :<=, after
  end

  # --- env ------------------------------------------------------------------------

  def test_the_environment_is_sent_as_zero_or_one
    v = verifier
    assert_equal({ "status" => 21_007 },
                 JSON.parse(v.verify_receipt_endpoint(APRV::Environment::PRODUCTION, "{}")))
    assert_equal({ "status" => 0 }, JSON.parse(v.verify_receipt_endpoint(APRV::Environment::SANDBOX, "{}")))
    ["production", "Sandbox", "XCODE", :SANDBOX, 1, nil].each do |environment|
      assert_raises(ArgumentError, environment.inspect) { v.verify_receipt_endpoint(environment, "{}") }
    end
  end
end
