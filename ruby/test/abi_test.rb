# frozen_string_literal: true

require_relative "helper"

# The canonical-ABI misuse and isolation tests of the final spike round
# (docs/evidence/2026-09-29-canonical-abi-final/), on the shipped aprv.wasm,
# called through the hand-written lowering in Guest. Where the spike had a
# test for a typed host's lowering table, the Ruby equivalent is that Guest
# refuses what it cannot lower. What a test asserts about an answer is
# deliberately loose ("verified":true, a status number): the wire's finer
# points belong to the shared cases, and these tests must hold for any module
# that speaks the ABI.
#
# Not applicable to this host: a double post-return and a post-return on a
# foreign pointer (finding 5 of the round). Guest calls post-return exactly
# once per result and never lets a pointer out, which is the mitigation the
# plan asks of every hand-rolled host.
class AbiTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  CASES = TestSupport.cases["cases"]
  NONE = '{"roots":[]}'
  NOW = 1_767_225_600_000

  def runtime
    APRV::Runtime.shared
  end

  def receipt_base64
    @receipt_base64 ||= [TestSupport.fixture_bytes("public-receipt-sandbox-g5")].pack("m0")
  end

  def jws
    @jws ||= TestSupport.fixture_bytes("transaction")
  end

  def jws_config
    JSON.generate("roots" => [[TestSupport.fixture_bytes("jws-root")].pack("m0")])
  end

  def guest(config = NONE)
    APRV::Guest.new(runtime, config)
  end

  def trapped?(guest = nil, &block)
    block.call
    false
  rescue APRV::TrapError
    guest.nil? || guest.broken?
  end

  # --- the interface's contract --------------------------------------------------

  def test_init_with_no_roots_answers_ok
    assert_equal '{"ok":true}', APRV::Guest.new(runtime, nil).call("init", [], NONE)
    assert_equal '{"ok":true}', APRV::Guest.new(runtime, nil).call("init", [], "")
    assert_equal '{"ok":true}', APRV::Guest.new(runtime, nil).call("init", [], "{}")
  end

  def test_a_verify_before_init_traps
    fresh = APRV::Guest.new(runtime, nil)
    assert trapped?(fresh) { fresh.call("verify-receipt", [NOW], receipt_base64) }
  end

  def test_a_second_init_traps
    initialised = guest
    assert trapped?(initialised) { initialised.call("init", [], NONE) }
  end

  def test_a_configuration_that_is_not_json_is_refused_as_a_value_and_init_can_be_retried
    fresh = APRV::Guest.new(runtime, nil)
    answer = JSON.parse(fresh.call("init", [], "{not json"))
    assert_same false, answer["ok"]
    refute_empty answer["message"]
    refute_predicate fresh, :broken?
    assert_equal '{"ok":true}', fresh.call("init", [], NONE)
    assert_includes fresh.call("verify-receipt", [NOW], receipt_base64), '"verified":true'
  end

  def test_a_root_that_is_not_a_certificate_is_refused_at_init
    error = assert_raises(APRV::RootsRejected) { guest(JSON.generate("roots" => [["not a cert"].pack("m0")])) }
    refute_empty error.message
  end

  def test_the_genuine_receipt_verifies_against_the_bundled_roots
    assert_includes guest.call("verify-receipt", [NOW], receipt_base64), '"verified":true'
  end

  def test_the_shared_sandbox_jws_verifies_against_its_own_roots
    assert_includes guest(jws_config).call("verify-signed-data", [NOW], jws), '"verified":true'
  end

  def test_the_endpoint_answers_status_zero_for_the_sandbox_receipt_in_the_sandbox
    body = JSON.generate("receipt-data" => receipt_base64)
    answer = JSON.parse(guest.call("verify-receipt-endpoint", [1, NOW], body))
    assert_equal 0, answer["status"]
    answer = JSON.parse(guest.call("verify-receipt-endpoint", [0, NOW], body))
    assert_equal 21_007, answer["status"], "a sandbox receipt on the production endpoint"
  end

  def test_a_jws_that_is_not_utf8_reaches_the_module_and_is_a_value
    instance = guest
    answer = JSON.parse(instance.call("verify-signed-data", [NOW], "ey\xff\xfe.x".b))
    assert_same false, answer["verified"]
    refute_predicate instance, :broken?
  end

  # --- what the wrapper refuses to lower ----------------------------------------------

  def test_guest_refuses_arguments_that_are_not_the_wits_types_and_discards_itself
    # (wasmtime-rb coerces a Float to an integer instead of refusing it, so
    # the Verifier's own check that the clock answered an Integer is what
    # keeps a Float from becoming an instant.)
    [[["5"], "u64 as a String"], [[nil], "u64 as nil"], [[2**64], "u64 out of range"],
     [[], "a missing scalar"], [[NOW, NOW], "an extra scalar"]].each do |scalars, what|
      instance = guest
      error = assert_raises(APRV::TrapError, what) { instance.call("verify-receipt", scalars, receipt_base64) }
      assert_predicate instance, :broken?, what
      refute_empty error.message
    end
  end

  # --- env is a u32 the guest matches ------------------------------------------------------

  def test_an_environment_other_than_zero_or_one_traps
    body = JSON.generate("receipt-data" => receipt_base64)
    [2, 255, (2**32) - 1, -1].each do |env|
      instance = guest
      assert trapped?(instance) { instance.call("verify-receipt-endpoint", [env, NOW], body) }, "env #{env}"
    end
  end

  # --- the import ---------------------------------------------------------------------------

  def test_random_get_answering_the_wrong_length_traps
    short = APRV::Runtime.new(TestSupport.read_module, random: ->(n) { SecureRandom.random_bytes(n - 1) })
    instance = APRV::Guest.new(short, jws_config)
    assert trapped?(instance) { instance.call("verify-signed-data", [NOW], jws) }
  end

  def test_the_module_imports_only_random_get
    imports = runtime.wasm_module.imports.map { |i| [i["module"], i["name"]] }
    assert_equal [["aprv:verifier/host@1.0.0", "random-get"]], imports
  end

  def test_the_module_exports_the_interface_at_the_version_the_wrapper_binds
    names = guest.instance_variable_get(:@operations).keys
    assert_equal APRV::Runtime::OPERATIONS.sort, names.sort
  end

  # --- isolation ------------------------------------------------------------------------------

  def test_a_trap_in_one_instance_leaves_another_verifying
    a = guest
    b = guest
    assert_includes b.call("verify-receipt", [NOW], receipt_base64), '"verified":true'
    body = JSON.generate("receipt-data" => receipt_base64)
    assert trapped?(a) { a.call("verify-receipt-endpoint", [2, NOW], body) }
    2.times { assert_includes b.call("verify-receipt", [NOW], receipt_base64), '"verified":true' }
  end

  def test_a_trapped_guest_refuses_to_answer_again
    a = guest
    assert trapped?(a) { a.call("verify-receipt-endpoint", [2, NOW], "{}") }
    assert_raises(APRV::TrapError) { a.call("verify-receipt", [NOW], receipt_base64) }
  end

  # --- heap discipline ---------------------------------------------------------------------------

  # 2,000 calls leave linear memory the size it was after the first.
  def test_linear_memory_does_not_grow_over_many_calls
    instance = guest
    store = instance.instance_variable_get(:@store)
    instance.call("verify-receipt", [NOW], receipt_base64)
    after_first = store.max_linear_memory_consumed
    2000.times { instance.call("verify-receipt", [NOW], receipt_base64) }
    assert_equal after_first, store.max_linear_memory_consumed
  end

  def test_an_input_of_no_bytes_and_of_the_cap_are_answered
    instance = guest
    assert_includes instance.call("verify-receipt", [NOW], ""), '"verified":false'
    big = "A" * 3_145_729
    assert_includes instance.call("verify-receipt", [NOW], big), '"verified":false'
    assert_includes instance.call("verify-receipt", [NOW], receipt_base64), '"verified":true'
  end

  # An input is never copied into linear memory beyond one byte over the
  # cap: the module answers TOO_LARGE itself, with the same answer and the
  # same memory use as for an input of exactly that length.
  def test_an_input_over_the_cap_is_cut_to_one_byte_over_and_the_module_answers_too_large
    cut = guest
    exact = guest
    huge = "A" * (4 * 1024 * 1024)
    answer = JSON.parse(cut.call("verify-receipt", [NOW], huge))
    assert_same false, answer["verified"]
    assert_equal "TOO_LARGE", answer["reason"]
    assert_equal exact.call("verify-receipt", [NOW], huge.byteslice(0, 3_145_729)),
                 cut.call("verify-receipt", [NOW], huge)
    assert_equal exact.instance_variable_get(:@store).max_linear_memory_consumed,
                 cut.instance_variable_get(:@store).max_linear_memory_consumed
    endpoint = JSON.parse(cut.call("verify-receipt-endpoint", [1, NOW], huge))
    assert_equal 21_002, endpoint["status"]
  end

  def test_an_input_of_exactly_the_cap_is_passed_whole
    instance = guest
    answer = JSON.parse(instance.call("verify-receipt", [NOW], "A" * 3_145_728))
    assert_same false, answer["verified"]
    refute_equal "TOO_LARGE", answer["reason"], "3,145,728 bytes is the cap itself, not over it"
  end
end
