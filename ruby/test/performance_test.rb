# frozen_string_literal: true

require_relative "helper"

# Cost budgets for the largest genuine inputs this project knows of. They exist
# so a change that quietly makes verification an order of magnitude more
# expensive fails a test instead of a customer's p99, and the observed numbers
# are printed either way.
#
# CPU time, not wall time: this suite runs on shared runners where wall time
# also measures the scheduler (a 1.46 s wall-clock outlier with 10 ms of CPU
# behind it was observed while developing the mutation suite).
class PerformanceTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def cpu_ms(iterations = 10, &)
    yield # warm up
    started = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    iterations.times(&)
    ((Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - started) / iterations) * 1000
  end

  def report(label, milliseconds, budget)
    puts format("\n  [perf] %<label>-42s %<ms>6.2f ms (budget %<budget>d ms)",
                label: label, ms: milliseconds, budget: budget)
    assert_operator milliseconds, :<, budget, "#{label} took #{milliseconds.round(2)}ms"
  end

  # 79 KB, 187 in-app purchases, SHA-1 chain end to end.
  def test_the_largest_genuine_receipt_stays_inside_its_budget
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "com.nutcall.alert")
    bytes = TestSupport.fixture_bytes("public-receipt-sandbox-legacy")
    report("legacy receipt, 79 KB / 187 purchases", cpu_ms { verifier.verify_der(bytes) }, 150)
  end

  def test_a_typical_receipt_stays_inside_its_budget
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "dev.bonzer.weeka.app")
    bytes = TestSupport.fixture_bytes("public-receipt-sandbox-g5")
    report("sandbox receipt, 5.6 KB", cpu_ms(50) { verifier.verify_der(bytes) }, 25)
  end

  def test_a_transaction_jws_stays_inside_its_budget
    verifier = APRV::JwsVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("jws-root")],
      bundle_id: "com.example.app", accepted_environments: [APRV::Environment::SANDBOX]
    )
    jws = TestSupport.fixture_bytes("transaction").force_encoding(Encoding::UTF_8)
    report("transaction JWS", cpu_ms(50) { verifier.verify_transaction(jws) }, 15)
  end

  # Rejecting hostile input must not cost more than accepting genuine input.
  def test_rejecting_a_nesting_bomb_costs_almost_nothing
    verifier = APRV::ReceiptVerifier.new(trusted_roots: APRV.apple_receipt_roots,
                                         bundle_id: "com.example.app")
    bomb = "\x30\x80".b * 500_000
    milliseconds = cpu_ms(20) do
      verifier.verify_der(bomb)
    rescue APRV::VerificationError
      nil
    end
    report("2 MB indefinite-length nesting bomb", milliseconds, 10)
  end
end
