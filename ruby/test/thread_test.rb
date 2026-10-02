# frozen_string_literal: true

require_relative "helper"
require_relative "fake_module"

# One Verifier used from several threads at once: each call gets an instance
# to itself, a trap costs the caller that one call and its instance, and no
# thread ever sees another's answer. (bench/threads.rb measures how the rate
# scales with the threads; this file is about correctness under them.)
class ThreadTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  FAKE = Internals::Runtime.new(FakeModule.wat)

  def verifier
    APRV::Verifier.send(:new, APRV::Config.defaults, runtime: FAKE)
  end

  # Four threads, a trap on every 7th call: 180 verified and exactly 30
  # INTERNAL_ERROR each, however the instances are handed around. (The
  # spike's first harness assigned to a variable the four thread blocks
  # shared, and the counts came out 59, 89, 90 and 92.)
  def test_a_trap_in_one_thread_is_that_calls_alone
    shared = verifier
    outcomes = Array.new(4) do
      Thread.new do
        Array.new(210) { |i| ((i + 1) % 7).zero? ? shared.verify_receipt("t") : shared.verify_receipt("v") }
      end
    end.map(&:value)
    outcomes.each do |results|
      assert_equal 180, results.count(&:verified?)
      assert_equal(30, results.count { |r| r.failure&.reason == APRV::Reason::INTERNAL_ERROR })
    end
  end

  def test_no_thread_sees_another_threads_answer
    shared = verifier
    answers = Array.new(8) do |n|
      Thread.new do
        Array.new(100) do
          input = n.even? ? "f" : "v"
          [input, shared.verify_receipt(input)]
        end
      end
    end.flat_map(&:value)
    answers.each do |input, result|
      assert_equal input == "v", result.verified?, "input #{input}"
    end
  end

  def test_a_burst_grows_the_pool_and_only_a_few_idle_instances_are_kept
    shared = verifier
    gate = Thread::Queue.new
    starters = Array.new(20) do
      Thread.new do
        gate.pop
        shared.verify_receipt("d") # random-get, so calls overlap
      end
    end
    20.times { gate << :go }
    starters.each(&:join)
    idle = shared.instance_variable_get(:@pool).idle_count
    assert_operator idle, :>=, 1
    assert_operator idle, :<=, Internals::InstancePool::MAX_IDLE
  end

  # Every export runs without the GVL (`to_func(gvl: false)`), which is what
  # lets threads verify in parallel. The 1 MiB byte-floor receipt takes the
  # module about 100 ms; a thread that sleeps a millisecond at a time keeps
  # ticking through it. With the GVL held it would not tick until the call
  # returned. (bench/threads.rb measures the rate this buys on real cores;
  # this test does not depend on there being any.)
  def test_a_long_call_does_not_hold_the_gvl
    root = TestSupport.fixture_bytes("large-receipt-root")
    receipt = [TestSupport.fixture_bytes("receipt-byte-floor")].pack("m0")
    pool = APRV::Verifier.create(APRV::Config.new(roots: [root])).instance_variable_get(:@pool)
    now = (Time.now.to_r * 1000).to_i
    pool.with_guest { |guest| guest.call("verify-receipt", [now], receipt) } # first call warms the instance

    ticks = 0
    ticker = Thread.new { loop { sleep 0.001 and (ticks += 1) } }
    sleep 0.01
    before = ticks
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    answer = pool.with_guest { |guest| guest.call("verify-receipt", [now], receipt) }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    during = ticks - before
    ticker.kill

    assert_includes answer, '"verified":true'
    assert_operator elapsed, :>, 0.02, "the call was too short to tell"
    assert_operator during, :>=, 5, "the ticker made #{during} ticks in a #{(elapsed * 1000).round} ms call"
  end

  def test_a_call_cut_short_discards_its_instance
    shared = verifier
    pool = shared.instance_variable_get(:@pool)
    assert_equal 1, pool.idle_count
    worker = Thread.new do
      pool.with_guest { |_guest| Thread.current.kill }
    end
    worker.join
    assert_equal 0, pool.idle_count, "the instance whose call never finished is not reused"
    assert_predicate shared.verify_receipt("v"), :verified?
  end
end
