# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # The instances behind one {Verifier}: a small pool of {Guest}s made from
  # one compiled module, each with `init` already called with the {Config}'s
  # roots.
  #
  # A call takes an idle instance or, when there is none, makes another, so
  # one instance serves one call at a time and a busy pool grows to the
  # number of concurrent callers; the idle ones kept are capped. An instance
  # that trapped, that failed, or whose call was cut short (a `Timeout`, a
  # killed thread) is discarded with everything in it and the next call makes
  # a fresh one. Instances are handed out here, never held in a variable a
  # block can capture, which is how a first harness ended up sharing one
  # across four threads.
  #
  # @api private
  class InstancePool
    # Idle instances kept. Each one holds its linear memory (about 2 MiB
    # after a verification, more after a large receipt).
    MAX_IDLE = 8

    # @param runtime [Runtime]
    # @param config_json [String] `init`'s argument
    # @raise [AbiMismatchError, RootsRejected, TrapError] from the first
    #   instance, made now so a broken module or configuration fails at
    #   {Verifier.create} and never later
    def initialize(runtime, config_json)
      @runtime = runtime
      @config_json = config_json
      @idle = Thread::Queue.new
      @idle << Guest.new(runtime, config_json)
    end

    # Runs the block with an instance to itself. The instance goes back to
    # the pool only when the block returns normally and the instance is not
    # {Guest#broken?}; any other exit discards it.
    #
    # @yieldparam guest [Guest]
    # @return the block's value
    def with_guest
      guest = checkout
      returned = false
      begin
        value = yield guest
        returned = true
        value
      ensure
        if returned && !guest.broken? && @idle.size < MAX_IDLE
          @idle << guest
        else
          guest.close
        end
      end
    end

    # @return [Integer] instances waiting for a call
    def idle_count
      @idle.size
    end

    private

    def checkout
      @idle.pop(true)
    rescue ThreadError
      Guest.new(@runtime, @config_json)
    end
  end
end
