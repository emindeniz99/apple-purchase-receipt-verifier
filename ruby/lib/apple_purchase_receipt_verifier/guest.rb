# frozen_string_literal: true

require "wasmtime"

module ApplePurchaseReceiptVerifier
  # The module refused the configuration `init` was given: a root that is not
  # a certificate, or a configuration that is not the JSON it expects.
  # {Verifier.create} turns it into an ArgumentError.
  #
  # @api private
  class RootsRejected < StandardError; end
  private_constant :RootsRejected

  # One Store and one Instance of `aprv.wasm`, and the hand-written call of
  # the canonical ABI (the Component Model's calling convention) over its core
  # exports. One call at a time: the return area is a single static slot in
  # the guest, and a Store is used by one thread at a time.
  #
  # Every call follows the same steps, and no guest pointer leaves this class:
  #
  # 1. `cabi_realloc(0, 0, 1, len)` for the input, then copy the bytes in
  #    (the guest owns and frees that buffer);
  # 2. call the export with its scalars in declaration order, then `(ptr, len)`;
  # 3. read the return area, `ptr` then `len` as little-endian u32, at the
  #    returned address, both checked against the memory size, and copy the
  #    result out;
  # 4. `cabi_post_<export>(retptr)`, which frees the result.
  #
  # A trap, a runtime error, an out-of-range pointer or a Store that reached
  # its memory limit makes the instance {#broken?}: the caller discards it. A
  # hand-rolled host must do that itself, because Wasmtime lets a trapped
  # instance keep answering.
  #
  # @api private
  class Guest
    # Linear memory of one instance, at most; and one instance, memory and
    # table per Store.
    LIMITS = { memory_size: 256 * 1024 * 1024, instances: 1, memories: 1, tables: 1 }.freeze

    # The most bytes of one input this instance is handed: the
    # `max_input_bytes` its `init` answer stated (docs/rust-core/DECISIONS.md
    # R42), one over the largest cap the module knows, so the module itself
    # answers TOO_LARGE for anything longer and no bigger copy is ever made.
    # nil until `init` has answered, and an input is then passed whole.
    #
    # @return [Integer, nil]
    attr_reader :max_input_bytes

    # @param runtime [Runtime]
    # @param config_json [String, nil] `init`'s argument,
    #   `{"roots":["<base64>", ...]}`; nil skips `init` (for tests of what
    #   the module does before it)
    # @raise [AbiMismatchError] the module lacks the exports this wrapper binds
    # @raise [RootsRejected] `init` refused the configuration
    # @raise [TrapError] the module trapped, or failed, while starting, or
    #   `init`'s answer states no input length
    def initialize(runtime, config_json)
      @broken = false
      @max_input_bytes = nil
      @store = Wasmtime::Store.new(runtime.engine, limits: LIMITS)
      exports = instantiate(runtime)
      @memory = exports.fetch("memory").to_memory
      # Every export runs without the GVL, so threads verify in parallel;
      # wasmtime's rule for that is one Store per thread at a time, which is
      # what one Guest per call gives. The host function takes the GVL back.
      @realloc = exports.fetch("cabi_realloc").to_func(gvl: false)
      @operations = Runtime::OPERATIONS.to_h do |name|
        [name, [exports.fetch("#{Runtime::ABI}##{name}").to_func(gvl: false),
                exports.fetch("cabi_post_#{Runtime::ABI}##{name}").to_func(gvl: false)]]
      end.freeze
      start(config_json) unless config_json.nil?
    rescue Wasmtime::Error => e
      raise TrapError, "starting the module: #{describe(e)}"
    end

    # @return [Boolean] the instance trapped or failed and must be discarded
    def broken?
      @broken
    end

    # Releases the Store's memory now rather than when the GC gets to it.
    def close
      @store.close unless @store.closed?
    rescue Wasmtime::Error
      nil
    end

    # Calls one operation.
    #
    # @param name [String] one of {Runtime::OPERATIONS}
    # @param scalars [Array<Integer>] the operation's `u32` and `u64`
    #   parameters, in declaration order
    # @param input [String] the `list<u8>` parameter's bytes; at most
    #   {#max_input_bytes} of them are passed on
    # @return [String] the operation's `string` result, UTF-8
    # @raise [TrapError] the call trapped or failed; the instance is broken
    def call(name, scalars, input)
      raise TrapError, "the instance has trapped" if @broken

      function, post_return = @operations.fetch(name)
      bytes = input.b
      max = @max_input_bytes
      bytes = bytes.byteslice(0, max) || bytes if max && bytes.bytesize > max
      pointer = lower(bytes)
      retptr = function.call(*scalars, pointer, bytes.bytesize) & 0xFFFFFFFF
      out = lift(retptr)
      post_return.call(retptr)
      check_memory_limit
      out.force_encoding(Encoding::UTF_8)
    rescue TrapError
      discard
      raise
    rescue Wasmtime::Error => e
      discard
      raise TrapError, describe(e)
    rescue StandardError => e
      discard
      raise TrapError, "#{e.class} while calling #{name}"
    end

    private

    def instantiate(runtime)
      instance = runtime.linker.instantiate(@store, runtime.wasm_module)
      exports = instance.exports
      wanted = %w[memory cabi_realloc] +
               Runtime::OPERATIONS.flat_map { |n| ["#{Runtime::ABI}##{n}", "cabi_post_#{Runtime::ABI}##{n}"] }
      missing = wanted - exports.keys
      return exports if missing.empty?

      raise AbiMismatchError,
            "this wrapper binds #{Runtime::ABI}; the module lacks #{missing.join(", ")} " \
            "and exports #{exports.keys.grep(/#/).sort.join(", ")}"
    end

    # `init`, and the input length its answer states. Every instance runs
    # the one compiled module, so each states the same number; it is read
    # from this instance's own answer rather than assumed.
    def start(config_json)
      @max_input_bytes = Wire.init_answer(call("init", [], config_json))
    rescue RootsRejected, TrapError
      discard
      raise
    end

    def discard
      @broken = true
      close
    end

    # Steps 1 of the lifecycle: the input into guest memory.
    def lower(bytes)
      length = bytes.bytesize
      pointer = @realloc.call(0, 0, 1, length) & 0xFFFFFFFF
      if pointer + length > @memory.data_size
        raise TrapError,
              "cabi_realloc returned an out-of-range pointer"
      end

      @memory.write(pointer, bytes) unless bytes.empty?
      pointer
    end

    # Step 3: the return area, then the string it points at.
    def lift(retptr)
      raise TrapError, "the return area is out of range" if retptr + 8 > @memory.data_size

      pointer = @memory.read_u32(retptr)
      length = @memory.read_u32(retptr + 4)
      raise TrapError, "the result is out of range" if pointer + length > @memory.data_size

      @memory.read(pointer, length)
    end

    # The Store's limit was reached: an allocation inside the guest failed, so
    # its answer is not one to trust.
    def check_memory_limit
      raise TrapError, "the instance reached its memory limit" if @store.linear_memory_limit_hit?
    end

    def describe(error)
      return "wasm trap #{error.code.inspect}" if error.is_a?(Wasmtime::Trap) && error.code

      "wasm runtime error (#{error.class})"
    end
  end
  private_constant :Guest
end
