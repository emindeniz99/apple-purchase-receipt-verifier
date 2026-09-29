# frozen_string_literal: true

# Spike only (2026-09-26): a minimal Ruby facade over aprv.wasm (ABI v1) on
# the official Bytecode Alliance wasmtime gem.
#
#   v = AprvWasm::Verifier.new                       # one per thread; never shared
#   v.verify_receipt(receipt_data)                   # => Hash: "verified", "payload" | "reason"
#   v.verify_signed_data(jws)                        # => Hash: + "payloadJson"
#   v.verify_receipt_endpoint("Sandbox", body)       # => String, byte for byte
#
# No business policy: the caller compares bundleId, environment and
# appAppleId from the payload. A verification failure is a value;
# AbiMismatchError and WasmTrapError are exceptions, and a trap discards
# the instance (the next call starts a fresh one).
#
# Engine, compiled Module and a Linker holding the two host functions are
# process-wide; each Verifier owns its Store and Instance. aprv_call is
# called through `to_func(gvl: false)` (wasmtime-rb 48, opt-in), so Wasm
# runs without the GVL and threads verify in parallel; the host functions
# take the GVL back.
require "json"
require "securerandom"
require "wasmtime"

module AprvWasm
  ABI_VERSION = 1
  OP = { verify_receipt: 1, verify_signed_data: 2, endpoint_production: 3, endpoint_sandbox: 4 }.freeze
  ENDPOINT = { "Production" => 3, "Sandbox" => 4 }.freeze

  class AbiMismatchError < StandardError; end
  class WasmTrapError < StandardError; end

  # Host-function calls, process-wide (for the tests).
  IMPORT_CALLS = { "aprv.clock_now_ms" => 0, "aprv.random_get" => 0 }

  class Runtime
    attr_reader :engine, :module, :linker

    def initialize(wasm)
      @engine = Wasmtime::Engine.new
      @module = Wasmtime::Module.new(@engine, wasm)
      @module.imports.each do |imp|
        next if imp["module"] == "aprv" && %w[clock_now_ms random_get].include?(imp["name"])

        raise AbiMismatchError, "unexpected import #{imp["module"]}.#{imp["name"]}"
      end
      @linker = Wasmtime::Linker.new(@engine)
      @linker.func_new("aprv", "clock_now_ms", [], [:f64]) do |_caller|
        IMPORT_CALLS["aprv.clock_now_ms"] += 1
        Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond).to_f
      end
      @linker.func_new("aprv", "random_get", %i[i32 i32], [:i32]) do |caller, ptr, len|
        IMPORT_CALLS["aprv.random_get"] += 1
        memory = caller.export("memory").to_memory
        raise WasmTrapError, "aprv.random_get out of bounds" if ptr.negative? || len.negative? || ptr + len > memory.data_size

        memory.write(ptr, SecureRandom.random_bytes(len)) if len.positive?
        0
      end
    end

    def self.shared
      @lock.synchronize { @shared ||= new(File.binread(File.join(__dir__, "aprv_wasm", "aprv.wasm"))) }
    end
    @lock = Mutex.new
  end

  # One Store + Instance. Not thread-safe.
  class Instance
    attr_reader :store, :memory, :module_version

    def initialize(runtime = Runtime.shared)
      @store = Wasmtime::Store.new(runtime.engine)
      @instance = runtime.linker.instantiate(@store, runtime.module)
      @memory = @instance.export("memory").to_memory
      @f = %w[aprv_alloc aprv_dealloc aprv_result_ptr aprv_result_len aprv_result_free aprv_abi_version _initialize]
           .to_h { |n| [n, @instance.export(n).to_func] }
      # The one long call runs without the GVL, so threads verify in
      # parallel. wasmtime-rb's rule for gvl: false: each thread its own
      # Store, which is what one Instance per thread gives.
      # APRV_GVL=1 (spike only) keeps the GVL, to measure the default.
      @f["aprv_call"] = @instance.export("aprv_call").to_func(gvl: ENV["APRV_GVL"] == "1")
      @f["_initialize"].call
      @module_version = @f["aprv_abi_version"].call
      return if @module_version == ABI_VERSION

      raise AbiMismatchError, "APRV Wasm ABI mismatch: module=#{@module_version}, caller=#{ABI_VERSION}"
    end

    # A raw export call, for the ABI tests.
    def raw(name, *args)
      @instance.export(name).to_func.call(*args)
    end

    # The lifecycle: alloc, copy in, aprv_call, bounds-check, copy out, free, dealloc.
    def invoke(operation, data, abi_version = ABI_VERSION)
      data = data.b
      n = data.bytesize
      p = @f["aprv_alloc"].call(n) & 0xFFFFFFFF
      raise NoMemoryError, "aprv_alloc(#{n}) failed" if p.zero?

      @memory.write(p, data) if n.positive?
      begin
        h = @f["aprv_call"].call(abi_version, operation, p, n)
      rescue Wasmtime::Trap
        raise AbiMismatchError, "APRV Wasm ABI mismatch: module=#{@module_version}, caller=#{abi_version}" if abi_version != @module_version

        raise
      end
      rp = @f["aprv_result_ptr"].call(h) & 0xFFFFFFFF
      rn = @f["aprv_result_len"].call(h) & 0xFFFFFFFF
      raise WasmTrapError, "result out of bounds" if rp + rn > @memory.data_size

      out = @memory.read(rp, rn) # a copy owned by Ruby
      @f["aprv_result_free"].call(h)
      @f["aprv_dealloc"].call(p, n)
      out
    end
  end

  # The facade: one per thread. A trap discards the instance.
  class Verifier
    attr_reader :traps

    def initialize
      @inst = Instance.new
      @traps = 0
    end

    def call(operation, data, abi_version = ABI_VERSION)
      @inst ||= Instance.new
      @inst.invoke(operation, data, abi_version)
    rescue Wasmtime::Error, WasmTrapError => e # Wasmtime::Trap is a Wasmtime::Error
      @inst = nil
      @traps += 1
      raise WasmTrapError, e.message
    rescue AbiMismatchError
      @inst = nil
      raise
    end

    def verify_receipt(receipt_data)
      JSON.parse(call(OP[:verify_receipt], receipt_data))
    end

    def verify_signed_data(jws)
      JSON.parse(call(OP[:verify_signed_data], jws))
    end

    def verify_receipt_endpoint(environment, body)
      call(ENDPOINT.fetch(environment), body).force_encoding(Encoding::UTF_8)
    end
  end
end
