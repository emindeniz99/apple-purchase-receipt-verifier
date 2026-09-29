# frozen_string_literal: true

require "digest"
require "securerandom"
require "wasmtime"

module ApplePurchaseReceiptVerifier
  # The process-wide half of the wasm host: one Engine, one compiled Module
  # and one Linker holding the module's single import, `random-get`. Every
  # {Guest} (one Store and one Instance) is made from it.
  #
  # The module is `aprv.wasm`, the same file every other package of this
  # repository runs. It holds all of the verification; this class only
  # loads it, checks it is the module this gem shipped with, and refuses to
  # run it if it asks the host for anything but random bytes.
  #
  # @api private
  class Runtime
    # The interface package the wrapper is built for. The version is the
    # ABI version: a module of another version has no such exports.
    ABI = "aprv:verifier/verify@1.0.0"
    HOST = "aprv:verifier/host@1.0.0"
    RANDOM_GET = "random-get"

    # The four operations of the WIT interface.
    OPERATIONS = %w[init verify-receipt verify-signed-data verify-receipt-endpoint].freeze

    # `random-get`'s answer is OpenSSL's blinding and seeding draw, a few
    # bytes at a time; refuse a request no verification needs.
    MAX_RANDOM_BYTES = 1 << 20

    # Where the module is read from: this path and no other. The library
    # reads no environment variable and takes no option that swaps the
    # module. The file is not tracked (a build or a release job copies it
    # into place); the SHA-256 beside it is, and pins it.
    MODULE_PATH = File.join(File.dirname(__FILE__), "aprv.wasm")
    HASH_PATH = "#{MODULE_PATH}.sha256".freeze

    LOCK = Mutex.new
    private_constant :LOCK

    class << self
      # The runtime for the module this gem ships, compiled on first use and
      # once per process (the compile takes about a second; every later
      # {Verifier} reuses it).
      #
      # @return [Runtime]
      # @raise [ModuleIntegrityError] the module does not match its SHA-256
      # @raise [AbiMismatchError] the module does not speak this ABI
      def shared
        LOCK.synchronize { @shared ||= new(read_module) }
      end

      # The module's bytes, checked against the SHA-256 recorded in
      # {HASH_PATH}. The arguments exist for the tests and tooling of this
      # repository; {shared}, which every {Verifier} uses, passes none.
      #
      # @param path [String]
      # @param hash_path [String] a `sha256sum` line: 64 hex digits first
      # @return [String]
      # @raise [ModuleIntegrityError] the file is missing, or does not match
      def read_module(path = MODULE_PATH, hash_path = HASH_PATH)
        unless File.file?(path)
          raise ModuleIntegrityError,
                "the module #{File.basename(path)} is not at #{path}: copy the release build " \
                "to lib/apple_purchase_receipt_verifier/aprv.wasm"
        end

        bytes = File.binread(path)
        recorded = File.read(hash_path)[/\A\h{64}/]
        raise ModuleIntegrityError, "#{File.basename(hash_path)} does not hold a SHA-256" if recorded.nil?

        actual = Digest::SHA256.hexdigest(bytes)
        return bytes if actual == recorded.downcase

        raise ModuleIntegrityError,
              "#{File.basename(path)} has SHA-256 #{actual}, " \
              "but #{File.basename(hash_path)} records #{recorded}"
      end
    end

    # @return [Wasmtime::Engine]
    attr_reader :engine

    # @return [Wasmtime::Module]
    attr_reader :wasm_module

    # @return [Wasmtime::Linker]
    attr_reader :linker

    # @param bytes [String] the module
    # @param random [#call] returns the requested number of random bytes;
    #   `SecureRandom` unless a test says otherwise
    # @raise [AbiMismatchError] the module is not valid, or imports anything
    #   but `random-get`
    def initialize(bytes, random: SecureRandom.method(:random_bytes))
      @random = random
      @engine = Wasmtime::Engine.new
      @wasm_module = compile(bytes)
      refuse_other_imports
      @linker = Wasmtime::Linker.new(@engine)
      @linker.func_new(HOST, RANDOM_GET, %i[i32 i32], []) do |caller, length, retptr|
        random_get(caller, length, retptr)
        nil
      end
      freeze
    end

    private

    def compile(bytes)
      Wasmtime::Module.new(@engine, bytes)
    rescue Wasmtime::Error => e
      raise AbiMismatchError, "the module does not compile: #{e.class}"
    end

    def refuse_other_imports
      @wasm_module.imports.each do |import|
        next if import["module"] == HOST && import["name"] == RANDOM_GET

        raise AbiMismatchError,
              "the module imports #{import["module"]}##{import["name"]}; " \
              "this wrapper provides only #{HOST}##{RANDOM_GET}"
      end
    end

    # `random-get: func(len: u32) -> list<u8>`, lowered as (len, retptr): the
    # answer is allocated in guest memory with the guest's own
    # `cabi_realloc`, and (ptr, len) written at `retptr`. The guest traps
    # when the length is not the one it asked for.
    def random_get(caller, length, retptr)
      length &= 0xFFFFFFFF
      raise TrapError, "random-get asked for #{length} bytes" if length > MAX_RANDOM_BYTES

      bytes = @random.call(length).b
      memory = caller.export("memory").to_memory
      pointer = caller.export("cabi_realloc").to_func.call(0, 0, 1, bytes.bytesize) & 0xFFFFFFFF
      size = memory.data_size
      unless pointer + bytes.bytesize <= size && (retptr & 0xFFFFFFFF) + 8 <= size
        raise TrapError, "random-get: out-of-range pointer"
      end

      memory.write(pointer, bytes) unless bytes.empty?
      retptr &= 0xFFFFFFFF
      memory.write_u32(retptr, pointer)
      memory.write_u32(retptr + 4, bytes.bytesize)
    end
  end
end
