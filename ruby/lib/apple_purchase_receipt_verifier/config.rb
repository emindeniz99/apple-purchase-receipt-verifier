# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # Immutable {Verifier} configuration: the pinned trust anchors and the
  # clock.
  #
  # The clock answers "what time is it now?" and nothing else. The library
  # reads it at most once per call, and only for one of two things: the
  # certificate-validity instant when the receipt or JWS carries no usable
  # signing date, and `request_date` in the endpoint response. A
  # caller-supplied clock must be safe to call from several threads.
  #
  #   Config.defaults                                   # Apple's pinned roots + the system clock
  #   Config.new(roots: my_roots, clock: -> { Time.now.to_i * 1000 })
  #   Config.builder.roots(my_roots).build
  class Config
    # A proc reading the system clock, epoch milliseconds. The default
    # {#clock} of {defaults} and of a {Builder} whose `clock` is never set.
    SYSTEM_CLOCK = -> { (Time.now.to_r * 1000).to_i }

    # @return [Array<OpenSSL::X509::Certificate>] the pinned trust anchors,
    #   frozen
    attr_reader :roots

    # @return [#call] a proc (or any object responding to `#call`) returning
    #   the current instant as epoch milliseconds
    attr_reader :clock

    class << self
      # Apple's three pinned roots and the system clock.
      #
      # The bundled roots load all together or not at all, each checked
      # against its published SHA-256 fingerprint (Roots). Should they not
      # load, {#roots} is empty and every {Verifier} built from this answers
      # INTERNAL_ERROR to every call, rather than the misleading
      # UNTRUSTED_CHAIN an empty anchor set would otherwise produce.
      #
      # @return [Config]
      def defaults
        new
      end

      # @return [Builder] a builder whose unset parts are {defaults}'
      def builder
        Builder.new
      end
    end

    # @param roots [Array<OpenSSL::X509::Certificate, String>, nil] pinned
    #   anchors, as certificate objects or DER/PEM strings; Apple's bundled
    #   roots when omitted
    # @param clock [#call, nil] the system clock when omitted
    # @raise [ArgumentError] a `roots` entry is neither a certificate nor a
    #   String, or `clock` does not respond to `#call`
    def initialize(roots: nil, clock: nil)
      @roots = roots.nil? ? Roots.apple_roots : normalize(roots)
      raise ArgumentError, "clock must respond to #call" if !clock.nil? && !clock.respond_to?(:call)

      @clock = clock || SYSTEM_CLOCK
      freeze
    end

    private

    def normalize(roots)
      raise ArgumentError, "roots must be an Array" unless roots.is_a?(Array)

      roots.map do |root|
        case root
        when OpenSSL::X509::Certificate then root
        when String then OpenSSL::X509::Certificate.new(root)
        else
          raise ArgumentError,
                "roots entries must be OpenSSL::X509::Certificate or DER/PEM String, got #{root.class}"
        end
      end.freeze
    end

    # Builds a {Config} from parts set one at a time. Every 0.7 port offers
    # this shape; in Ruby, `Config.new(roots:, clock:)` says the same thing
    # in one call and is the more idiomatic spelling.
    class Builder
      def initialize
        @roots = nil
        @clock = nil
      end

      # @param roots [Array<OpenSSL::X509::Certificate, String>]
      # @return [self]
      def roots(roots)
        @roots = roots
        self
      end

      # @param clock [#call]
      # @return [self]
      def clock(clock)
        @clock = clock
        self
      end

      # @return [Config]
      def build
        Config.new(roots: @roots, clock: @clock)
      end
    end
  end
end
