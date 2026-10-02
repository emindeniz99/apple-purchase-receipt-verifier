# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Immutable {Verifier} configuration: the pinned trust anchors and the
  # clock.
  #
  # The clock answers "what time is it now?" and nothing else. The library
  # reads it once per call, before it looks at the input, and passes the
  # value to the module, which uses it for one of two things: the
  # certificate-validity instant when the receipt or JWS carries no usable
  # signing date, and `request_date` in the endpoint response. A clock that
  # raises, or answers anything but an Integer in 0..2**63-1, makes the call
  # INTERNAL_ERROR. A caller-supplied clock must be safe to call from several
  # threads.
  #
  #   Config.new                                        # Apple's pinned roots + the system clock
  #   Config.new(roots: my_roots, clock: -> { Time.now.to_i * 1000 })
  class Config
    # A proc reading the system clock, epoch milliseconds: the {#clock} of a
    # Config given no `clock:`.
    SYSTEM_CLOCK = -> { (Time.now.to_r * 1000).to_i }

    # @return [Array<String>] the caller's pinned trust anchors as frozen DER
    #   strings; empty for {defaults}, whose three Apple roots are compiled
    #   into the module and pinned there
    attr_reader :roots

    # @return [#call] a proc (or any object responding to `#call`) returning
    #   the current instant as epoch milliseconds
    attr_reader :clock

    class << self
      # Apple's three pinned roots and the system clock. The roots are the
      # ones compiled into `aprv.wasm`, each checked there against its
      # published SHA-256 fingerprint.
      #
      # @return [Config]
      def defaults
        new
      end
    end

    # @param roots [Array<#to_der, String>, nil] pinned anchors, as
    #   certificate objects (anything answering `#to_der`, such as an
    #   OpenSSL certificate object) or DER strings; Apple's bundled roots
    #   when omitted. A PEM string is refused: parse it into a certificate
    #   object and pass that. An empty Array is not "no roots":
    #   {Verifier.create} refuses it. A string the module does not accept as
    #   a certificate is refused there too.
    # @param clock [#call, nil] the system clock when omitted
    # @raise [ArgumentError] `roots` is not an Array, an entry is neither a
    #   certificate object nor a String, an entry is a PEM String, or `clock`
    #   does not respond to `#call`
    def initialize(roots: nil, clock: nil)
      @custom_roots = !roots.nil?
      @roots = roots.nil? ? none : normalize(roots)
      raise ArgumentError, "clock must respond to #call" if !clock.nil? && !clock.respond_to?(:call)

      @clock = clock || SYSTEM_CLOCK
      freeze
    end

    # Whether the caller chose the roots, as opposed to taking Apple's.
    #
    # @api private
    def custom_roots?
      @custom_roots
    end

    private

    def none
      empty = [] #: Array[String]
      empty.freeze
    end

    def normalize(roots)
      raise ArgumentError, "roots must be an Array" unless roots.is_a?(Array)

      roots.map { |root| der_of(root) }.freeze
    end

    # The bytes the module is given for one root: a certificate object's
    # DER, or a DER String as given. Roots are DER in every package
    # (docs/rust-core/DECISIONS.md R39); a PEM String is recognised only to
    # refuse it. Whether the bytes are a certificate is the
    # module's to say, at `init`.
    def der_of(root)
      return root.to_der.b.freeze if root.respond_to?(:to_der)
      unless root.is_a?(String)
        raise ArgumentError,
              "roots entries must be certificate objects (#to_der) or DER Strings, got #{root.class}"
      end
      if root.b.include?("-----BEGIN")
        raise ArgumentError,
              "roots entries must be certificate objects (#to_der) or DER Strings; " \
              "convert a PEM certificate first (see README)"
      end

      root.b.freeze
    end
  end
end
