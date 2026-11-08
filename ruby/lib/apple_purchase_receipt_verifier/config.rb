# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # One certificate to refuse, named by its revocation key: the issuer id of
  # the certificate that issued it and its serial number, both in hex.
  # {Verifier.create} hands both strings to the module, which checks and
  # normalises them; this value holds them exactly as given.
  #
  # @!attribute [r] issuer
  #   @return [String] the SHA-256, in hex (64 digits, either case), of the
  #     issuing certificate's subject Name followed by its
  #     subjectPublicKeyInfo, both as encoded in that certificate
  # @!attribute [r] serial
  #   @return [String] the revoked certificate's serial number in hex,
  #     either case, with or without leading zeros
  RevokedCertificate = Data.define(:issuer, :serial)

  # Immutable {Verifier} configuration: the pinned trust anchors, the
  # revocation settings and the clock.
  #
  # The clock answers "what time is it now?" and nothing else. The library
  # reads it once per call, before it looks at the input, and passes the
  # value to the module, which uses it for the certificate-validity instant
  # when the receipt or JWS carries no usable signing date, for
  # `request_date` in the endpoint response, and to judge whether a
  # revocation list holding a `certificateHold` entry is still fresh. A clock that
  # raises, or answers anything but an Integer in 0..2**63-1, makes the call
  # INTERNAL_ERROR. A caller-supplied clock must be safe to call from several
  # threads.
  #
  #   Config.new                                        # Apple's pinned roots + the system clock
  #   Config.new(roots: my_roots, clock: -> { Time.now.to_i * 1000 })
  #   Config.new(revocation_lists: [crl_der])           # Apple's lists, downloaded by the caller
  class Config
    # A proc reading the system clock, epoch milliseconds: the {#clock} of a
    # Config given no `clock:`.
    SYSTEM_CLOCK = -> { (Time.now.to_r * 1000).to_i }

    # @return [Array<String>] the caller's pinned trust anchors as frozen
    #   binary Strings, DER or PEM as given; empty for `Config.new`, whose
    #   three Apple roots are compiled into the module and pinned there
    attr_reader :roots

    # @return [#call] a proc (or any object responding to `#call`) returning
    #   the current instant as epoch milliseconds
    attr_reader :clock

    # @return [Array<String>] the revocation lists as frozen binary Strings,
    #   in the order given; empty when none
    attr_reader :revocation_lists

    # @return [Array<String>] the added revocation issuers as frozen binary
    #   Strings, DER or PEM as given; empty when none
    attr_reader :revocation_issuers

    # @return [Array<RevokedCertificate>] the distrust entries, in the order
    #   given; empty when none
    attr_reader :distrust

    # @param roots [Array<#to_der, String>, nil] pinned anchors, as
    #   certificate objects (anything answering `#to_der`, such as an
    #   OpenSSL certificate object) or Strings of DER or PEM bytes, which the
    #   module tells apart (a PEM bundle of several certificates is one
    #   entry); Apple's bundled roots when omitted, the ones compiled into
    #   `aprv.wasm` and checked there against their published SHA-256
    #   fingerprints. An empty Array is not "no roots":
    #   {Verifier.create} refuses it. A string the module does not accept as
    #   a certificate is refused there too.
    # @param clock [#call, nil] the system clock when omitted
    # @param revocation_lists [Array<String>, nil] certificate revocation
    #   lists (CRLs) exactly as downloaded (DER), in any order: at most 16,
    #   each at most 1 MiB. The URLs to download are
    #   {Verifier#revocation_urls}. {Verifier.create} refuses a list that is
    #   not a CRL, is signed by no issuer the verifier knows, or is older
    #   than the one this release was built with; a genuine list in a form
    #   the module does not support is ignored. None when omitted: the list
    #   built into the module and `distrust` still apply.
    # @param revocation_issuers [Array<#to_der, String>, nil] CA certificates
    #   that sign revocation lists, added to the ones built into the module
    #   (a new Apple intermediate, or a test PKI's), in the same forms as
    #   `roots`; each must chain to a configured root
    # @param distrust [Array<RevokedCertificate, Array(String, String)>, nil]
    #   revocation keys to refuse, at most 1,000, as {RevokedCertificate}s or
    #   `[issuer, serial]` pairs of Strings
    # @raise [ArgumentError] `roots` is not an Array, an entry is neither a
    #   certificate object nor a String, `clock` does not respond to
    #   `#call`, or a revocation setting is not an Array of the types above
    def initialize(roots: nil, clock: nil, revocation_lists: nil, revocation_issuers: nil, distrust: nil)
      @custom_roots = !roots.nil?
      @roots = roots.nil? ? none : normalize(roots)
      raise ArgumentError, "clock must respond to #call" if !clock.nil? && !clock.respond_to?(:call)

      @clock = clock || SYSTEM_CLOCK
      @revocation_lists = lists_of(revocation_lists)
      @revocation_issuers =
        revocation_issuers.nil? ? none : normalize(revocation_issuers, "revocation_issuers")
      @distrust = distrust_of(distrust)
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

    def normalize(roots, name = "roots")
      raise ArgumentError, "#{name} must be an Array" unless roots.is_a?(Array)

      roots.map { |root| bytes_of(root, name) }.freeze
    end

    # The lists as given, as frozen binary copies: whether each is a CRL is
    # the module's to say, at `init`.
    def lists_of(lists)
      return none if lists.nil?
      raise ArgumentError, "revocation_lists must be an Array" unless lists.is_a?(Array)

      lists.map do |list|
        unless list.is_a?(String)
          raise ArgumentError, "revocation_lists entries must be Strings of DER bytes, got #{list.class}"
        end

        list.b.freeze
      end.freeze
    end

    # Each entry as a {RevokedCertificate} holding its two Strings as given;
    # whether they are hex is the module's to say, at `init`.
    def distrust_of(entries)
      if entries.nil?
        empty = [] #: Array[RevokedCertificate]
        return empty.freeze
      end
      raise ArgumentError, "distrust must be an Array" unless entries.is_a?(Array)

      entries.map do |entry|
        issuer, serial = entry.is_a?(RevokedCertificate) ? [entry.issuer, entry.serial] : entry
        unless (entry.is_a?(RevokedCertificate) || (entry.is_a?(Array) && entry.size == 2)) &&
               issuer.is_a?(String) && serial.is_a?(String)
          raise ArgumentError,
                "distrust entries must be RevokedCertificate values or [issuer, serial] pairs of Strings"
        end

        RevokedCertificate.new(issuer: text(issuer), serial: text(serial))
      end.freeze
    end

    # A distrust String as UTF-8 text, the form JSON can carry to the module.
    def text(value)
      utf8 = value.dup.force_encoding(Encoding::UTF_8)
      raise ArgumentError, "distrust issuer and serial must be UTF-8 text" unless utf8.valid_encoding?

      utf8.freeze
    end

    # The bytes the module is given for one root: a certificate object's
    # DER, or a String as given. The module reads DER or PEM and tells them
    # apart (docs/rust-core/DECISIONS.md R39); whether the bytes are a
    # certificate is the module's to say, at `init`.
    def bytes_of(root, name)
      return root.to_der.b.freeze if root.respond_to?(:to_der)
      unless root.is_a?(String)
        raise ArgumentError,
              "#{name} entries must be certificate objects (#to_der) or Strings of DER or PEM bytes, " \
              "got #{root.class}"
      end

      root.b.freeze
    end
  end
end
