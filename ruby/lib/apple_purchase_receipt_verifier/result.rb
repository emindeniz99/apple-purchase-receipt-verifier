# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Why a verification is not verified. `message` is safe to log — it never
  # embeds raw input, and control characters and bidi controls in anything
  # quoted from the input are neutralised — but is not meant to be parsed;
  # match on {#reason} instead, the text may change between releases.
  #
  # @!attribute [r] reason
  #   @return [Symbol] one of {Reason::ALL}
  # @!attribute [r] message
  #   @return [String] safe to log, not meant to be parsed
  # @!attribute [r] cause
  #   @return [Exception, nil] the exception behind an
  #     {Reason::INTERNAL_ERROR} the gem produced itself, when the module
  #     trapped or gave an answer the gem could not read; nil for every
  #     verdict the module gives, {Reason::UNREADABLE_PAYLOAD} included
  Failure = Data.define(:reason, :message, :cause)

  # The outcome of one {Verifier} call: `verified?` and, exclusively, either
  # {#payload} or {#failure}.
  #
  # @!attribute [r] verified
  #   @return [Boolean] whether the input verified
  # @!attribute [r] payload
  #   @return [ReceiptPayload, JsonPayload, nil] set only when {#verified?}
  # @!attribute [r] failure
  #   @return [Failure, nil] set only when not {#verified?}
  VerificationResult = Data.define(:verified, :payload, :failure) do
    # @return [Boolean]
    def verified? # steep:ignore UndeclaredMethodDefinition
      # @type self: VerificationResult
      verified
    end

    class << self
      # @api private
      def ok(payload)
        # @type self: singleton(VerificationResult)
        new(verified: true, payload: payload, failure: nil)
      end

      # @api private
      def error(failure)
        # @type self: singleton(VerificationResult)
        new(verified: false, payload: nil, failure: failure)
      end
    end
  end
end
