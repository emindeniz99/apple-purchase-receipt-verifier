# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Reads a {Config} clock at most once per {Verifier} call, and only when a
  # verdict actually needs it: the chain-validity instant when a receipt's
  # first attribute 12, or a JWS's `signedDate`, is missing or does not
  # parse, and `request_date` at the endpoint. A caller-supplied clock
  # raising, or returning anything but an Integer, is {Reason::INTERNAL_ERROR}
  # — the library's own dependency broke, not the input.
  #
  # @api private
  class ClockOnce
    def initialize(clock)
      @clock = clock
      @read = false
      @millis = nil
    end

    # @return [Integer] epoch milliseconds, the same value on every call
    # @raise [VerificationError] INTERNAL_ERROR when the clock raises or
    #   does not return an Integer
    def millis
      return @millis if @read

      @read = true
      value = begin
        @clock.call
      rescue SystemStackError, StandardError
        raise VerificationError.new(Reason::INTERNAL_ERROR, "the configured clock raised")
      end
      unless value.is_a?(Integer)
        raise VerificationError.new(Reason::INTERNAL_ERROR,
                                    "the configured clock did not return an Integer")
      end

      @millis = value
    end
  end
end
