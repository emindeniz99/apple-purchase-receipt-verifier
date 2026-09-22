# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # @api private
  #
  # The one JSON reader for untrusted text: the verifyReceipt request body and
  # the JWS header and payload.
  module JsonLimits
    # How deep arrays and objects may nest; the Java port's number. Every
    # document read here is a flat or near-flat object.
    MAX_NESTING_DEPTH = 64

    class << self
      # `JSON.parse` with the nesting depth held to {MAX_NESTING_DEPTH}.
      #
      # `max_nesting:` alone does not say it the same way on every json gem
      # the supported Rubies ship. It stops the parser as it descends, so the
      # parser never recurses past it, but on json 2.21 and 3.0 an EMPTY
      # innermost array or object is not counted: 65 levels ending in `[]`
      # parse, 65 ending in `[1]` do not, while json 2.7.2 (Ruby 3.3's
      # default) refuses both. Measured, not assumed. The walk
      # below counts every container, so the answer is the same on every
      # version, and it runs over a structure the parser has already bounded
      # to 65 levels.
      #
      # @param text [String]
      # @return [Object]
      # @raise [JSON::ParserError] unparseable, or nested too deep
      #   (JSON::NestingError is a JSON::ParserError)
      def parse(text)
        parsed = JSON.parse(text, max_nesting: MAX_NESTING_DEPTH)
        if depth(parsed) > MAX_NESTING_DEPTH
          raise JSON::NestingError, "nesting of #{MAX_NESTING_DEPTH + 1} is too deep"
        end

        parsed
      end

      private

      def depth(value)
        case value
        when Hash then 1 + (value.each_value.map { |child| depth(child) }.max || 0)
        when Array then 1 + (value.map { |child| depth(child) }.max || 0)
        else 0
        end
      end
    end
  end
end
