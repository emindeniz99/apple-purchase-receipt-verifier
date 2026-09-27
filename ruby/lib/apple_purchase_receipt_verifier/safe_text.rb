# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Quotes a piece of untrusted input for embedding in a {Failure} message,
  # so the message stays safe to write into a log line as is
  # (docs/design/0.7-api.md, Result).
  #
  # Deliberately not `String#inspect`: MRI's choice of which characters
  # count as "non-printable" there depends on `Encoding.default_external`
  # (measured — the same input quotes every C0/C1/bidi character on a POSIX
  # locale and leaves a right-to-left override character raw on a UTF-8
  # one), so a message built with it is only as safe as whatever locale the
  # process happens to run under. This module escapes a fixed set of code
  # points regardless of locale: C0 controls, DEL, C1 controls, the
  # line/paragraph separators and the bidi format characters (Arabic Letter
  # Mark, LRM/RLM, the embedding/override pair and the isolate pair).
  #
  # @api private
  module SafeText
    # A ceiling on how much of the input one message quotes.
    MAX_LENGTH = 200

    class << self
      # @param value [#to_s]
      # @return [String] double-quoted
      def quote(value)
        text = value.to_s
        truncated = text.length > MAX_LENGTH
        text = text[0, MAX_LENGTH] if truncated

        out = +"\""
        text.each_char do |char|
          case char
          when "\"" then out << "\\\""
          when "\\" then out << "\\\\"
          else
            code = char.ord
            unsafe?(code) ? (out << format("\\u%04x", code)) : (out << char)
          end
        end
        out << "…" if truncated
        out << "\""
      end

      private

      def unsafe?(code)
        code < 0x20 || code == 0x7F || (0x80..0x9F).cover?(code) ||
          code == 0x2028 || code == 0x2029 || code == 0x061C ||
          (0x200E..0x200F).cover?(code) || (0x202A..0x202E).cover?(code) ||
          (0x2066..0x2069).cover?(code)
      end
    end
  end
end
