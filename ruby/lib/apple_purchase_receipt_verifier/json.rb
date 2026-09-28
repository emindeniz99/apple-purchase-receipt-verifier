# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # A bounded, strict RFC 8259 JSON object reader for untrusted text: a JWS
  # header, a JWS payload and the verifyReceipt endpoint's request body. None
  # of the three is behind a signature when it is read.
  #
  # Hand-written rather than `JSON.parse` plus options, because three things
  # a general-purpose parser does not bound by default are exactly what this
  # library's shared cases pin (docs/design/0.7-api.md, Bounds): nesting
  # depth, the digit length of a number and the length of a member name.
  # Byte-oriented throughout: every structural character JSON defines (the
  # brackets, the colon, the comma, the quote, the digits, the escape
  # backslash) is ASCII, and every byte of a multi-byte UTF-8 sequence is
  # 0x80 or above, so scanning bytes never mismatches a structural token —
  # and a raw run sliced between two structural points is itself a valid
  # UTF-8 substring of an input already checked to be one.
  #
  # @api private
  module Json
    class Error < StandardError; end

    # How deep arrays and objects may nest, the outermost one included. 64 in
    # every port.
    MAX_NESTING_DEPTH = 64
    # The longest number, in digits. The Java reference's parser refuses a
    # longer one, so this one does too.
    MAX_NUMBER_DIGITS = 1000
    # The longest member name, in UTF-16 code units, for the same reason.
    MAX_NAME_UTF16_LENGTH = 50_000

    class << self
      # Parses `text`, which must be a whole JSON object: only whitespace may
      # follow the closing brace. Used for a JWS header and a JWS payload,
      # where trailing content is not the document that was signed for.
      #
      # @param text [String]
      # @return [Hash]
      # @raise [Error]
      def parse_whole_object(text)
        reader = Reader.new(text)
        value = reader.read_object
        reader.skip_whitespace
        raise Error, "content after the object" unless reader.eof?

        value
      end

      # Parses the object `text` starts with; anything after its closing
      # brace is not read, Apple's own rule for a verifyReceipt request body.
      # Still bounded and grammar-checked all the way down, including values
      # this reader does not keep.
      #
      # @param text [String]
      # @return [Hash]
      # @raise [Error]
      def parse_leading_object(text)
        Reader.new(text).read_object
      end
    end

    # @api private
    class Reader
      def initialize(text)
        # The bytes decide, not whatever encoding Ruby happened to tag the
        # String with: a base64url-decoded segment or a Rack request body
        # commonly arrives ASCII-8BIT even when every byte is valid UTF-8.
        utf8 = text.dup.force_encoding(Encoding::UTF_8)
        raise Error, "input is not valid UTF-8" unless utf8.valid_encoding?
        raise Error, "input has a byte-order mark" if utf8.b.start_with?("\xEF\xBB\xBF".b)

        @s = utf8
        @i = 0
        @n = text.bytesize
        @depth = 0
      end

      def eof?
        @i >= @n
      end

      def read_object
        skip_whitespace
        value = read_value
        raise Error, "not a JSON object" unless value.is_a?(Hash)

        value
      end

      def skip_whitespace
        while @i < @n
          byte = @s.getbyte(@i)
          case byte
          when 0x20, 0x09, 0x0A, 0x0D then @i += 1
          when 0x00..0x1F then raise Error, "illegal control character"
          else break
          end
        end
      end

      private

      def peek
        @i < @n ? @s.getbyte(@i) : nil
      end

      def next_byte
        raise Error, "unexpected end of input" if @i >= @n

        byte = @s.getbyte(@i)
        @i += 1
        byte
      end

      def expect(byte)
        raise Error, "unexpected character" unless next_byte == byte
      end

      def enter
        @depth += 1
        raise Error, "nesting deeper than #{MAX_NESTING_DEPTH}" if @depth > MAX_NESTING_DEPTH
      end

      def leave
        @depth -= 1
      end

      def read_value
        skip_whitespace
        case peek
        when 0x22 then read_string # '"'
        when 0x7B then read_object_body # '{'
        when 0x5B then read_array # '['
        when 0x74 then read_literal("true", true)
        when 0x66 then read_literal("false", false)
        when 0x6E then read_literal("null", nil)
        when 0x2D, 0x30..0x39 then read_number
        else raise Error, "unexpected character"
        end
      end

      def read_object_body
        @i += 1
        enter
        object = {} #: Hash[String, untyped]
        skip_whitespace
        if peek == 0x7D
          @i += 1
        else
          loop do
            skip_whitespace
            name = read_member_name
            skip_whitespace
            expect(0x3A) # ':'
            skip_whitespace
            object[name] = read_value # last duplicate wins, as a Hash literal would
            skip_whitespace
            byte = next_byte
            break if byte == 0x7D

            raise Error, "expected ',' or '}'" unless byte == 0x2C
          end
        end
        leave
        object
      end

      def read_member_name
        raise Error, "expected a member name" unless peek == 0x22

        name = read_string
        if name.encode(Encoding::UTF_16LE).bytesize / 2 > MAX_NAME_UTF16_LENGTH
          raise Error,
                "member name too long"
        end

        name
      end

      def read_array
        @i += 1
        enter
        array = [] #: Array[untyped]
        skip_whitespace
        if peek == 0x5D
          @i += 1
        else
          loop do
            skip_whitespace
            array << read_value
            skip_whitespace
            byte = next_byte
            break if byte == 0x5D

            raise Error, "expected ',' or ']'" unless byte == 0x2C
          end
        end
        leave
        array
      end

      def read_literal(word, value)
        bytes = word.bytesize
        raise Error, "unrecognized token" unless @s.byteslice(@i, bytes) == word

        @i += bytes
        after = peek
        if after && (ascii_alnum?(after) || after == 0x5F || after >= 0x80)
          raise Error, "unrecognized token"
        end

        value
      end

      def ascii_alnum?(byte)
        (0x30..0x39).cover?(byte) || (0x41..0x5A).cover?(byte) || (0x61..0x7A).cover?(byte)
      end

      def read_number
        start = @i
        @i += 1 if peek == 0x2D
        int_digits = read_digits
        raise Error, "expected a digit" if int_digits.zero?
        if int_digits > 1 && @s.getbyte(@i - int_digits) == 0x30
          raise Error, "leading zeroes are not allowed"
        end

        total = int_digits
        integer = true
        if peek == 0x2E # '.'
          @i += 1
          fraction = read_digits
          raise Error, "expected a digit after the decimal point" if fraction.zero?

          total += fraction
          integer = false
        end
        # rubocop:disable Style/MultipleComparison -- Array#include? needs an
        # Integer, and `peek` is `Integer?`; RBS core's Array#include? has no
        # untyped/nilable overload, so steep would reject that spelling.
        if peek == 0x65 || peek == 0x45 # 'e' / 'E'
          @i += 1
          @i += 1 if peek == 0x2B || peek == 0x2D
          # rubocop:enable Style/MultipleComparison
          exponent = read_digits
          raise Error, "expected a digit in the exponent" if exponent.zero?

          total += exponent
          integer = false
        end
        raise Error, "number too long" if (integer ? int_digits : total) > MAX_NUMBER_DIGITS

        text = @s.byteslice(start, @i - start)
        integer ? text.to_i : text.to_f
      end

      def read_digits
        start = @i
        @i += 1 while peek && (0x30..0x39).cover?(peek)
        @i - start
      end

      def read_string
        @i += 1 # opening quote
        out = +""
        run_start = @i
        loop do
          raise Error, "unterminated string" if @i >= @n

          byte = @s.getbyte(@i)
          case byte
          when 0x22 # '"'
            out << @s.byteslice(run_start, @i - run_start)
            @i += 1
            return out
          when 0x5C # '\\'
            out << @s.byteslice(run_start, @i - run_start)
            @i += 1
            read_escape(out)
            run_start = @i
          when 0x00..0x1F
            raise Error, "unescaped control character in string"
          else
            @i += 1
          end
        end
      end

      ESCAPES = {
        0x22 => '"', 0x5C => "\\", 0x2F => "/", 0x62 => "\b", 0x66 => "\f",
        0x6E => "\n", 0x72 => "\r", 0x74 => "\t"
      }.freeze
      private_constant :ESCAPES

      def read_escape(out)
        byte = next_byte
        if byte == 0x75 # 'u'
          out << read_unicode_escape
          return
        end
        char = ESCAPES[byte]
        raise Error, "unrecognized escape" if char.nil?

        out << char
      end

      def read_unicode_escape
        unit = read_hex4
        if (0xD800..0xDBFF).cover?(unit) && @s.byteslice(@i, 2) == "\\u"
          saved = @i
          @i += 2
          low = read_hex4
          if (0xDC00..0xDFFF).cover?(low)
            code = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            return [code].pack("U")
          end
          @i = saved
        end
        # A lone surrogate, as an unpaired \uD800-\uDFFF is, becomes U+FFFD:
        # `String#pack("U")` cannot hold a surrogate scalar value at all.
        return "\u{FFFD}" if (0xD800..0xDFFF).cover?(unit)

        [unit].pack("U")
      end

      def read_hex4
        value = 0
        4.times do
          byte = next_byte
          digit = HEX_DIGIT[byte]
          raise Error, "bad unicode escape" if digit.nil?

          value = (value * 16) + digit
        end
        value
      end

      hex_digit_table = {} #: Hash[Integer, Integer]
      HEX_DIGIT = hex_digit_table.tap do |table|
        "0123456789abcdef".each_byte.with_index { |b, v| table[b] = v }
        "ABCDEF".each_byte.with_index { |b, v| table[b] = v + 10 }
      end.freeze
      private_constant :HEX_DIGIT
    end
  end
end
