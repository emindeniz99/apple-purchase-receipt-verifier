# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # A hand-written JSON object writer for the two bytes-pinned outputs this
  # library produces: {ReceiptPayload#to_json} and the verifyReceipt-shaped
  # response {Verifier#verify_receipt_endpoint} renders. Builds the string
  # directly rather than through `JSON.generate`, so key order is exactly
  # what the code below writes (never a Hash's) and string escaping is
  # exactly the design's rule, not the `json` gem's.
  #
  # Canonical form (docs/design/0.7-api.md, "Our JSON"): no whitespace, UTF-8,
  # and strings escaped exactly as ECMAScript `JSON.stringify` escapes them:
  # `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t` as short escapes, every other
  # character from U+0000 to U+001F as `\u00xx` in lowercase hex, and nothing
  # else — `/` is not escaped, and non-ASCII characters, U+2028 and U+2029
  # included, are written raw.
  #
  # @api private
  class CanonicalJson
    def initialize
      @out = +""
      @first = [true]
    end

    def to_s
      @out
    end

    def object
      @out << "{"
      @first.push(true)
      yield self
      @first.pop
      @out << "}"
      self
    end

    def array
      @out << "["
      @first.push(true)
      yield self
      @first.pop
      @out << "]"
      self
    end

    def key(name)
      comma
      quote(name)
      @out << ":"
    end

    def string(key_name, value)
      key(key_name)
      value.nil? ? (@out << "null") : quote(value)
    end

    def number(key_name, value)
      key(key_name)
      @out << (value.nil? ? "null" : value.to_s)
    end

    # A 64-bit id, as a JSON string so a JavaScript reader does not round it.
    def id(key_name, value)
      string(key_name, value&.to_s)
    end

    def boolean(key_name, value)
      key(key_name)
      @out << (value.nil? ? "null" : value.to_s)
    end

    def bytes(key_name, value)
      string(key_name, value.nil? ? nil : [value].pack("m0"))
    end

    def raw_value
      comma
      yield self
    end

    def comma
      @out << "," unless @first.last
      @first[-1] = false
    end

    HEX = "0123456789abcdef"
    private_constant :HEX

    def quote(value)
      @out << '"'
      value.each_char do |c|
        case c
        when '"' then @out << '\\"'
        when "\\" then @out << "\\\\"
        when "\b" then @out << "\\b"
        when "\f" then @out << "\\f"
        when "\n" then @out << "\\n"
        when "\r" then @out << "\\r"
        when "\t" then @out << "\\t"
        else
          code = c.ord
          if code < 0x20
            @out << "\\u00" << HEX[code >> 4] << HEX[code & 0xF]
          else
            @out << c
          end
        end
      end
      @out << '"'
      self
    end
  end
end
