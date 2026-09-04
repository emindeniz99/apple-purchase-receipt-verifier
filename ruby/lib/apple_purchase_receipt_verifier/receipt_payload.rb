# frozen_string_literal: true

require "time"

module ApplePurchaseReceiptVerifier
  # One in-app purchase decoded from a legacy app receipt (attribute 17).
  # Dates are `Time` in UTC — receipt attributes are the half of the API that
  # carries native times; JWS claims stay epoch-millisecond Integers.
  class InAppPurchase
    ATTRIBUTES = %i[quantity product_id transaction_id original_transaction_id purchase_date
                    original_purchase_date expires_date cancellation_date web_order_line_item_id
                    is_in_intro_offer_period unknown_attributes].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(fields)
      ATTRIBUTES.each { |name| instance_variable_set(:"@#{name}", fields[name]) }
      freeze
    end

    def to_h
      ATTRIBUTES.to_h { |name| [name.to_s, public_send(name)] }
    end

    def inspect
      "#<#{self.class.name} product_id=#{product_id.inspect} " \
        "transaction_id=#{transaction_id.inspect}>"
    end
  end

  # A verified legacy app receipt. Only receipts returned by {ReceiptVerifier}
  # or {ApplePurchaseReceiptVerifier.verify_receipt_core} should be trusted.
  class AppReceipt
    ATTRIBUTES = %i[receipt_type bundle_id bundle_id_bytes app_version opaque_value sha1_hash
                    creation_date original_purchase_date original_app_version expiration_date
                    in_app_purchases unknown_attributes].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(fields)
      ATTRIBUTES.each { |name| instance_variable_set(:"@#{name}", fields[name]) }
      freeze
    end

    def to_h
      ATTRIBUTES.to_h { |name| [name.to_s, public_send(name)] }
    end

    def inspect
      "#<#{self.class.name} bundle_id=#{bundle_id.inspect} " \
        "in_app_purchases=#{in_app_purchases.size}>"
    end
  end

  # The receipt payload attribute grammar (Apple, "Validating receipts on the
  # device"). Strict, offset-based DER: the verified bytes go in, the modelled
  # fields come out, and anything the grammar cannot represent is rejected
  # rather than repaired.
  #
  # @api private
  module ReceiptPayload
    RECEIPT_TYPE           = 0
    BUNDLE_ID              = 2
    APP_VERSION            = 3
    OPAQUE_VALUE           = 4
    SHA1_HASH              = 5
    CREATION_DATE          = 12
    IN_APP                 = 17
    ORIGINAL_PURCHASE_DATE = 18
    ORIGINAL_APP_VERSION   = 19
    EXPIRATION_DATE        = 21

    IAP_QUANTITY                 = 1701
    IAP_PRODUCT_ID               = 1702
    IAP_TRANSACTION_ID           = 1703
    IAP_PURCHASE_DATE            = 1704
    IAP_ORIGINAL_TRANSACTION_ID  = 1705
    IAP_ORIGINAL_PURCHASE_DATE   = 1706
    IAP_EXPIRES_DATE             = 1708
    IAP_WEB_ORDER_LINE_ITEM_ID   = 1711
    IAP_CANCELLATION_DATE        = 1712
    IAP_IS_IN_INTRO_OFFER_PERIOD = 1719

    # Attribute *types* live in a 32-bit signed space. Every type Apple has
    # ever issued is a small number, and a value above 2^31-1 cannot be
    # represented by ports whose type field is an int. Java once mapped such a
    # type onto -1 and filed it under unknownAttributes, which collides every
    # oversized type into one bucket keyed by a value that is not a type; the
    # cross-port contract now says reject. Attribute *values* keep the wider
    # range — web_order_line_item_id is genuinely a 7-byte integer.
    MAX_ATTRIBUTE_TYPE = 2_147_483_647

    # A ceiling on attributes per set. The largest genuine receipt known to
    # this project carries 196 at the top level and 11 per purchase.
    MAX_ATTRIBUTES = 100_000

    # Fractional seconds are read to the nanosecond and no further.
    #
    # The digit run is unbounded in the grammar and no structural budget covers
    # it: `Asn1::MAX_NODES`, `MAX_ATTRIBUTES` and `MAX_DEPTH` all count
    # elements, never the cost of one. Turning the run into an exact `Rational`
    # is superlinear in its length, and `parse` runs before the
    # embedded-certificate bound, the chain walk and the signature check — so a
    # blob carrying no signature at all bought seconds of CPU. A nanosecond is
    # the finest precision any port represents (java's `Instant.parse` ceiling;
    # node truncates to milliseconds, python to microseconds), so nothing
    # observable through this API is lost.
    NANOSECOND_DIGITS = 9

    # RFC 3339 with a mandatory timezone designator. A naive date would be read
    # as the server's local time, and the creation date is the instant the
    # chain's validity is judged at — the same receipt would verify on one host
    # and fail on another.
    RFC_3339 = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))\z/

    class << self
      # @param content [String] the verified encapsulated content bytes
      # @return [AppReceipt]
      def parse(content)
        fields = {
          receipt_type: nil, bundle_id: nil, bundle_id_bytes: nil, app_version: nil,
          opaque_value: nil, sha1_hash: nil, creation_date: nil, original_purchase_date: nil,
          original_app_version: nil, expiration_date: nil
        }
        purchases = []
        unknown = {}

        each_attribute(content, "receipt payload") do |type, value|
          case type
          when RECEIPT_TYPE then fields[:receipt_type] = decode_string(value)
          when BUNDLE_ID
            fields[:bundle_id] = decode_string(value)
            fields[:bundle_id_bytes] = value.dup.freeze
          when APP_VERSION            then fields[:app_version] = decode_string(value)
          when OPAQUE_VALUE           then fields[:opaque_value] = value.dup.freeze
          when SHA1_HASH              then fields[:sha1_hash] = value.dup.freeze
          when CREATION_DATE          then fields[:creation_date] = decode_date(value)
          when IN_APP                 then purchases << parse_in_app(value)
          when ORIGINAL_PURCHASE_DATE then fields[:original_purchase_date] = decode_date(value)
          when ORIGINAL_APP_VERSION   then fields[:original_app_version] = decode_string(value)
          when EXPIRATION_DATE        then fields[:expiration_date] = decode_date(value)
          else record_unknown(unknown, type, value)
          end
        end

        fields[:in_app_purchases] = purchases.freeze
        fields[:unknown_attributes] = freeze_unknown(unknown)
        AppReceipt.new(fields)
      end

      private

      def parse_in_app(bytes)
        fields = {
          quantity: nil, product_id: nil, transaction_id: nil, original_transaction_id: nil,
          purchase_date: nil, original_purchase_date: nil, expires_date: nil,
          cancellation_date: nil, web_order_line_item_id: nil, is_in_intro_offer_period: nil
        }
        unknown = {}

        each_attribute(bytes, "in-app purchase attribute") do |type, value|
          case type
          when IAP_QUANTITY                 then fields[:quantity] = decode_integer(value)
          when IAP_PRODUCT_ID               then fields[:product_id] = decode_string(value)
          when IAP_TRANSACTION_ID           then fields[:transaction_id] = decode_string(value)
          when IAP_PURCHASE_DATE            then fields[:purchase_date] = decode_date(value)
          when IAP_ORIGINAL_TRANSACTION_ID
            fields[:original_transaction_id] = decode_string(value)
          when IAP_ORIGINAL_PURCHASE_DATE   then fields[:original_purchase_date] = decode_date(value)
          when IAP_EXPIRES_DATE             then fields[:expires_date] = decode_date(value)
          when IAP_WEB_ORDER_LINE_ITEM_ID
            fields[:web_order_line_item_id] = decode_integer(value)
          when IAP_CANCELLATION_DATE        then fields[:cancellation_date] = decode_date(value)
          when IAP_IS_IN_INTRO_OFFER_PERIOD
            fields[:is_in_intro_offer_period] = decode_integer(value)
          else record_unknown(unknown, type, value)
          end
        end

        fields[:unknown_attributes] = freeze_unknown(unknown)
        InAppPurchase.new(fields)
      end

      def record_unknown(unknown, type, value)
        (unknown[type] ||= []) << value.dup.freeze
      end

      def freeze_unknown(unknown)
        unknown.each_value(&:freeze)
        unknown.freeze
      end

      # Walks `SET OF SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }`,
      # yielding [type, value bytes].
      #
      # Offsets only. There is no node tree, no slice per structural element
      # and — decisively — no recursion: the grammar is exactly two levels
      # deep, so the walk validates as it goes and needs no separate bounded
      # pre-scan. Building a tree here instead cost 36 ms on the 187-purchase
      # legacy receipt against 6 ms for this.
      def each_attribute(bytes, what)
        tag, start, finish = outer(bytes, what)

        if [Asn1::TAG_OCTET_STRING, Asn1::TAG_OCTET_STRING_BER].include?(tag)
          # Xcode receipts double-wrap the payload in an extra OCTET STRING.
          bytes = if tag == Asn1::TAG_OCTET_STRING
                    bytes.byteslice(start, finish - start)
                  else
                    ber_octets(bytes, what)
                  end
          tag, start, finish = outer(bytes, what)
        end

        raise format_error("#{what} is not an ASN.1 SET") unless tag == Asn1::TAG_SET

        position = start
        seen = 0
        while position < finish
          seen += 1
          raise format_error("#{what} carries too many attributes") if seen > MAX_ATTRIBUTES

          sequence_tag, sequence_start, sequence_end, after = header(bytes, position, finish, what)
          raise format_error("malformed receipt attribute") unless sequence_tag == Asn1::TAG_SEQUENCE

          type_tag, type_start, type_end, cursor = header(bytes, sequence_start, sequence_end, what)
          raise format_error("malformed receipt attribute") unless type_tag == Asn1::TAG_INTEGER

          # version, present and skipped
          _, _, _, cursor = header(bytes, cursor, sequence_end, what)
          value_tag, value_start, value_end, = header(bytes, cursor, sequence_end, what)
          unless [Asn1::TAG_OCTET_STRING, Asn1::TAG_OCTET_STRING_BER].include?(value_tag)
            raise format_error("malformed receipt attribute")
          end

          value =
            if value_tag == Asn1::TAG_OCTET_STRING
              bytes.byteslice(value_start, value_end - value_start)
            else
              # The VALUE's own TLV, not the attribute SEQUENCE that contains
              # it: `position`/`after` bound the SEQUENCE, and handing those to
              # `ber_octets` made this branch reject every input it exists to
              # accept, with a message naming the wrong object.
              ber_octets(bytes.byteslice(cursor, value_end - cursor), "receipt attribute value")
            end

          yield attribute_type(bytes.byteslice(type_start, type_end - type_start)), value
          position = after
        end
      end

      # Reads the one TLV that must span the whole buffer.
      def outer(bytes, what)
        tag, start, finish, after = header(bytes, 0, bytes.bytesize, what)
        raise format_error("trailing bytes after #{what}") unless after == bytes.bytesize

        [tag, start, finish]
      end

      # One definite-length TLV header, fully bounds-checked against `limit`.
      # Indefinite lengths, multi-byte tags and length fields wider than four
      # octets are refused rather than interpreted.
      def header(bytes, offset, limit, what)
        raise format_error("truncated #{what}") if offset + 2 > limit

        tag = bytes.getbyte(offset)
        raise format_error("multi-byte ASN.1 tag in #{what}") if (tag & 0x1F) == 0x1F

        position = offset + 1
        length_byte = bytes.getbyte(position)
        position += 1
        if length_byte == 0x80
          raise format_error("indefinite length in #{what}")
        elsif length_byte < 0x80
          length = length_byte
        else
          count = length_byte & 0x7F
          raise format_error("unsupported ASN.1 length in #{what}") if count > 4
          raise format_error("truncated #{what}") if position + count > limit

          length = 0
          count.times do
            length = (length << 8) | bytes.getbyte(position)
            position += 1
          end
        end

        finish = position + length
        raise format_error("#{what} value overruns its parent") if finish > limit

        [tag, position, finish, finish]
      end

      # The one place BER chunking can appear: a constructed OCTET STRING.
      # Rare enough to take the general bounded parser rather than a second
      # hand-written loop.
      def ber_octets(bytes, what)
        node = Asn1.parse(bytes)
        raise format_error("#{what} is not an OCTET STRING") unless node.octet_string?

        node.octet_value
      rescue Asn1::Error => e
        raise format_error("#{what} is not valid ASN.1 (#{e.message})")
      end

      def attribute_type(raw)
        type = integer_value(raw)
        return type unless type > MAX_ATTRIBUTE_TYPE

        raise format_error("receipt attribute type exceeds the 32-bit signed range")
      end

      def integer_value(raw)
        raise format_error("attribute integer out of range") if raw.bytesize > 8
        raise format_error("empty receipt integer") if raw.empty?
        raise format_error("negative receipt integer") if raw.getbyte(0) >= 0x80

        value = 0
        raw.each_byte { |byte| value = (value << 8) | byte }
        value
      end

      def single_value(bytes)
        Asn1.read_single(bytes)
      rescue Asn1::Error => e
        raise format_error("attribute value is not valid ASN.1 (#{e.message})")
      end

      def decode_string(bytes)
        tag, content = single_value(bytes)
        unless [Asn1::TAG_UTF8_STRING, Asn1::TAG_IA5_STRING].include?(tag)
          raise format_error("attribute value is not an ASN.1 string")
        end

        text = content.force_encoding(Encoding::UTF_8)
        raise format_error("attribute value is not valid UTF-8") unless text.valid_encoding?

        text.freeze
      end

      def decode_integer(bytes)
        tag, content = single_value(bytes)
        raise format_error("attribute value is not an ASN.1 integer") unless tag == Asn1::TAG_INTEGER

        integer_value(content)
      end

      # An empty string means "absent", which genuine receipts do.
      #
      # Built from the captures rather than through `Time.iso8601`: the parse
      # runs once per date and the largest genuine receipt carries 748 of them,
      # where the difference is measurable. The timezone designator stays
      # mandatory — a naive date would be read as the server's local time, and
      # this is the instant the chain's validity is judged at, so the same
      # receipt would verify on one host and fail on another.
      def decode_date(bytes)
        text = decode_string(bytes)
        return nil if text.empty?

        match = RFC_3339.match(text)
        raise format_error("unparseable receipt date") unless match

        year, month, day, hour, minute, second = (1..6).map { |i| match[i].to_i }

        # A leap second. node, python and swift reject it and java clamps it
        # back to :59; Ruby's `Time` would roll it FORWARD into the next
        # minute, which is the one answer no other port gives. This is the
        # instant the chain's validity is judged at, so it is refused rather
        # than repaired.
        raise format_error("unparseable receipt date") if second > 59

        begin
          time = Time.utc(year, month, day, hour, minute, second,
                          Rational(nanoseconds(match[7]), 1000))
        rescue ArgumentError, RangeError
          raise format_error("unparseable receipt date")
        end
        return time if match[8].nil?

        offset_hours = match[9].to_i
        offset_minutes = match[10].to_i

        # The offset is arithmetic on that same instant, and unchecked it moves
        # it a long way: `+99:99` is four days and change. node, java, python
        # and swift all refuse an hour field of 24 or more, and node, java and
        # swift refuse a minute field of 60 or more (python is the outlier that
        # accepts it).
        raise format_error("unparseable receipt date") if offset_hours > 23 || offset_minutes > 59

        offset = ((offset_hours * 3600) + (offset_minutes * 60)) * (match[8] == "-" ? -1 : 1)
        (time - offset).utc
      end

      def nanoseconds(fraction)
        return 0 if fraction.nil?

        fraction.byteslice(1, NANOSECOND_DIGITS).ljust(NANOSECOND_DIGITS, "0").to_i
      end

      def format_error(message)
        VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, message)
      end
    end
  end
end
