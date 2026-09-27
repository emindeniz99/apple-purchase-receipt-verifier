# frozen_string_literal: true

require "time"
require_relative "canonical_json"

module ApplePurchaseReceiptVerifier
  # One in-app purchase decoded from a legacy app receipt (attribute 17).
  # Dates are epoch milliseconds, UTC, with an `_ms` suffix — the JWS half of
  # this API returns Apple's own claims the same way (docs/design/0.7-api.md).
  #
  # Public so callers can build one by hand in their own tests. Only a value
  # returned by {Verifier#verify_receipt} came from a receipt whose chain and
  # signature passed.
  InAppPurchase = Data.define(
    :quantity, :product_id, :transaction_id, :purchase_date_ms, :original_transaction_id,
    :original_purchase_date_ms, :expires_date_ms, :web_order_line_item_id, :cancellation_date_ms,
    :is_trial_period, :is_in_intro_offer_period, :unknown_attributes
  ) do
    # @api private
    def write_json(json) # steep:ignore UndeclaredMethodDefinition
      # @type self: InAppPurchase
      json.object do |o|
        o.number("quantity", quantity)
        o.string("product_id", product_id)
        o.string("transaction_id", transaction_id)
        o.number("purchase_date_ms", purchase_date_ms)
        o.string("original_transaction_id", original_transaction_id)
        o.number("original_purchase_date_ms", original_purchase_date_ms)
        o.number("expires_date_ms", expires_date_ms)
        o.id("web_order_line_item_id", web_order_line_item_id)
        o.number("cancellation_date_ms", cancellation_date_ms)
        o.boolean("is_trial_period", is_trial_period)
        o.boolean("is_in_intro_offer_period", is_in_intro_offer_period)
        ReceiptAttributes.write_unknown_attributes(o, unknown_attributes)
      end
    end
  end

  # A verified legacy app receipt — the payload of {Verifier#verify_receipt}.
  # Field names are Apple's own words from the verifyReceipt response
  # (docs/design/0.7-api.md): a caller reading {#to_json}, these readers and
  # Apple's documentation sees one vocabulary.
  #
  # Public so callers can build one by hand in their own tests. Only a value
  # returned by {Verifier#verify_receipt} came from a receipt whose chain and
  # signature passed.
  ReceiptPayload = Data.define(
    :receipt_type, :app_item_id, :bundle_id, :bundle_id_bytes, :application_version,
    :opaque_value, :sha1_hash, :receipt_creation_date_ms, :download_id,
    :version_external_identifier, :in_app, :original_purchase_date_ms,
    :original_application_version, :expiration_date_ms, :unknown_attributes
  ) do
    # The canonical JSON every port produces byte for byte, for logging and
    # storage (docs/design/0.7-api.md, "Our JSON"): the fields in the design's
    # order, no whitespace, `null` for a missing field, 64-bit ids as JSON
    # strings, bytes as padded standard base64, `unknown_attributes` keys in
    # ascending numeric order with each key's values in receipt order, and
    # strings escaped as ECMAScript `JSON.stringify` escapes them.
    #
    # @return [String]
    def to_json(*)
      # @type self: ReceiptPayload
      json = CanonicalJson.new
      json.object do |o|
        o.string("receipt_type", receipt_type)
        o.id("app_item_id", app_item_id)
        o.string("bundle_id", bundle_id)
        o.bytes("bundle_id_bytes", bundle_id_bytes)
        o.string("application_version", application_version)
        o.bytes("opaque_value", opaque_value)
        o.bytes("sha1_hash", sha1_hash)
        o.number("receipt_creation_date_ms", receipt_creation_date_ms)
        o.id("download_id", download_id)
        o.id("version_external_identifier", version_external_identifier)
        o.key("in_app")
        o.array { |a| in_app.each { |purchase| a.raw_value { purchase.write_json(a) } } }
        o.number("original_purchase_date_ms", original_purchase_date_ms)
        o.string("original_application_version", original_application_version)
        o.number("expiration_date_ms", expiration_date_ms)
        ReceiptAttributes.write_unknown_attributes(o, unknown_attributes)
      end
      json.to_s
    end
  end

  # The receipt payload attribute grammar (Apple, "Validating receipts on the
  # device") and its decode rules (docs/design/0.7-api.md): strict,
  # offset-based DER — the verified bytes go in, {ReceiptPayload} comes out,
  # and anything the grammar cannot represent is rejected rather than
  # repaired.
  #
  # @api private
  module ReceiptAttributes
    RECEIPT_TYPE                = 0
    APP_ITEM_ID                 = 1
    BUNDLE_ID                   = 2
    APP_VERSION                 = 3
    OPAQUE_VALUE                = 4
    SHA1_HASH                   = 5
    CREATION_DATE = 12
    DOWNLOAD_ID                 = 15
    VERSION_EXTERNAL_IDENTIFIER = 16
    IN_APP                      = 17
    ORIGINAL_PURCHASE_DATE      = 18
    ORIGINAL_APP_VERSION        = 19
    EXPIRATION_DATE             = 21

    IAP_QUANTITY                 = 1701
    IAP_PRODUCT_ID               = 1702
    IAP_TRANSACTION_ID           = 1703
    IAP_PURCHASE_DATE            = 1704
    IAP_ORIGINAL_TRANSACTION_ID  = 1705
    IAP_ORIGINAL_PURCHASE_DATE   = 1706
    IAP_EXPIRES_DATE             = 1708
    IAP_WEB_ORDER_LINE_ITEM_ID   = 1711
    IAP_CANCELLATION_DATE        = 1712
    IAP_IS_TRIAL_PERIOD          = 1713
    IAP_IS_IN_INTRO_OFFER_PERIOD = 1719

    KNOWN_TOP_LEVEL = [
      RECEIPT_TYPE, APP_ITEM_ID, BUNDLE_ID, APP_VERSION, OPAQUE_VALUE, SHA1_HASH, CREATION_DATE,
      DOWNLOAD_ID, VERSION_EXTERNAL_IDENTIFIER, ORIGINAL_PURCHASE_DATE, ORIGINAL_APP_VERSION,
      EXPIRATION_DATE
    ].freeze
    KNOWN_IN_APP = [
      IAP_QUANTITY, IAP_PRODUCT_ID, IAP_TRANSACTION_ID, IAP_PURCHASE_DATE,
      IAP_ORIGINAL_TRANSACTION_ID, IAP_ORIGINAL_PURCHASE_DATE, IAP_EXPIRES_DATE,
      IAP_WEB_ORDER_LINE_ITEM_ID, IAP_CANCELLATION_DATE, IAP_IS_TRIAL_PERIOD,
      IAP_IS_IN_INTRO_OFFER_PERIOD
    ].freeze

    # Attribute *types* live in a 32-bit signed space. Every type Apple has
    # ever issued is a small number, and a value above 2^31-1 (or negative)
    # cannot be represented by ports whose type field is an int32. The
    # cross-port contract says reject: a receipt carrying one is unreadable
    # as a whole. Attribute *values* keep the wider, signed 64-bit range —
    # `web_order_line_item_id` is genuinely a 7-byte integer, and a hostile
    # ASN.1 INTEGER can be negative.
    MAX_ATTRIBUTE_TYPE = 2_147_483_647

    # A ceiling on attributes per set. The largest genuine receipt known to
    # this project carries 196 at the top level and 11 per purchase.
    MAX_ATTRIBUTES = 100_000

    # `YYYY-MM-DDTHH:MM:SSZ` and nothing else (owner, 2026-09-27): a
    # four-digit year, uppercase `T` and `Z`, a real calendar date (leap
    # years included), hours 00-23, minutes and seconds 00-59, no fraction
    # and no offset. Built from captures rather than `Time.iso8601`: this
    # runs once per date and the largest genuine receipt carries hundreds.
    RECEIPT_DATE = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\z/

    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31].freeze

    class << self
      # The receipt creation date (attribute 12), read the only way anything
      # in a payload is read before its signer is trusted: the top-level
      # attribute SET is walked shallowly, each entry's type is read, and
      # only the value of the FIRST type-12 entry is decoded.
      #
      # `nil` means "judge the chain at the clock": no attribute 12, one
      # that is empty or does not decode, or a walk that fails anywhere.
      # Never raises: nothing is trusted yet, so nothing here can blame
      # anyone.
      #
      # @param content [String] the encapsulated content bytes, unverified
      # @return [Integer, nil] epoch milliseconds
      def creation_date(content)
        found = nil
        each_attribute(content, "receipt payload") do |type, value|
          next unless type == CREATION_DATE
          break if found # only the first counts; a walk failure past it is fine

          found = [value]
        end
        return nil if found.nil?

        pair = found #: Array[String]
        first = pair[0] #: String
        date(first)
      rescue SystemStackError, StandardError
        nil
      end

      # @param content [String] the verified encapsulated content bytes
      # @return [ReceiptPayload]
      # @raise [VerificationError] MALFORMED when the attribute SET, or one
      #   of its attributes, does not parse structurally
      def parse(content)
        fields = {
          receipt_type: nil, app_item_id: nil, bundle_id: nil, bundle_id_bytes: nil,
          application_version: nil, opaque_value: nil, sha1_hash: nil, receipt_creation_date_ms: nil,
          download_id: nil, version_external_identifier: nil, original_purchase_date_ms: nil,
          original_application_version: nil, expiration_date_ms: nil
        } #: fields
        purchases = [] #: Array[InAppPurchase]
        unknown = {} #: unknown_attributes
        seen = [] #: Array[Integer]

        each_attribute(content, "receipt payload") do |type, value|
          if KNOWN_TOP_LEVEL.include?(type) && later_copy?(seen, type)
            keep_raw(unknown, type, value)
            next
          end

          ok =
            case type
            when RECEIPT_TYPE then assign(fields, :receipt_type) { decode_string(value) }
            when APP_ITEM_ID then assign(fields, :app_item_id) { decode_integer(value) }
            when BUNDLE_ID
              fields[:bundle_id_bytes] = value.dup.freeze
              fields[:bundle_id] = begin
                decode_string(value)
              rescue Asn1::Error
                nil
              end
              true
            when APP_VERSION then assign(fields, :application_version) { decode_string(value) }
            when OPAQUE_VALUE
              fields[:opaque_value] = value.dup.freeze
              true
            when SHA1_HASH
              fields[:sha1_hash] = value.dup.freeze
              true
            when CREATION_DATE then assign(fields, :receipt_creation_date_ms, optional: true) do
              date(value)
            end
            when DOWNLOAD_ID then assign(fields, :download_id) { decode_integer(value) }
            when VERSION_EXTERNAL_IDENTIFIER
              assign(fields, :version_external_identifier) { decode_integer(value) }
            when IN_APP
              purchase = parse_in_app(value)
              purchases << purchase unless purchase.nil?
              !purchase.nil?
            when ORIGINAL_PURCHASE_DATE
              assign(fields, :original_purchase_date_ms, optional: true) { date(value) }
            when ORIGINAL_APP_VERSION
              assign(fields, :original_application_version) { decode_string(value) }
            when EXPIRATION_DATE then assign(fields, :expiration_date_ms, optional: true) { date(value) }
            else false
            end
          keep_raw(unknown, type, value) unless ok
        end

        ReceiptPayload.new( # steep:ignore InsufficientKeywordArguments
          **fields,
          in_app: purchases.freeze,
          unknown_attributes: freeze_unknown(unknown)
        )
      end

      # Writes `unknown_attributes` in the canonical form: keys in ascending
      # numeric order, each key's values in receipt order.
      def write_unknown_attributes(json, attributes)
        json.key("unknown_attributes")
        json.object do |o|
          attributes.keys.sort.each do |type|
            o.key(type.to_s)
            o.array { |a| attributes[type].each { |value| a.raw_value { a.quote([value].pack("m0")) } } }
          end
        end
      end

      private

      # Runs the block; on success stores the (possibly nil, for `optional:
      # true` date fields) value and returns true; on a decode failure
      # returns false so the caller keeps the raw bytes. A date attribute
      # whose string is EMPTY decodes to `Ok(None)`, which must count as
      # success (the empty string is not kept raw); any other decoder
      # returning `nil` is a failure.
      def assign(fields, key, optional: false)
        value = yield
        return false if value.nil? && !optional

        fields[key] = value
        true
      rescue Asn1::Error
        false
      end

      def later_copy?(seen, type)
        return true if seen.include?(type)

        seen << type
        false
      end

      def keep_raw(unknown, type, value)
        (unknown[type] ||= []) << value.dup.freeze
      end

      def freeze_unknown(unknown)
        unknown.each_value(&:freeze)
        unknown.freeze
      end

      def parse_in_app(bytes)
        fields = {
          quantity: nil, product_id: nil, transaction_id: nil, purchase_date_ms: nil,
          original_transaction_id: nil, original_purchase_date_ms: nil, expires_date_ms: nil,
          web_order_line_item_id: nil, cancellation_date_ms: nil, is_trial_period: nil,
          is_in_intro_offer_period: nil
        } #: fields
        unknown = {} #: unknown_attributes
        seen = [] #: Array[Integer]

        each_attribute(bytes, "in-app purchase attribute") do |type, value|
          if KNOWN_IN_APP.include?(type) && later_copy?(seen, type)
            keep_raw(unknown, type, value)
            next
          end

          ok =
            case type
            when IAP_QUANTITY then assign(fields, :quantity) { decode_integer(value) }
            when IAP_PRODUCT_ID then assign(fields, :product_id) { decode_string(value) }
            when IAP_TRANSACTION_ID then assign(fields, :transaction_id) { decode_string(value) }
            when IAP_PURCHASE_DATE then assign(fields, :purchase_date_ms, optional: true) { date(value) }
            when IAP_ORIGINAL_TRANSACTION_ID
              assign(fields, :original_transaction_id) { decode_string(value) }
            when IAP_ORIGINAL_PURCHASE_DATE
              assign(fields, :original_purchase_date_ms, optional: true) { date(value) }
            when IAP_EXPIRES_DATE then assign(fields, :expires_date_ms, optional: true) { date(value) }
            when IAP_WEB_ORDER_LINE_ITEM_ID
              assign(fields, :web_order_line_item_id) { decode_integer(value) }
            when IAP_CANCELLATION_DATE
              assign(fields, :cancellation_date_ms, optional: true) { date(value) }
            when IAP_IS_TRIAL_PERIOD
              assign(fields, :is_trial_period) { decode_flag?(value) }
            when IAP_IS_IN_INTRO_OFFER_PERIOD
              assign(fields, :is_in_intro_offer_period) { decode_flag?(value) }
            else false
            end
          keep_raw(unknown, type, value) unless ok
        end

        InAppPurchase.new( # steep:ignore InsufficientKeywordArguments
          **fields, unknown_attributes: freeze_unknown(unknown)
        )
      rescue VerificationError
        # The in-app attribute SET itself (or one of its own attributes)
        # does not parse: the whole attribute 17 value is kept raw by the
        # caller instead of becoming an InAppPurchase (docs/design's "an
        # in-app purchase that does not parse is kept raw under 17").
        nil
      end

      # Walks `SET OF SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }`,
      # yielding [type, value bytes]. Offsets only: no node tree, no slice
      # per structural element and no recursion, since the grammar is
      # exactly two levels deep.
      def each_attribute(bytes, what)
        # The ASN.1 nesting bound (32, docs/design/0.7-api.md, Bounds)
        # applies to the signed content parsed on its own, same as the CMS
        # envelope; the fast offset-based walk below has no depth concept
        # of its own; a value that overruns it once, unattributably to
        # any one attribute, must fail the whole payload.
        bounded_scan!(bytes, what)
        tag, start, finish = outer(bytes, what)

        if [Asn1::TAG_OCTET_STRING, Asn1::TAG_OCTET_STRING_BER].include?(tag)
          # Xcode receipts double-wrap the payload in an extra OCTET STRING.
          bytes = if tag == Asn1::TAG_OCTET_STRING
                    bytes.byteslice(start, finish - start)
                  else
                    ber_octets(bytes, what)
                  end #: String
          bounded_scan!(bytes, what)
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

          # version: tolerated in any position after, but when it IS tagged
          # INTEGER it must be a well-formed one.
          version_tag, version_start, version_end, cursor = header(bytes, cursor, sequence_end, what)
          if version_tag == Asn1::TAG_INTEGER
            begin
              integer_value(bytes.byteslice(version_start, version_end - version_start)) # steep:ignore
            rescue Asn1::Error
              raise format_error("malformed receipt attribute")
            end
          end

          value_tag, value_start, value_end, = header(bytes, cursor, sequence_end, what)
          unless [Asn1::TAG_OCTET_STRING, Asn1::TAG_OCTET_STRING_BER].include?(value_tag)
            raise format_error("malformed receipt attribute")
          end

          value =
            if value_tag == Asn1::TAG_OCTET_STRING
              bytes.byteslice(value_start, value_end - value_start)
            else
              ber_octets(bytes.byteslice(cursor, value_end - cursor), # steep:ignore ArgumentTypeMismatch
                         "receipt attribute value")
            end #: String

          yield attribute_type(bytes.byteslice(type_start, type_end - type_start)), value # steep:ignore
          position = after
        end
      end

      def bounded_scan!(bytes, what)
        Asn1.scan!(bytes)
      rescue Asn1::Error => e
        raise format_error("#{what} is not valid ASN.1 (#{e.message})")
      end

      def outer(bytes, what)
        tag, start, finish, after = header(bytes, 0, bytes.bytesize, what)
        raise format_error("trailing bytes after #{what}") unless after == bytes.bytesize

        [tag, start, finish]
      end

      def header(bytes, offset, limit, what)
        raise format_error("truncated #{what}") if offset + 2 > limit

        tag = bytes.getbyte(offset) #: Integer
        raise format_error("multi-byte ASN.1 tag in #{what}") if (tag & 0x1F) == 0x1F

        position = offset + 1
        length_byte = bytes.getbyte(position) #: Integer
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
            length = (length << 8) | bytes.getbyte(position) # steep:ignore ArgumentTypeMismatch
            position += 1
          end
        end

        finish = position + length
        raise format_error("#{what} value overruns its parent") if finish > limit

        [tag, position, finish, finish]
      end

      def ber_octets(bytes, what)
        node = Asn1.parse(bytes)
        raise format_error("#{what} is not an OCTET STRING") unless node.octet_string?

        node.octet_value
      rescue Asn1::Error => e
        raise format_error("#{what} is not valid ASN.1 (#{e.message})")
      end

      def attribute_type(raw)
        type = integer_value(raw)
        return type if type.between?(0, MAX_ATTRIBUTE_TYPE)

        raise format_error("receipt attribute type out of the 32-bit signed range")
      rescue Asn1::Error
        raise format_error("receipt attribute type is not a well-formed ASN.1 integer")
      end

      # A DER INTEGER's value: two's-complement, minimally encoded (X.690
      # 8.3.2 — the first nine bits are never all zero or all one), at most
      # 8 content octets so the value fits a signed 64-bit range. Negative
      # values ARE representable: a hostile ASN.1 INTEGER can be negative,
      # and this reports what is there rather than clamping it.
      #
      # @raise [Asn1::Error] empty, over 8 octets, or a redundant leading
      #   octet
      def integer_value(bytes)
        raise Asn1::Error, "attribute integer out of range" if bytes.bytesize > 8
        raise Asn1::Error, "empty receipt integer" if bytes.empty?

        first = bytes.getbyte(0) #: Integer
        if bytes.bytesize > 1
          second = bytes.getbyte(1) #: Integer
          redundant = (first.zero? && (second & 0x80).zero?) || (first == 0xFF && (second & 0x80) != 0)
          raise Asn1::Error, "receipt integer is not minimally encoded" if redundant
        end

        value = first >= 0x80 ? -1 : 0
        bytes.each_byte { |b| value = (value << 8) | b }
        value
      end

      def single_value(bytes)
        Asn1.read_single(bytes)
      rescue Asn1::Error => e
        raise Asn1::Error, "attribute value is not valid ASN.1 (#{e.message})"
      end

      # A `UTF8String` or an `IA5String`, the two string types Apple's
      # receipts use. A `UTF8String` must be valid UTF-8; an `IA5String`
      # must be 7-bit ASCII, as IA5 is (owner, 2026-09-27, Q23): a byte at
      # or above 0x80 does not decode, rather than being read as Latin-1.
      def decode_string(bytes)
        tag, content = single_value(bytes)
        case tag
        when Asn1::TAG_UTF8_STRING
          text = content.dup.force_encoding(Encoding::UTF_8)
          raise Asn1::Error, "attribute value is not valid UTF-8" unless text.valid_encoding?
        when Asn1::TAG_IA5_STRING
          raise Asn1::Error, "attribute value is not 7-bit IA5" unless content.ascii_only?

          text = content.dup.force_encoding(Encoding::UTF_8)
        else
          raise Asn1::Error, "attribute value is not an ASN.1 string"
        end
        text.freeze
      end

      def decode_integer(bytes)
        tag, content = single_value(bytes)
        raise Asn1::Error, "attribute value is not an ASN.1 integer" unless tag == Asn1::TAG_INTEGER

        integer_value(content)
      end

      # `Boolean`: 0 is `false`, any other DER-valid integer value is `true`.
      def decode_flag?(bytes)
        decode_integer(bytes) != 0
      end

      # An empty string means "absent"; anything else non-empty must be
      # exactly `YYYY-MM-DDTHH:MM:SSZ`. `nil` from this method (as opposed
      # to `Asn1::Error`) means "not set, do not keep raw".
      #
      # @return [Integer, nil] epoch milliseconds, or nil for the empty string
      # @raise [Asn1::Error] the value does not decode as a string, or is a
      #   non-empty string in any other form
      def date(bytes)
        text = decode_string(bytes)
        return nil if text.empty?

        millis = parse_receipt_date(text)
        raise Asn1::Error, "unparseable receipt date" if millis.nil?

        millis
      end

      def leap_year?(year)
        (year % 4).zero? && (!(year % 100).zero? || (year % 400).zero?)
      end

      def days_in_month(year, month)
        return 29 if month == 2 && leap_year?(year)

        DAYS_IN_MONTH[month - 1]
      end

      # Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
      # Hinnant's `days_from_civil`), matching the algorithm every other
      # port's date grammar uses, so a receipt decodes to the same
      # millisecond everywhere.
      def days_from_civil(year, month, day)
        y = month <= 2 ? year - 1 : year
        era = (y >= 0 ? y : y - 399) / 400
        yoe = y - (era * 400)
        mp = (month + 9) % 12
        doy = (((153 * mp) + 2) / 5) + day - 1
        doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy
        (era * 146_097) + doe - 719_468
      end

      def parse_receipt_date(text)
        match = RECEIPT_DATE.match(text)
        return nil unless match

        year, month, day, hour, minute, second =
          (1..6).map { |i| match[i].to_i } #: [Integer, Integer, Integer, Integer, Integer, Integer]
        return nil unless (1..12).cover?(month)
        return nil if day < 1 || day > days_in_month(year, month)
        return nil if hour > 23 || minute > 59 || second > 59

        seconds = (days_from_civil(year, month, day) * 86_400) + (hour * 3600) + (minute * 60) + second
        seconds * 1000
      end

      def format_error(message)
        VerificationError.new(Reason::MALFORMED, message)
      end
    end
  end
end
