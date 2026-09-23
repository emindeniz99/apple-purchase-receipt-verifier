# frozen_string_literal: true

require_relative "helper"

# The spellings Receipt.decode_base64 must accept and refuse are the
# decodeBase64 groups of fixtures/cases.json, which conformance_test.rb runs
# against both the receipt-data and the x5c decoder. What stays here is what a
# shared vector cannot hold: a string that is not UTF-8 at all, which JSON text
# cannot carry, and why neither of Ruby's own decoders is the rule alone.
class ReceiptBase64Test < Minitest::Test
  Receipt = ApplePurchaseReceiptVerifier::Receipt
  VerificationError = ApplePurchaseReceiptVerifier::VerificationError
  Reason = ApplePurchaseReceiptVerifier::Reason

  def test_a_string_that_is_not_utf8_is_invalid_receipt_format
    text = "QU\xffD".b
    error = assert_raises(VerificationError, text.inspect) { Receipt.decode_base64(text) }
    assert_equal Reason::INVALID_RECEIPT_FORMAT, error.reason
    assert_nil Receipt.decode_canonical_base64(text)
  end

  # Why the shape is checked by hand: Ruby's strict decoder refuses the
  # trailing bits Apple accepts, and its lenient one skips what it does not
  # know, so neither alone is the rule.
  def test_neither_ruby_decoder_alone_is_the_rule
    assert_raises(ArgumentError) { "QR==".unpack1("m0") }
    assert_equal "ABC", "QU JD\n".unpack1("m")
  end
end
