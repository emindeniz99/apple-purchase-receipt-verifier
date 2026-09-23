# frozen_string_literal: true

require_relative "helper"

# Receipt.decode_base64 must answer what Apple's verifyReceipt answered on
# 2026-09-23 for the same spellings of genuine receipts
# (docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple
# decodes must decode here to the same bytes; a spelling Apple answers 21002
# must be INVALID_RECEIPT_FORMAT here, or a receipt verifies in this library
# that Apple itself refuses. The conformance cases pin the rule on a real
# receipt; this pins each shape on its own, including the ones Ruby's own
# decoders would have decided differently.
class ReceiptBase64Test < Minitest::Test
  Receipt = ApplePurchaseReceiptVerifier::Receipt
  VerificationError = ApplePurchaseReceiptVerifier::VerificationError
  Reason = ApplePurchaseReceiptVerifier::Reason

  ACCEPTED = {
    "QUJD" => "ABC",
    "QUI=" => "AB",
    "QQ==" => "A",
    "+/8=" => "\xfb\xff".b,
    # Unused low bits set in the last data character: Apple accepts them.
    "QR==" => "A",
    "Qf==" => "A",
    "QUJ=" => "AB"
  }.freeze

  REFUSED = [
    "",
    "QQ", "QUI", # padding omitted
    "QQ=", # under-padded
    "QQ===", "QQ====", # extra padding
    "QUJD=", "QUJD==", "QUJD====", "==", # padding after a full group
    "Q===", "QUJDR", # impossible length
    "QQ==QUJD", "QQ==!!!!", "QQ=A", # data or junk after the padding
    "QU!D", # junk inside
    "QUJD\n", "QUJD\r\n", "QUJD\nQUJD", # line feeds
    " QUJD", "QU JD", "QU\tJD", "  QUJD  ", # other whitespace
    "-_8=", "-_8", "+_8=", # base64url, unpadded, mixed
    "QUJé", "QU\xffD".b # outside ASCII, and not UTF-8 at all
  ].freeze

  def test_canonical_spellings_and_trailing_bits_decode
    ACCEPTED.each do |text, expected|
      assert_equal expected.b, Receipt.decode_base64(text), text.inspect
    end
  end

  def test_every_other_spelling_is_invalid_receipt_format
    REFUSED.each do |text|
      error = assert_raises(VerificationError, text.inspect) { Receipt.decode_base64(text) }
      assert_equal Reason::INVALID_RECEIPT_FORMAT, error.reason, text.inspect
    end
  end

  # Why the shape is checked by hand: Ruby's strict decoder refuses the
  # trailing bits Apple accepts, and its lenient one skips what it does not
  # know, so neither alone is the rule.
  def test_neither_ruby_decoder_alone_is_the_rule
    assert_raises(ArgumentError) { "QR==".unpack1("m0") }
    assert_equal "ABC", "QU JD\n".unpack1("m")
  end
end
