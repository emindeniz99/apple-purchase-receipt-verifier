# frozen_string_literal: true

require_relative "helper"

# The spellings Receipt.decode_canonical_base64 must accept and refuse are the
# decodeBase64 groups of fixtures/cases-0.7.json, which conformance_test.rb
# runs against both the receipt-data and the x5c decoder. What stays here is
# what a shared vector cannot hold: bytes outside the base64 alphabet
# entirely (which JSON text cannot carry either), and why neither of Ruby's
# own decoders is the rule alone.
class ReceiptBase64Test < Minitest::Test
  Receipt = ApplePurchaseReceiptVerifier::Receipt

  def test_bytes_outside_the_base64_alphabet_are_refused
    text = "QU\xffD".b
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
