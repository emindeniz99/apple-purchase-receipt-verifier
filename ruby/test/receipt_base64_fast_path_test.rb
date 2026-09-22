# frozen_string_literal: true

require_relative "helper"

# The strict fast path in front of the receipt-data base64 decoder.
#
# Receipt.decode_base64 tries `unpack1("m0")` first and falls back to the
# tolerant rule on anything it declines. That is only a speed-up if it can
# never change an answer: every string the fast path accepts must be one the
# tolerant path accepts, with the same bytes, and every rejection must still
# carry the tolerant path's reason and message. A client whose receipt was
# refused yesterday must be refused today for the same stated reason, and a
# receipt that decoded must decode to the same DER.
class ReceiptBase64FastPathTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  RECEIPT = APRV::Receipt

  SEED = 20_260_922
  RANDOM_INPUTS = 20_000

  # Strings where a strict decoder and the tolerant rule are most likely to
  # disagree: padding in every wrong count and place, whitespace, the other
  # alphabet, non-ASCII, and the lengths base64 cannot have.
  EDGE_CASES = [
    "", " ", "\n", "=", "==", "===", "====", "A", "AA", "AAA", "AAAA", "A===",
    "AA=", "AA==", "AA===", "AAA=", "AAA==", "AAAA=", "AAAA==", "AAAA===",
    "AAAA====", "AAAAA===", "AB==", "AAB=", "QQ==QQ==", "AA==AA==", "AAA=AAA=",
    "AAAA\n", " AAAA", "AA\r\nAA", "AA-_", "AA+/", "A+_A", "AAAA!", "éééé",
    "AA\x00A", "////", "++++", "QUJD".encode(Encoding::UTF_16LE)
  ].freeze

  WHITESPACE = " \t\r\n"
  POOL = [*"A".."Z", *"a".."z", *"0".."9", "+", "/", "-", "_", "=", " ", "\t", "\r", "\n", "!", "é"].freeze

  # One input, drawn so that each branch of the decoder gets thousands of
  # hits: clean canonical base64, the variants only the tolerant path
  # accepts, and near misses that both must reject.
  def random_input(random)
    canonical = [random.bytes(random.rand(40))].pack("m0")
    case random.rand(6)
    when 0 then canonical
    when 1
      url = canonical.tr("+/", "-_")
      random.rand < 0.5 ? url.delete("=") : url
    when 2
      chars = canonical.chars
      random.rand(1..3).times { chars.insert(random.rand(chars.size + 1), WHITESPACE[random.rand(4)]) }
      chars.join
    when 3 then canonical.delete("=") + ("=" * random.rand(5))
    when 4 then near_miss(random, canonical.chars)
    else Array.new(random.rand(13)) { POOL.sample(random: random) }.join
    end
  end

  def near_miss(random, chars)
    position = random.rand(chars.size + 1)
    operation = random.rand(3)
    if operation.zero? || chars.empty?
      chars.insert(position, POOL.sample(random: random))
    elsif operation == 1
      chars[[position, chars.size - 1].min] = POOL.sample(random: random)
    else
      chars.delete_at([position, chars.size - 1].min)
    end
    chars.join
  end

  def inputs
    random = Random.new(SEED)
    EDGE_CASES + Array.new(RANDOM_INPUTS) { random_input(random) }
  end

  def outcome(text)
    [:ok, yield(text)]
  rescue APRV::VerificationError => e
    [:error, e.reason, e.message]
  end

  def tolerant(text)
    outcome(text) { |t| RECEIPT.decode_base64_tolerant(t) }
  end

  # The inputs on which `fast` in front of the tolerant path answers
  # differently from the tolerant path alone.
  def mismatches(texts, &fast)
    texts.reject do |text|
      combined = outcome(text) { |t| fast.call(t) || RECEIPT.decode_base64_tolerant(t) }
      combined == tolerant(text)
    end
  end

  def test_the_fast_path_never_changes_an_answer
    branches = { fast: 0, tolerant_accept: 0, reject: 0 }
    inputs.each do |text|
      expected = tolerant(text)
      assert_equal expected, outcome(text) { |t| RECEIPT.decode_base64(t) }, text.inspect
      if RECEIPT.decode_base64_strict(text).nil?
        branches[expected.first == :ok ? :tolerant_accept : :reject] += 1
      else
        # Accepted by the fast path, so the tolerant path must accept it
        # too; the equality above already compared the bytes.
        assert_equal :ok, expected.first, text.inspect
        branches[:fast] += 1
      end
    end
    # A differential test that never reached one of the branches proves
    # nothing about it.
    branches.each { |branch, hits| assert_operator hits, :>, 1000, "#{branch}: #{branches}" }
  end

  # The comparison above can fail: a decoder that skips characters outside
  # the alphabet instead of refusing them accepts strings the tolerant rule
  # rejects, and the same inputs expose it.
  def test_a_permissive_fast_path_is_caught
    refute_empty(mismatches(inputs) { |text| text.empty? ? nil : text.unpack1("m") })
  end

  # `unpack1("m0")` decodes "" to "", which the tolerant rule rejects as an
  # empty receipt. The guard is what keeps the fast path a subset; it is the
  # only one needed on the Rubies this was measured on.
  def test_the_empty_guard_is_what_makes_the_decoder_a_subset
    unguarded = mismatches(EDGE_CASES) do |text|
      text.unpack1("m0")
    rescue ArgumentError
      nil
    end
    assert_equal [""], unguarded
    assert_empty(mismatches(EDGE_CASES) { |text| RECEIPT.decode_base64_strict(text) })
  end
end
