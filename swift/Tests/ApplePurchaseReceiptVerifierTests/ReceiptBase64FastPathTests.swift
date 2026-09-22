import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// `decodeReceiptBase64` tries Foundation's decoder before its own tolerant
/// parser. That shortcut is only safe if it never changes an answer: every
/// string it accepts must be one the tolerant parser accepts too, with the
/// same bytes, and every string it refuses must reach the tolerant parser
/// unchanged. If the fast path ever accepted something the documented
/// `receipt-data` contract rejects (a character after the padding, a wrong
/// padding count), a malformed receipt would start verifying in Swift alone,
/// and the ports would disagree.
///
/// This matters more here than in the other ports because Foundation's
/// decoder is not the same code on every platform: on Linux it accepts
/// over-padded strings such as "AAAA=" that the contract rejects, which is
/// why the fast path checks the shape itself first. These tests run on
/// whichever Foundation the suite is built against, so CI proves it on Linux
/// and on macOS separately.
///
/// The generator is seeded, so a failure reproduces. It mixes the shapes the
/// contract names: clean standard base64, missing and extra padding, both
/// alphabets, whitespace anywhere, illegal characters (including ones outside
/// Latin-1), characters after the padding, and lengths congruent to 1 mod 4.
final class ReceiptBase64FastPathTests: XCTestCase {
    private static let seed: UInt64 = 0x5EED_B64
    private static let cases = 20_000
    private static let illegal = Array("!#$%&*.,:;?@[]{}|~\"'\\\u{0000}\u{007F}éÿĀ\u{00A0}\u{2028}\u{000B}")
    private static let whitespace: [Character] = ["\r", "\n", " ", "\t"]

    func testDecodeAgreesWithTheTolerantPathOnGeneratedInputs() {
        var random = SplitMix64(seed: Self.seed)
        var fastAccepted = 0
        var tolerantOnlyAccepted = 0
        var rejected = 0
        for _ in 0..<Self.cases {
            let input = generate(&random)
            if compare(input) {
                if fastPathAccepts(input) {
                    fastAccepted += 1
                } else {
                    tolerantOnlyAccepted += 1
                }
            } else {
                rejected += 1
            }
        }
        // The comparison proves nothing unless every branch was exercised
        // many times: the fast path taken, the fallback accepting, and both
        // rejecting.
        XCTAssertGreaterThan(fastAccepted, 1_000, "fast path accepted only \(fastAccepted)")
        XCTAssertGreaterThan(tolerantOnlyAccepted, 1_000, "fallback accepted only \(tolerantOnlyAccepted)")
        XCTAssertGreaterThan(rejected, 1_000, "rejected only \(rejected)")
    }

    func testDecodeAgreesWithTheTolerantPathOnHandPickedEdges() {
        let edges = [
            "", " ", "\r\n\t ", "=", "==", "===", "====",
            "A", "A=", "A==", "A===", "AA", "AA=", "AA==", "AA===",
            "AAA", "AAA=", "AAA==", "AAAA", "AAAA=", "AAAA==", "AAAA====",
            "AA==A", "AA==\n", "AA==AA==", "AAAAA",
            "-_", "+/", "+_", "-/", "AB-_", "AB+/", "ABé=", "ABĀ",
            "QUJD", "QUJ", "QUI", "QQ", "QR", "QR==", "QUK=", "QUJD\r\n",
        ]
        for edge in edges {
            compare(edge)
        }
    }

    /// The shape check is what keeps Foundation's leniency out: each of these
    /// is a string Foundation on Linux decodes and the contract rejects, so
    /// the guard must refuse it before the decoder runs.
    func testShapeCheckRefusesWhatFoundationWouldOverAccept() {
        for input in ["AA===", "AAAA=", "AAAA==", "AAAA====", "A===", "===="] {
            XCTAssertFalse(isCanonicalStandardBase64(input), input.debugDescription)
            XCTAssertNil(decodeReceiptBase64(input), input.debugDescription)
        }
    }

    /// Asserts that `decodeReceiptBase64` and `decodeReceiptBase64Tolerant`
    /// give the same answer for `input`: equal bytes, or both nil. Returns
    /// whether the input was accepted. The Swift decoder reports a rejection
    /// as nil, with no reason or message of its own; the callers turn every
    /// nil into the same `.invalidReceiptFormat` error.
    @discardableResult
    private func compare(_ input: String) -> Bool {
        let expected = decodeReceiptBase64Tolerant(input)
        let actual = decodeReceiptBase64(input)
        let shown = input.debugDescription
        guard let expected else {
            XCTAssertNil(actual, "decode accepted what the tolerant path rejects: \(shown)")
            return false
        }
        XCTAssertEqual(actual, expected, shown)
        return true
    }

    private func fastPathAccepts(_ input: String) -> Bool {
        isCanonicalStandardBase64(input) && Data(base64Encoded: input) != nil
    }

    private func generate(_ random: inout SplitMix64) -> String {
        let bytes = (0..<Int.random(in: 0..<40, using: &random)).map { _ in
            UInt8.random(in: 0...255, using: &random)
        }
        var s = Array(Data(bytes).base64EncodedString())
        // About half the inputs stay canonical standard base64 so the fast
        // path is taken often; the rest get one or more defects.
        if Bool.random(using: &random) {
            return String(s)
        }
        for _ in 0..<Int.random(in: 1...3, using: &random) {
            switch Int.random(in: 0..<9, using: &random) {
            case 0:  // drop the padding
                while s.last == "=" { s.removeLast() }
            case 1:  // extra padding
                s.append(contentsOf: Bool.random(using: &random) ? "=" : "==")
            case 2:  // base64url alphabet, whole string
                s = s.map { $0 == "+" ? "-" : $0 == "/" ? "_" : $0 }
            case 3:  // one character of the other alphabet
                insert(&s, Array("+/-_").randomElement(using: &random)!, &random)
            case 4:  // whitespace somewhere, including before and after the padding
                insert(&s, Self.whitespace.randomElement(using: &random)!, &random)
            case 5:  // an illegal character
                insert(&s, Self.illegal.randomElement(using: &random)!, &random)
            case 6:  // something after the padding
                s.append("=")
                s.append(Character(Unicode.Scalar(UInt8(ascii: "A") + UInt8.random(in: 0..<26, using: &random))))
            case 7:  // length congruent to 1 mod 4 (after stripping padding)
                while s.last == "=" { s.removeLast() }
                while s.count % 4 != 1 { s.append("A") }
            default:  // whitespace-only or empty
                if Int.random(in: 0..<8, using: &random) == 0 {
                    s = (0..<Int.random(in: 0..<3, using: &random)).map { _ in
                        Self.whitespace.randomElement(using: &random)!
                    }
                } else {
                    s.append(Self.whitespace.randomElement(using: &random)!)
                }
            }
        }
        // String(s) joins "\r" and "\n" into one Character, but the decoders
        // walk UTF-8 bytes, so the joined form is what a client would send.
        return String(s)
    }

    private func insert(_ s: inout [Character], _ c: Character, _ random: inout SplitMix64) {
        s.insert(c, at: Int.random(in: 0...s.count, using: &random))
    }
}

/// A seeded generator, so a failing input can be reproduced. The standard
/// library's `SystemRandomNumberGenerator` cannot be seeded.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
