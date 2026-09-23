import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Receipt dates are parsed with `Date.ISO8601FormatStyle` when the text has
/// the canonical shape and with `ISO8601DateFormatter` otherwise
/// (ReceiptVerifier.swift says why: a formatter per date made a 187-purchase
/// receipt about 50 times slower than the Java port). The fast path is only
/// allowed because it never changes an answer, so it is compared here with
/// the formatter on whichever Foundation the suite is built against.
///
/// The generators are seeded, so a failure reproduces.
final class ReceiptDateTests: XCTestCase {
    private static let seed: UInt64 = 0xDA7E_5EED

    func testParseAgreesWithFormatterOnGeneratedStrings() {
        var random = SplitMix64(seed: Self.seed)
        var fast = 0
        var other = 0
        for _ in 0..<20_000 {
            if comparesParse(generateDateText(&random)) { fast += 1 } else { other += 1 }
        }
        // Both paths must run many times for the comparison to mean anything.
        XCTAssertGreaterThan(fast, 5_000, "fast path: \(fast)")
        XCTAssertGreaterThan(other, 5_000, "formatter path: \(other)")
    }

    func testParseAgreesWithFormatterOnHandPickedEdges() {
        let edges = [
            "", "Z", "1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z", "2000-02-29T12:00:00Z",
            "1900-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2023-02-29T00:00:00Z",
            "2024-02-30T00:00:00Z", "2024-04-31T00:00:00Z", "2024-12-31T23:59:59Z",
            "2016-12-31T23:59:60Z", "2024-01-01T24:00:00Z", "2024-01-01T23:60:00Z",
            "2024-00-10T00:00:00Z", "2024-13-10T00:00:00Z", "2024-01-00T00:00:00Z",
            "9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z",
            "1582-10-10T00:00:00Z", "1582-10-15T00:00:00Z", "2024-01-01T00:00:00z",
            "2024-01-01t00:00:00Z", "2024-01-01 00:00:00Z", "2024-01-01T00:00:00",
            "2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00-08:00", "2024-01-01T00:00:00+2400",
            "2024-01-01T00:00:00.000Z", "2024-01-01T00:00:00.5Z", "2024-01-01T00:00:00.123456789Z",
            "999999-12-31T23:59:59Z", "12024-01-01T00:00:00Z", "-2024-01-01T00:00:00Z",
            "+2024-01-01T00:00:00Z", "2024-1-01T00:00:00Z", "２０２４-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z ", " 2024-01-01T00:00:00Z", "2024-01-01T00:00:00 Z",
            "20240101T000000Z", "2024-01-01T00:00Z", "2024-01-01T00:00:00ZZ",
        ]
        for edge in edges {
            comparesParse(edge)
        }
    }

    /// Asserts the parse `decodeDate` does gives the formatter's answer;
    /// returns whether the fast path produced it.
    @discardableResult
    private func comparesParse(_ text: String) -> Bool {
        let fast = parseCanonicalReceiptDate(text)
        XCTAssertEqual(
            fast ?? parseReceiptDateWithFormatter(text), parseReceiptDateWithFormatter(text),
            text.debugDescription)
        return fast != nil
    }

    private func generateDateText(_ random: inout SplitMix64) -> String {
        var fields = [
            Int.random(in: 1960...10_000, using: &random),
            Int.random(in: 0...13, using: &random),
            Int.random(in: 0...32, using: &random),
            Int.random(in: 0...24, using: &random),
            Int.random(in: 0...60, using: &random),
            Int.random(in: 0...60, using: &random),
        ]
        // Most strings keep every field in range, so the fast path is taken
        // often; out-of-range fields above exercise the formatter.
        if Int.random(in: 0..<4, using: &random) != 0 {
            fields[1] = Int.random(in: 1...12, using: &random)
            fields[2] = Int.random(in: 1...31, using: &random)
            fields[3] = Int.random(in: 0...23, using: &random)
            fields[4] = Int.random(in: 0...59, using: &random)
            fields[5] = Int.random(in: 0...59, using: &random)
        }
        let widths = [4, 2, 2, 2, 2, 2]
        let parts = zip(fields, widths).map { value, width in
            let digits = String(value)
            return String(repeating: "0", count: max(0, width - digits.count)) + digits
        }
        var text = "\(parts[0])-\(parts[1])-\(parts[2])T\(parts[3]):\(parts[4]):\(parts[5])"
        switch Int.random(in: 0..<12, using: &random) {
        case 0: text += ".\(Int.random(in: 0...999, using: &random))Z"
        case 1: text += ".\(Int.random(in: 0...999_999, using: &random))Z"
        case 2: text += "+00:00"
        case 3: text += "-07:00"
        case 4: text += "+0530"
        case 5: text += "z"
        case 6: text += " Z"
        case 7: break
        default: text += "Z"
        }
        return text
    }
}
