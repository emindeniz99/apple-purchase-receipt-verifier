import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Receipt dates are parsed with `Date.ISO8601FormatStyle` when the text has
/// the canonical shape and with `ISO8601DateFormatter` otherwise
/// (ReceiptVerifier.swift says why: a formatter per date made a 187-purchase
/// receipt about 50 times slower than the Java port), and rendered with
/// shared `Date.VerbatimFormatStyle`s instead of a new `DateFormatter` per
/// date. Both are only allowed because they never change an answer, so each
/// is compared here with the formatter it replaced, on whichever Foundation
/// the suite is built against.
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

    // MARK: render

    func testRenderAgreesWithDateFormatterOnGeneratedInstants() {
        var random = SplitMix64(seed: Self.seed ^ 1)
        for _ in 0..<5_000 {
            // The whole range decodeDate lets through, 0001 to 9999: before
            // the Gregorian cutover, around the 2007 US rule change, and far
            // past the last transition the time zone database lists.
            let seconds = Double.random(in: -62_135_596_800...253_402_300_799, using: &random)
            let whole = seconds.rounded(.down)
            for instant in [seconds, whole, whole - 0.0004, whole - 0.0006, whole.nextDown] {
                comparesRender(Date(timeIntervalSince1970: instant))
            }
        }
    }

    /// Every Los Angeles offset change from 1900 to 2100, approached from
    /// both sides at the hour, the second, the millisecond and the closest
    /// representable instants.
    func testRenderAgreesWithDateFormatterAroundEveryOffsetChange() {
        let pacific = TimeZone(identifier: "America/Los_Angeles")!
        var instant = Date(timeIntervalSince1970: -2_208_988_800)  // 1900-01-01
        let end = Date(timeIntervalSince1970: 4_102_444_800)  // 2100-01-01
        var transitions = 0
        while let next = pacific.nextDaylightSavingTimeTransition(after: instant), next < end {
            let t = next.timeIntervalSince1970
            for offset in [-3600, -1, -0.001, -0.0006, -0.0004, 0, 0.001, 1, 3600] {
                comparesRender(Date(timeIntervalSince1970: t + offset))
            }
            comparesRender(Date(timeIntervalSince1970: t.nextDown))
            comparesRender(Date(timeIntervalSince1970: t.nextUp))
            transitions += 1
            instant = next
        }
        XCTAssertGreaterThan(transitions, 300, "transitions: \(transitions)")
    }

    /// The styles are shared by every thread, which only `Sendable` values
    /// may be; this checks concurrent use gives the answers serial use does.
    func testRenderAndParseGiveTheSameAnswersFromManyThreads() async {
        let instants = (0..<2_000).map { Date(timeIntervalSince1970: Double($0) * 86_417.123) }
        let expected = instants.map(renderBoth)
        let texts = instants.map { canonicalText($0) }
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    zip(instants, expected).allSatisfy { renderBoth($0) == $1 }
                        && zip(instants, texts).allSatisfy {
                            parseCanonicalReceiptDate($1)?.timeIntervalSince1970
                                == $0.timeIntervalSince1970.rounded(.down)
                        }
                }
            }
            for await agreed in group {
                XCTAssertTrue(agreed)
            }
        }
    }

    private func comparesRender(_ date: Date) {
        for (style, zone) in [
            (appleGMTDateStyle, "UTC"), (applePacificDateStyle, "America/Los_Angeles"),
        ] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: zone)!
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            XCTAssertEqual(
                formatAppleDate(date, style), formatter.string(from: date),
                "\(date.timeIntervalSince1970) in \(zone)")
        }
    }
}

private func renderBoth(_ date: Date) -> String {
    formatAppleDate(date, appleGMTDateStyle) + " " + formatAppleDate(date, applePacificDateStyle)
}

private func canonicalText(_ date: Date) -> String {
    Date.ISO8601FormatStyle().format(date)
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
