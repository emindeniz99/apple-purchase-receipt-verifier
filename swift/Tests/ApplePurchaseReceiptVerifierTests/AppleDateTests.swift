import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Receipt dates are parsed and rendered by arithmetic on the shapes genuine
/// receipts use, and by Foundation otherwise (AppleDate.swift says why: a
/// formatter per date made a 187-purchase receipt about 50 times slower than
/// the Java port). The arithmetic is only allowed because it never changes an
/// answer, so each half is compared here with the Foundation code it
/// replaced, on whichever Foundation the suite is built against: CI proves it
/// on Linux and on macOS separately.
///
/// The generators are seeded, so a failure reproduces.
final class AppleDateTests: XCTestCase {
    private static let seed: UInt64 = 0xDA7E_5EED

    // MARK: parse

    func testParseAgreesWithFoundationOnGeneratedStrings() {
        var random = SplitMix64(seed: Self.seed)
        var canonical = 0
        var other = 0
        for _ in 0..<20_000 {
            let text = generateDateText(&random)
            if comparesParse(text) { canonical += 1 } else { other += 1 }
        }
        // Both branches must run many times for the comparison to mean anything.
        XCTAssertGreaterThan(canonical, 5_000, "canonical strings: \(canonical)")
        XCTAssertGreaterThan(other, 5_000, "other strings: \(other)")
    }

    func testParseAgreesWithFoundationOnHandPickedEdges() {
        let edges = [
            "", "Z", "1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z", "2000-02-29T12:00:00Z",
            "1900-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2023-02-29T00:00:00Z",
            "2024-02-30T00:00:00Z", "2024-04-31T00:00:00Z", "2024-12-31T23:59:59Z",
            "2016-12-31T23:59:60Z", "2024-01-01T24:00:00Z", "2024-01-01T23:60:00Z",
            "2024-00-10T00:00:00Z", "2024-13-10T00:00:00Z", "2024-01-00T00:00:00Z",
            "9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z",
            "1582-10-10T00:00:00Z", "2024-01-01T00:00:00z", "2024-01-01t00:00:00Z",
            "2024-01-01 00:00:00Z", "2024-01-01T00:00:00", "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00-08:00", "2024-01-01T00:00:00.000Z", "2024-01-01T00:00:00.5Z",
            "999999-12-31T23:59:59Z", "+2024-01-01T00:00:00Z", "2024-1-01T00:00:00Z",
            "２０２４-01-01T00:00:00Z", "2024-01-01T00:00:00Z ", " 2024-01-01T00:00:00Z",
        ]
        for edge in edges {
            comparesParse(edge)
        }
    }

    /// Asserts both parses give the same `Date` or both nil; returns whether
    /// the input had the canonical shape the arithmetic path takes.
    @discardableResult
    private func comparesParse(_ text: String) -> Bool {
        XCTAssertEqual(parseReceiptDate(text), parseReceiptDateWithFoundation(text), text.debugDescription)
        return text.utf8.count == 20 && text.hasSuffix("Z")
    }

    private func generateDateText(_ random: inout SplitMix64) -> String {
        let year = Int.random(in: 1960...10_000, using: &random)
        let fields = [
            year,
            Int.random(in: 0...13, using: &random),
            Int.random(in: 0...32, using: &random),
            Int.random(in: 0...24, using: &random),
            Int.random(in: 0...60, using: &random),
            Int.random(in: 0...60, using: &random),
        ]
        // Most strings keep every field in range, so the arithmetic path is
        // taken often; out-of-range fields above exercise the fallback.
        var f = fields
        if Int.random(in: 0..<4, using: &random) != 0 {
            f[1] = Int.random(in: 1...12, using: &random)
            f[2] = Int.random(in: 1...31, using: &random)
            f[3] = Int.random(in: 0...23, using: &random)
            f[4] = Int.random(in: 0...59, using: &random)
            f[5] = Int.random(in: 0...59, using: &random)
        }
        let pad = { (value: Int, width: Int) -> String in
            let digits = String(value)
            return String(repeating: "0", count: max(0, width - digits.count)) + digits
        }
        var text =
            "\(pad(f[0], 4))-\(pad(f[1], 2))-\(pad(f[2], 2))T\(pad(f[3], 2)):\(pad(f[4], 2)):\(pad(f[5], 2))"
        switch Int.random(in: 0..<10, using: &random) {
        case 0: text += ".\(pad(Int.random(in: 0...999, using: &random), 3))Z"
        case 1: text += "+00:00"
        case 2: text += "-07:00"
        case 3: text += "z"
        case 4: break
        default: text += "Z"
        }
        return text
    }

    // MARK: render

    func testRenderAgreesWithFoundationOnGeneratedInstants() {
        var random = SplitMix64(seed: Self.seed ^ 1)
        for _ in 0..<5_000 {
            // 1990 through 9999: both sides of the 2007 rule boundary and the
            // far end of the arithmetic range.
            let seconds = Double.random(in: 631_152_000...253_402_300_799, using: &random)
            comparesRender(Date(timeIntervalSince1970: seconds))
            comparesRender(Date(timeIntervalSince1970: seconds.rounded(.down)))
        }
    }

    /// Every daylight-saving transition in the rule range this suite can
    /// afford, approached from both sides at the second, the millisecond and
    /// the closest representable instants.
    func testRenderAgreesWithFoundationAroundEveryDaylightSavingTransition() {
        let pacific = TimeZone(identifier: "America/Los_Angeles")!
        var instant = Date(timeIntervalSince1970: 1_167_638_400)  // 2007-01-01 PST
        let end = Date(timeIntervalSince1970: 4_102_444_800)  // 2100-01-01
        var transitions = 0
        while let next = pacific.nextDaylightSavingTimeTransition(after: instant), next < end {
            let t = next.timeIntervalSince1970
            // -0.0004 renders as the transition second itself and -0.0006
            // as the one before: Foundation rounds to the nearest millisecond.
            for offset in [-3600.0, -1, -0.001, -0.0006, -0.0004, 0, 0.001, 1, 3600] {
                comparesRender(Date(timeIntervalSince1970: t + offset))
            }
            comparesRender(Date(timeIntervalSince1970: t.nextDown))
            comparesRender(Date(timeIntervalSince1970: t.nextUp))
            instant = next
            transitions += 1
        }
        XCTAssertEqual(transitions, 186, "two transitions a year, 2007 through 2099")
    }

    func testRenderAgreesWithFoundationOnHandPickedEdges() {
        let seconds: [Double] = [
            0, -1, 1_167_638_400, 1_167_638_400.0.nextDown, 1_167_638_399,
            253_402_214_400, 253_402_214_400.0.nextDown, 253_402_300_799, 253_402_300_800,
            1_709_251_199.999_999_9, 1_767_225_599.999_999_8, 1_767_225_600,
            951_782_400, 4_107_542_400,  // 2000-02-29, 2100-03-01
            .nan, .infinity, -.infinity,
        ]
        for value in seconds {
            comparesRender(Date(timeIntervalSince1970: value))
        }
        // Instants just below a whole second, where the conversion to
        // milliseconds can round up into the next second.
        var random = SplitMix64(seed: Self.seed ^ 2)
        for _ in 0..<2_000 {
            let whole = Double(Int.random(in: 1_167_638_400...4_102_444_800, using: &random))
            comparesRender(Date(timeIntervalSince1970: whole.nextDown))
            comparesRender(Date(timeIntervalSince1970: whole.nextDown.nextDown))
            comparesRender(Date(timeIntervalSinceReferenceDate: (whole - 978_307_200).nextDown))
        }
    }

    private func comparesRender(_ date: Date, file: StaticString = #filePath, line: UInt = #line) {
        let shown = "\(date.timeIntervalSince1970) (reference \(date.timeIntervalSinceReferenceDate))"
        XCTAssertEqual(
            appleDateString(date, pacific: false), foundationAppleDateString(date, pacific: false),
            "UTC \(shown)", file: file, line: line)
        XCTAssertEqual(
            appleDateString(date, pacific: true), foundationAppleDateString(date, pacific: true),
            "Pacific \(shown)", file: file, line: line)
    }
}
