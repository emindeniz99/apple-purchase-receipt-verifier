import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The endpoint renders every receipt date in Apple's two spellings with
/// shared `Date.VerbatimFormatStyle`s rather than a new `DateFormatter` per
/// date (DateTime.swift says why: a formatter per date cost about 95 µs on
/// Linux, and swift-corelibs-foundation's `DateFormatter` cannot be shared
/// between threads). That is only allowed because it never changes an
/// answer, so it is compared here with the formatter it replaced, on
/// whichever Foundation the suite is built against. The shared endpoint
/// cases pin a handful of instants; these walk the whole range the endpoint
/// can be handed and every Los Angeles offset change.
///
/// Parsing is not compared: 0.7 reads a receipt date with a hand-written
/// grammar (`YYYY-MM-DDTHH:MM:SSZ` and nothing else) that no formatter
/// matches, and `receipt/date-grammar` pins it in every port.
///
/// The generators are seeded, so a failure reproduces.
final class ReceiptDateTests: XCTestCase {
    private static let seed: UInt64 = 0xDA7E_5EED

    func testRenderAgreesWithDateFormatterOnGeneratedInstants() {
        var random = SplitMix64(seed: Self.seed ^ 1)
        for _ in 0..<5_000 {
            // Year 0000 to 9999, the whole range a receipt date can parse to:
            // before the Gregorian cutover, around the 2007 US rule change,
            // and far past the last transition the time zone database lists.
            let millis = Int64.random(in: -62_167_219_200_000...253_402_300_799_999, using: &random)
            let whole = millis - ((millis % 1000) + 1000) % 1000
            for instant in [millis, whole, whole - 1, whole + 999] {
                comparesRender(instant)
            }
        }
    }

    /// Every Los Angeles offset change from 1900 to 2100, approached from
    /// both sides at the hour, the second and the millisecond.
    func testRenderAgreesWithDateFormatterAroundEveryOffsetChange() {
        let pacific = TimeZone(identifier: "America/Los_Angeles")!
        var instant = Date(timeIntervalSince1970: -2_208_988_800)  // 1900-01-01
        let end = Date(timeIntervalSince1970: 4_102_444_800)  // 2100-01-01
        var transitions = 0
        while let next = pacific.nextDaylightSavingTimeTransition(after: instant), next < end {
            let t = Int64((next.timeIntervalSince1970 * 1000).rounded())
            for offset: Int64 in [-3_600_000, -1000, -1, 0, 1, 1000, 3_600_000] {
                comparesRender(t + offset)
            }
            transitions += 1
            instant = next
        }
        XCTAssertGreaterThan(transitions, 300, "transitions: \(transitions)")
    }

    /// The styles are shared by every thread, which only `Sendable` values
    /// may be; this checks concurrent use gives the answers serial use does.
    func testRenderGivesTheSameAnswersFromManyThreads() async {
        let instants = (0..<2_000).map { Int64($0) * 86_417_123 }
        let expected = instants.map(renderBoth)
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 {
                group.addTask { zip(instants, expected).allSatisfy { renderBoth($0) == $1 } }
            }
            for await agreed in group {
                XCTAssertTrue(agreed)
            }
        }
    }

    private func comparesRender(_ millis: Int64) {
        let date = dateFromMillis(millis)
        for (rendered, zone) in [
            (formatEtcGMT(millis: millis), "Etc/GMT"), (formatPacific(millis: millis), "America/Los_Angeles"),
        ] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: zone == "Etc/GMT" ? "UTC" : zone)!
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            XCTAssertEqual(rendered, formatter.string(from: date) + " " + zone, "\(millis) in \(zone)")
        }
    }
}

private func renderBoth(_ millis: Int64) -> String {
    formatEtcGMT(millis: millis) + " " + formatPacific(millis: millis)
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
