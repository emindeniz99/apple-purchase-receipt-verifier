import Foundation
import XCTest

/// The conformance harness reads a verified payload's fields back from the
/// text as signed. Duplicate keys in that text must resolve to the LAST
/// member on every platform, as the library itself resolves them; Darwin's
/// `JSONSerialization` resolves them to the first, which made
/// `signed-data/duplicate-signed-date-last-wins` fail on macOS only.
/// The expectations here are literals, never a `JSONSerialization` read,
/// so this test cannot inherit the platform's policy.
final class LastWinsJsonTests: XCTestCase {
    func testDuplicateTopLevelKeyReadsTheLastMember() throws {
        let text = #"{"signedDate":1590969600000,"bundleId":"com.example.app","signedDate":1722945600000}"#
        let object = try XCTUnwrap(try parseJsonLastWins(text) as? [String: Any])
        XCTAssertEqual((object["signedDate"] as? NSNumber)?.int64Value, 1_722_945_600_000)
        XCTAssertEqual(object["bundleId"] as? String, "com.example.app")
    }

    func testDuplicateNestedKeyReadsTheLastMember() throws {
        let text = #"{"data":{"status":1,"status":2},"list":[{"k":"a","k":"b"}]}"#
        let object = try XCTUnwrap(try parseJsonLastWins(text) as? [String: Any])
        let data = try XCTUnwrap(object["data"] as? [String: Any])
        XCTAssertEqual((data["status"] as? NSNumber)?.int64Value, 2)
        let list = try XCTUnwrap(object["list"] as? [Any])
        XCTAssertEqual((list.first as? [String: Any])?["k"] as? String, "b")
    }

    func testIntegersBeyondDoublePrecisionKeepTheirDigits() throws {
        let object = try XCTUnwrap(try parseJsonLastWins(#"{"id":9007199254740993}"#) as? [String: Any])
        XCTAssertEqual((object["id"] as? NSNumber)?.int64Value, 9_007_199_254_740_993)
    }

    func testEscapesAndLiterals() throws {
        let text = #"{"s":"a\"\\\/\né😀","t":true,"f":false,"n":null,"d":1.5}"#
        let object = try XCTUnwrap(try parseJsonLastWins(text) as? [String: Any])
        XCTAssertEqual(object["s"] as? String, "a\"\\/\n\u{e9}\u{1F600}")
        XCTAssertEqual(object["t"] as? Bool, true)
        XCTAssertEqual(object["f"] as? Bool, false)
        XCTAssertTrue(object["n"] is NSNull)
        XCTAssertEqual((object["d"] as? NSNumber)?.doubleValue, 1.5)
    }

    func testTrailingContentIsRefused() {
        XCTAssertThrowsError(try parseJsonLastWins(#"{"a":1}x"#))
    }
}
