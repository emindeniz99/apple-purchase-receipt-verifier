import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// `decodeReceiptBase64` must answer what Apple's verifyReceipt answered on
/// 2026-09-23 for the same spellings of genuine receipts
/// (docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple
/// decodes must decode here to the same bytes; a spelling Apple answers 21002
/// must be refused here, or a receipt verifies in Swift that Apple itself
/// refuses. The conformance cases pin the rule on a real receipt; this pins
/// each shape on its own, including the ones `Data(base64Encoded:)` alone
/// would have accepted.
final class ReceiptBase64Tests: XCTestCase {
    func testCanonicalSpellingsAndTrailingBitsDecode() {
        let accepted: [(String, [UInt8])] = [
            ("QUJD", Array("ABC".utf8)),
            ("QUI=", Array("AB".utf8)),
            ("QQ==", Array("A".utf8)),
            ("+/8=", [0xFB, 0xFF]),
            // Unused low bits set in the last data character: Apple accepts them.
            ("QR==", Array("A".utf8)),
            ("Qf==", Array("A".utf8)),
            ("QUJ=", Array("AB".utf8)),
        ]
        for (text, expected) in accepted {
            XCTAssertEqual(decodeReceiptBase64(text).map { [UInt8]($0) }, expected, text)
        }
    }

    func testEveryOtherSpellingIsRefused() {
        let refused = [
            "",
            "QQ", "QUI",  // padding omitted
            "QQ=",  // under-padded
            "QQ===", "QQ====",  // extra padding: Data(base64Encoded:) on Linux accepts these
            "QUJD=", "QUJD==", "QUJD====", "====",  // padding after a full group
            "Q===", "QUJDR",  // impossible length
            "QQ==QUJD", "QQ==!!!!", "QQ=A",  // data or junk after the padding
            "QU!D",  // junk inside
            "QUJD\n", "QUJD\r\n", "QUJD\nQUJD",  // line feeds
            " QUJD", "QU JD", "QU\tJD", "  QUJD  ",  // other whitespace
            "-_8=", "-_8", "+_8=",  // base64url, unpadded, mixed
            "QUJ\u{e9}",  // outside ASCII
        ]
        for text in refused {
            XCTAssertNil(decodeReceiptBase64(text), text.debugDescription)
        }
    }
}
