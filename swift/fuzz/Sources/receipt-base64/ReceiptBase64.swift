import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// `Verifier.verifyReceipt(base64:)` on the string a client actually sends.
// The receipt-base64 rule (`decodeReceiptBase64`) runs first, then the whole
// DER path behind it.
//
// Seeded from fixtures/generated/receipt-b64 and fixtures/public-receipts, so
// the fuzzer starts from strings that decode and verify rather than from
// noise it would have to grow into base64 by itself.
//
// Input that is not UTF-8 is skipped: the entry point takes a `String`, so
// those bytes cannot reach it, and repairing them would fuzz the repair.
//
// The anchor invariant from the DER target is carried here too — this path
// ends in the same chain check, and an accepted string that also verifies
// under an unrelated anchor set is the same bug seen through the transport
// form a client uses.

private let trusted = Fixtures.verifier(
    roots: Fixtures.appleRoots + [Fixtures.receiptRoot], what: "trusted")
private let unrelated = Fixtures.verifier(roots: [Fixtures.jwsRoot], what: "unrelated")

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReceiptBase64(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let text = fuzzText(start, count) else { return -1 }
    let result = trusted.verifyReceipt(base64: text)
    requireNoInternalError(result, "verifyReceipt(base64:)")
    guard result.verified else { return 0 }
    let elsewhere = unrelated.verifyReceipt(base64: text)
    requireNoInternalError(elsewhere, "verifyReceipt(base64:) against the unrelated anchor set")
    if elsewhere.verified {
        fail(
            "this base64 receipt verifies against an unrelated anchor set too, "
                + "so the anchors are not what decided it")
    }
    return 0
}
