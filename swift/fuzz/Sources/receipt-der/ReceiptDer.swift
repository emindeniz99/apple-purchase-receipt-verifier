import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The whole legacy-receipt path on DER bytes, given to `verifyReceipt` as
// the canonical base64 a client would send: the BER-tolerant CMS walk, the
// unverified creation-date read, the certificate-bag walk, the top-down
// chain check, the marker OIDs, the signer signature and, once that
// verifies, the payload parse.
//
// Three invariants, the same three the Go and Rust ports state:
//
//  1. nothing traps — in Swift that covers fatalError, a force-unwrap, an
//     out-of-range index and an arithmetic overflow, all of which abort the
//     process, so libFuzzer records them as crashes;
//  2. the answer is never INTERNAL_ERROR, which input must not be able to
//     raise (`requireNoInternalError`);
//  3. an accepted receipt is accepted *because of the anchors*, proven by
//     re-running it against an unrelated anchor set and requiring a failure.
//
// The third is the one that lets a fuzzer find "accepts what it should not"
// rather than only crashes. Without it, an input that verifies tells you
// nothing about why it verified.
//
// The trusted set is the pinned Apple roots plus the 0.7 generated fixture
// receipt root, so the shared fixture receipts and the two public Apple
// receipts all get past the chain check and the fuzzer can explore what lies
// beyond it. The unrelated set is the fixture *JWS* root: a real anchor,
// issued by the same generator, that signed none of these receipts.

private let trusted = Fixtures.verifier(
    roots: Fixtures.appleRoots + [Fixtures.receiptRoot], what: "trusted")
private let unrelated = Fixtures.verifier(roots: [Fixtures.jwsRoot], what: "unrelated")

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReceiptDer(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let base64 = Data(fuzzInput(start, count)).base64EncodedString()
    let result = trusted.verifyReceipt(base64: base64)
    requireNoInternalError(result, "verifyReceipt")
    guard result.verified else { return 0 }
    let elsewhere = unrelated.verifyReceipt(base64: base64)
    requireNoInternalError(elsewhere, "verifyReceipt against the unrelated anchor set")
    if elsewhere.verified {
        fail("this receipt verifies against an unrelated anchor set too, so the anchors are not what decided it")
    }
    return 0
}
