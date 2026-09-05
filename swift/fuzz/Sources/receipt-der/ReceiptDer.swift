import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The whole legacy-receipt path on DER bytes: the BER-tolerant CMS walk, the
// attribute-set payload parse, the certificate-bag walk, chain building on
// swift-certificates, and the RSA signature check.
//
// Three invariants, the same three the Go and Rust ports state:
//
//  1. nothing traps — in Swift that covers fatalError, a force-unwrap, an
//     out-of-range index and an arithmetic overflow, all of which abort the
//     process rather than throw, so libFuzzer records them as crashes;
//  2. a failure is a `VerificationError`, never some other error type that a
//     caller's `catch` would miss;
//  3. an accepted receipt is accepted *because of the anchors*, proven by
//     re-running it against an unrelated anchor set and requiring a failure.
//
// The third is the one that lets a fuzzer find "accepts what it should not"
// rather than only crashes. Without it, an input that verifies tells you
// nothing about why it verified.
//
// The trusted set is the pinned Apple receipt roots plus the generated
// fixture receipt root, so the shared fixture receipts and the two public
// Apple receipts all get past the chain check and the fuzzer can explore
// what lies beyond it. The unrelated set is the fixture *JWS* root: a real
// anchor, issued by the same generator, that signed none of these receipts.

private let trusted = ReceiptVerifier.make(
    roots: appleReceiptRoots() + [Fixtures.receiptRoot], what: "trusted")
private let unrelated = ReceiptVerifier.make(roots: [Fixtures.jwsRoot], what: "unrelated")

extension ReceiptVerifier {
    fileprivate static func make(roots: [Data], what: String) -> ReceiptVerifier {
        guard let verifier = try? ReceiptVerifier(trustedRoots: roots, bundleId: Fixtures.bundleId)
        else {
            fatalError("fuzz harness setup failed: the \(what) anchor set is not loadable")
        }
        return verifier
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReceiptDer(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let receipt = Data(fuzzInput(start, count))
    do {
        // verifyCore, not verify(receipt:): the bundle-id claim check is not
        // what this target is about, and stopping at it would hide the
        // anchor invariant behind an unrelated comparison.
        _ = try blocking { try await trusted.verifyCore(receipt: receipt) }
    } catch {
        _ = requireTypedError(error, "verifyCore")
        return 0
    }
    do {
        _ = try blocking { try await unrelated.verifyCore(receipt: receipt) }
        fail(
            "this receipt verifies against an unrelated anchor set too, "
                + "so the anchors are not what decided it")
    } catch {
        _ = requireTypedError(error, "verifyCore against the unrelated anchor set")
    }
    return 0
}
