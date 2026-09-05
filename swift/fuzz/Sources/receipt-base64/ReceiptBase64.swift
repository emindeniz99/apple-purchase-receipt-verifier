import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// `ReceiptVerifier.verify(base64Receipt:)` — the string a client actually
// sends. The receipt-base64 rule (`decodeReceiptBase64`) runs first, then the
// whole DER path behind it, then the bundle-id claim check.
//
// Seeded from fixtures/generated/receipt-b64 and fixtures/public-receipts, so
// the fuzzer starts from strings that decode and verify rather than from
// noise it would have to grow into base64 by itself.
//
// Input that is not UTF-8 is skipped: the entry point takes a `String`, so
// those bytes cannot reach it, and repairing them would fuzz the repair.
//
// The anchor invariant from the DER target is carried here too — this path
// ends in the same chain build, and an accepted string that also verifies
// under an unrelated anchor set is the same bug seen through the transport
// form a client uses.

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
public func fuzzReceiptBase64(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let text = fuzzText(start, count) else { return -1 }
    do {
        _ = try blocking { try await trusted.verify(base64Receipt: text) }
    } catch {
        _ = requireTypedError(error, "verify(base64Receipt:)")
        return 0
    }
    do {
        _ = try blocking { try await unrelated.verify(base64Receipt: text) }
        fail(
            "this base64 receipt verifies against an unrelated anchor set too, "
                + "so the anchors are not what decided it")
    } catch {
        _ = requireTypedError(error, "verify(base64Receipt:) against the unrelated anchor set")
    }
    return 0
}
