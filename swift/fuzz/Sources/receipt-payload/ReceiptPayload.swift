import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The receipt attribute-SET walk and the string, integer and date decoders
// under it, on bytes the fuzzer chose.
//
// They are reachable no other way: `parseAttributeSet`, `decodeString`,
// `decodeInteger` and `decodeDate` are file-private inside
// ReceiptVerifier.swift, so not even `@testable` reaches them, and the
// `receipt-der` target only stumbles into them on an input it has already
// grown into a valid CMS envelope. This target splices the input in as a
// genuine receipt's payload instead, so every single execution reaches the
// walk. See `PayloadSplice` for why that works and why a spliced receipt can
// still never verify.
//
// It is a target of its own rather than a fifth check inside `readers`
// because it is thousands of times the cost: the payload parse is followed
// by a certificate-bag walk, a chain build and an RSA verification, none of
// which this target is about but none of which the public API can skip.
// Sharing an execution with the base64 readers would drag those down to this
// target's rate for nothing.

private let splice = PayloadSplice(template: Fixtures.load("generated", "receipt.der"))
private let verifier: ReceiptVerifier = {
    guard
        let verifier = try? ReceiptVerifier(
            trustedRoots: [Fixtures.receiptRoot], bundleId: Fixtures.bundleId)
    else {
        fatalError("fuzz harness setup failed: the anchor set is not loadable")
    }
    return verifier
}()

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReceiptPayload(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let receipt = splice.receipt(payload: fuzzInput(start, count))
    do {
        _ = try blocking { try await verifier.verifyCore(receipt: receipt) }
        // Not an error: the fuzzer can rediscover the template's own payload
        // from the seeds, and that receipt is genuine.
    } catch {
        _ = requireTypedError(error, "the attribute-set walk")
    }
    return 0
}
