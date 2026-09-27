import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The receipt attribute-SET walk and the string, integer and date decoders
// under it, on bytes the fuzzer chose, called directly.
//
// In 0.7 the full payload parse runs only after the chain and a signer
// signature have verified, so no receipt the fuzzer can build reaches it
// from outside; this target calls the parser through the `Readers` shim
// instead, which is the only way every execution reaches the walk. The one
// read that does run on unverified bytes, `readCreationDate`, is driven on
// the same input.
//
// Invariants beyond "nothing traps":
//
//  1. a parse failure is the parser's own `PayloadError`, the error the
//     verifier hands a caller as the `UNREADABLE_PAYLOAD` cause;
//  2. the unverified creation-date read agrees with the full parse: when the
//     set parses, `readCreationDate` returns exactly the typed
//     `receiptCreationDateMs`. Both apply "the first attribute 12 wins", and
//     a disagreement would judge the chain at an instant other than the date
//     the caller is handed.
//
// It is a target of its own rather than a check inside `readers` because a
// payload input is ASN.1, not text, and the corpora do not mix well.

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReceiptPayload(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let content = fuzzInput(start, count)
    let creationDate = Readers.readCreationDate(content)
    switch Readers.parseReceiptPayload(content) {
    case .success(let payload):
        if payload.receiptCreationDateMs != creationDate {
            fail(
                "the unverified creation-date read gave \(String(describing: creationDate)), "
                    + "the full parse \(String(describing: payload.receiptCreationDateMs))")
        }
    case .failure(let error):
        if !Readers.isPayloadError(error) {
            fail("the payload parse failed with \(type(of: error)) instead of PayloadError: \(error)")
        }
    }
    return 0
}
