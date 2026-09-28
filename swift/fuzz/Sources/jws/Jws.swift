import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The StoreKit 2 path through `Verifier.verifySignedData(jws:)`: compact-JWS
// split, strict unpadded base64url on each segment, the JSON header and
// payload readers under their bounds, the `x5c` certificates, the top-down
// chain check at the payload's own signed date, the marker OIDs and the
// ES256 signature check.
//
// Two invariants beyond "nothing traps": the answer is never INTERNAL_ERROR,
// and a JWS accepted under the fixture JWS root must be refused under
// Apple's pinned roots, or the anchors are not what decided it.
//
// The trusted verifier anchors on fixtures/generated/jws-root.der, so every
// generated JWS fixture verifies end to end and the fuzzer explores past the
// chain check.

private let trusted = Fixtures.verifier(roots: [Fixtures.jwsRoot], what: "fixture")
private let unrelated = Fixtures.verifier(roots: Fixtures.appleRoots, what: "Apple")

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzJws(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let jws = fuzzText(start, count) else { return -1 }
    let result = trusted.verifySignedData(jws: jws)
    requireNoInternalError(result, "verifySignedData")
    guard result.verified else { return 0 }
    let elsewhere = unrelated.verifySignedData(jws: jws)
    requireNoInternalError(elsewhere, "verifySignedData against Apple's roots")
    if elsewhere.verified {
        fail("this JWS verifies against Apple's roots too, so the anchors are not what decided it")
    }
    return 0
}
