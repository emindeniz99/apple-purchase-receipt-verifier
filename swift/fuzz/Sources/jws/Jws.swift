import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// The StoreKit 2 path, through all three public entry points: compact-JWS
// split, strict unpadded base64url on each segment, JSON header and payload,
// the `x5c` certificates and their Apple marker OIDs, chain building at the
// payload's own signed date, the ES256 signature check, and then the claim
// checks each entry point adds on top.
//
// Two invariants beyond "nothing traps and every failure is typed": a JWS
// that `verifyRaw` accepts under the fixture JWS root must be refused under
// Apple's production JWS roots, or the anchors are not what decided it; and
// `verifyTransaction` / `verifyAppTransaction` may only ever fail with the
// same typed error, since they are `verifyRaw` plus claim comparisons.
//
// The trusted verifier anchors on fixtures/generated/jws-root.der and takes
// the fixture bundle id and Sandbox environment, so every generated JWS
// fixture verifies end to end and the fuzzer explores past the chain build.

private let trusted = JwsVerifier.make(roots: [Fixtures.jwsRoot], what: "fixture")
private let unrelated = JwsVerifier.make(roots: appleJwsRoots(), what: "Apple production")

extension JwsVerifier {
    fileprivate static func make(roots: [Data], what: String) -> JwsVerifier {
        guard
            let verifier = try? JwsVerifier(
                trustedRoots: roots, bundleId: Fixtures.bundleId,
                acceptedEnvironments: [.sandbox, .production],
                appAppleId: 123_456_789)
        else {
            fatalError("fuzz harness setup failed: the \(what) anchor set is not loadable")
        }
        return verifier
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzJws(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let jws = fuzzText(start, count) else { return -1 }

    do {
        _ = try blocking { try await trusted.verifyTransaction(jws) }
    } catch {
        _ = requireTypedError(error, "verifyTransaction")
    }
    do {
        _ = try blocking { try await trusted.verifyAppTransaction(jws) }
    } catch {
        _ = requireTypedError(error, "verifyAppTransaction")
    }

    do {
        // The claims are `[String: Any]`, which is not Sendable; the count is,
        // and asking for it still materialises the whole dictionary.
        _ = try blocking { try await trusted.verifyRaw(jws).count }
    } catch {
        _ = requireTypedError(error, "verifyRaw")
        return 0
    }
    do {
        _ = try blocking { try await unrelated.verifyRaw(jws).count }
        fail(
            "this JWS verifies against Apple's production roots too, "
                + "so the anchors are not what decided it")
    } catch {
        _ = requireTypedError(error, "verifyRaw against Apple's production roots")
    }
    return 0
}
