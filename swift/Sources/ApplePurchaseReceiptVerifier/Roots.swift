import Foundation

/// Loads the Apple root certificates bundled with this package (copies of
/// the public roots from https://www.apple.com/certificateauthority/).
/// Production trust anchors; tests use the shared fixture PKI instead.
///
/// Both sets contain all three published Apple roots. Apple deliberately
/// documents the JWS chain as ending in "an Apple root certificate" (not a
/// specific one) and its guidance is to trust every root on the PKI page,
/// so anchoring on a single root would break silently if Apple re-anchored
/// a path — see PLAN.md D15.
private func load(_ name: String) -> Data {
    guard let url = Bundle.module.url(forResource: name, withExtension: "cer",
                                      subdirectory: "certs"),
          let data = try? Data(contentsOf: url) else {
        fatalError("bundled certificate missing: \(name).cer")
    }
    return data
}

private func allRoots() -> [Data] {
    [
        load("AppleIncRootCertificate"),
        load("AppleRootCA-G2"),
        load("AppleRootCA-G3"),
    ]
}

/// Trust anchors for StoreKit 2 / App Store Server JWS chains.
/// Production chains currently end at Apple Root CA - G3.
public func appleJwsRoots() -> [Data] {
    allRoots()
}

/// Trust anchors for legacy PKCS#7 app-receipt chains.
/// Production chains currently end at the Apple Inc. Root CA.
public func appleReceiptRoots() -> [Data] {
    allRoots()
}
