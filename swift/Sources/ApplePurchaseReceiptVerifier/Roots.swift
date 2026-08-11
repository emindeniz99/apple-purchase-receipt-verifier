import Foundation

/// Loads the Apple root certificates bundled with this package (copies of
/// the public roots from https://www.apple.com/certificateauthority/).
/// Production trust anchors; tests use the shared fixture PKI instead.
private func load(_ name: String) -> Data {
    guard let url = Bundle.module.url(forResource: name, withExtension: "cer",
                                      subdirectory: "certs"),
          let data = try? Data(contentsOf: url) else {
        fatalError("bundled certificate missing: \(name).cer")
    }
    return data
}

/// Apple Root CA - G3 — anchors StoreKit 2 / App Store Server JWS chains.
public func appleJwsRoots() -> [Data] {
    [load("AppleRootCA-G3")]
}

/// Apple Inc. Root CA — anchors legacy PKCS#7 app-receipt chains.
public func appleReceiptRoots() -> [Data] {
    [load("AppleIncRootCertificate")]
}
