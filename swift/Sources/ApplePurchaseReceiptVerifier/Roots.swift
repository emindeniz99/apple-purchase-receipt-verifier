import Crypto
import Foundation
import SwiftASN1
import X509

/// Apple marker OID on the leaf that signs App Store JWS payloads and legacy
/// receipts alike. The chain check alone is not enough: developer
/// certificates ("Apple Distribution", "Apple Development") chain through the
/// same WWDR intermediate to the same pinned root, so without this purpose
/// check any developer could sign a forged payload or receipt.
let signingLeafOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 11, 1]

/// Apple marker OID on the Worldwide Developer Relations intermediate CA
/// that issues the signing leaf.
let wwdrIntermediateOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 2, 1]

/// The three published Apple roots, bundled with this package (copies of the
/// public roots from https://www.apple.com/certificateauthority/). Apple's
/// guidance is to trust every root on that page, not a single one — see
/// PLAN.md D15 — so all three are pinned for both formats.
private let bundledRootFiles: [(name: String, sha256: String)] = [
    ("AppleIncRootCertificate", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"),
    ("AppleRootCA-G2", "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050"),
    ("AppleRootCA-G3", "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"),
]

/// The bundled Apple roots, loaded once per process: all three, or none.
///
/// Each file is checked against its published SHA-256 before it is trusted,
/// so a `certs/` file swapped at build time cannot become an anchor. A root
/// that is missing, does not parse, or does not match its fingerprint empties
/// the WHOLE set — a set silently one root short would verify until the day
/// Apple signed under the missing one — and ``Config/defaults()`` then hands
/// a ``Verifier`` an empty root set, which answers ``Reason/internalError``
/// to every call rather than a misleading ``Reason/untrustedChain``.
///
/// Loaded from the package's bundled resources, not read from disk at call
/// time beyond that one bundle lookup, so this works unchanged in a minimal
/// container image.
let bundledAppleRoots: [Certificate] = {
    var roots: [Certificate] = []
    for file in bundledRootFiles {
        guard
            let url = Bundle.module.url(
                forResource: file.name, withExtension: "cer", subdirectory: "certs"),
            let data = try? Data(contentsOf: url)
        else { return [] }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard digest == file.sha256, let certificate = try? Certificate(derEncoded: [UInt8](data))
        else { return [] }
        roots.append(certificate)
    }
    return roots
}()
