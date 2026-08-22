import ApplePurchaseReceiptVerifier
import Foundation

/// Smoke-tests the library as resolved from the published tag. Everything it
/// touches — the verifier, the error type, the bundled root certificates — comes
/// from the dependency, so a tag missing its resources fails here rather than in
/// a user's project.
@main
struct Smoke {
    static func main() async throws {
        let receiptB64 = try String(contentsOfFile: "receipt-sandbox-g5.b64", encoding: .ascii)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // A real Apple-signed receipt against the real pinned root: exercises
        // the packaged certs, the DER reader, the chain build and the signature.
        let verifier = try ReceiptVerifier(trustedRoots: appleReceiptRoots(),
                                           bundleId: "dev.bonzer.weeka.app")
        let receipt = try await verifier.verify(base64Receipt: receiptB64)
        guard receipt.receiptType == "ProductionSandbox" else {
            fatalError("receiptType was \(String(describing: receipt.receiptType))")
        }
        guard receipt.bundleId == "dev.bonzer.weeka.app" else {
            fatalError("bundleId was \(String(describing: receipt.bundleId))")
        }

        // And the negative direction, so a verifier that accepted everything
        // would fail here too.
        var rejected = false
        do {
            let other = try ReceiptVerifier(trustedRoots: appleReceiptRoots(),
                                            bundleId: "com.other.app")
            _ = try await other.verify(base64Receipt: receiptB64)
        } catch let error as VerificationError {
            rejected = error.reason == .wrongBundleId
        }
        guard rejected else {
            fatalError("a receipt for another bundle id was not rejected")
        }

        print("swiftpm: published tag verified a genuine Apple receipt "
            + "(\(receipt.bundleId ?? "?"), \(receipt.inAppPurchases.count) purchases) "
            + "and rejected a foreign bundle id")
    }
}
