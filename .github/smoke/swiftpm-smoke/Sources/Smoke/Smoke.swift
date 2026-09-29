import ApplePurchaseReceiptVerifier
import Foundation

/// Smoke-tests the library as resolved from the published tag. Everything it
/// touches — the verifier, the failure type, the bundled root certificates —
/// comes from the dependency, so a tag missing its resources fails here rather
/// than in a user's project.
@main
struct Smoke {
    static func main() throws {
        let receiptB64 = try String(contentsOfFile: "receipt-sandbox-g5.b64", encoding: .ascii)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // Apple's three roots are compiled into aprv.wasm, so the defaults
        // name none of their own (nil means the module's); a tag that lost
        // the module resource fails below, on the genuine receipt.
        let config = try Config.builder().build()
        guard config.roots == nil else {
            fatalError("expected the module's built-in roots (nil), got \(config.roots?.count ?? 0)")
        }
        let verifier = Verifier(config: config)

        // A real Apple-signed receipt against the real pinned root: exercises
        // the packaged certs, the DER reader, the chain build and the signature.
        let result = verifier.verifyReceipt(base64: receiptB64)
        guard let receipt = result.payload else {
            fatalError("verification failed: \(String(describing: result.failure))")
        }
        guard receipt.receiptType == "ProductionSandbox" else {
            fatalError("receiptType was \(String(describing: receipt.receiptType))")
        }
        guard receipt.bundleId == "dev.bonzer.weeka.app" else {
            fatalError("bundleId was \(String(describing: receipt.bundleId))")
        }

        // And the negative direction, so a verifier that accepted everything
        // would fail here too: the same receipt with one bit flipped in its
        // signature, the byte 128 from the end of the DER (BENCHMARKS.md).
        guard var der = Data(base64Encoded: receiptB64) else {
            fatalError("the fixture is not base64")
        }
        der[der.endIndex - 128] ^= 0x01
        let tampered = verifier.verifyReceipt(base64: der.base64EncodedString())
        guard tampered.failure?.reason == .invalidSignature else {
            fatalError("a tampered signature was not rejected as INVALID_SIGNATURE: "
                + "\(String(describing: tampered.failure?.reason))")
        }

        print("swiftpm: published tag verified a genuine Apple receipt "
            + "(\(receipt.bundleId ?? "?"), \(receipt.inApp.count) purchases) "
            + "and rejected a tampered signature")
    }
}
