import Foundation
import ApplePurchaseReceiptVerifier

let fixtures = "../../../../fixtures/"
let b64 = try String(contentsOfFile: fixtures + "public-receipts/receipt-sandbox-g5.b64", encoding: .utf8)
    .components(separatedBy: .whitespacesAndNewlines).joined()

// 1. ReceiptVerifier with Apple's pinned roots (default argument)
let verifier = try ReceiptVerifier(bundleId: "dev.bonzer.weeka.app")
let receipt = try verifier.verifyBase64(receipt: b64)
print("receipt ok:", receipt.bundleId ?? "-", "IAPs:", receipt.inAppPurchases.count)

// 2. typed error
do {
    _ = try ReceiptVerifier(bundleId: "com.other.app").verifyBase64(receipt: b64)
} catch let VerifyError.Verification(reason, detail) {
    print("error ok:", reason, "-", detail)
}

// 3. the verifyReceipt endpoint + toJsonIn
let endpoint = try VerifyReceiptEndpoint(environment: .production)
let result = endpoint.verifyReceiptResult(requestBody: "{\"receipt-data\":\"\(b64)\"}")
print("endpoint status:", result.status(), "verified:", result.verified())
print("toJson():", result.toJson())
print("toJsonIn(.sandbox):", String(try result.toJsonIn(environment: .sandbox).prefix(60)) + "...")

// 4. speed, warm
for _ in 0..<2000 { _ = try verifier.verifyBase64(receipt: b64) }
let n = 5000
let t = Date()
for _ in 0..<n { _ = try verifier.verifyBase64(receipt: b64) }
print("swift -> rust receipt:", Int(Date().timeIntervalSince(t) / Double(n) * 1_000_000), "us/op")
