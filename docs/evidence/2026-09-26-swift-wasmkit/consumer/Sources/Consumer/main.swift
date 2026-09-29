// Spike only (2026-09-26). Verifies the receipt-data string given as the
// first argument and prints the verdict and bundle id.
import AprvWasm

let verifier = try Verifier()
let result = try verifier.verifyReceipt(CommandLine.arguments[1])
print("{\"verified\":\(result.verified),\"bundleId\":\"\(result.payload?["bundleId"] as? String ?? "-")\"}")
