// The cross-port benchmark: the same operations on the same two genuine
// sandbox receipts in every port, named after the Java JMH benchmarks in
// java-bench/ (BENCHMARKS.md at the repository root has the table).
//
//     swift run -c release --package-path swift/bench > swift-bench.json
//
// Each benchmark warms up for one second, then takes ten samples of at least
// 100 ms each; the JSON on stdout carries the median, minimum and maximum
// microseconds per operation over those samples.
//
// decodeBase64 is the one operation missing here: the library's receipt-data
// decoder is internal, and reaching it would take `-enable-testing`, which
// changes how the library itself is compiled and so what every other number
// measures.

import ApplePurchaseReceiptVerifier
import Foundation

let warmup = Duration.seconds(1)
let sampleCount = 10
let minSample = Duration.milliseconds(100)

/// Any fixed instant (2026-01-01T00:00:00Z): it only feeds request_date.
let now = Date(timeIntervalSince1970: 1_767_225_600)

/// File under fixtures/public-receipts, and the bundle id and in-app count
/// fixtures/cases.json pins for it.
let fixtures: [(name: String, bundleId: String, inAppCount: Int)] = [
    ("receipt-sandbox-g5", "dev.bonzer.weeka.app", 2),
    ("receipt-sandbox-legacy", "com.nutcall.alert", 187),
]

struct Result: Encodable {
    let benchmark: String
    let fixture: String
    let us_per_op_median: Double
    let us_per_op_min: Double
    let us_per_op_max: Double
    let ops_per_sample: Int
}

struct Report: Encodable {
    let port: String
    let tool: String
    let settings: [String: Double]
    let results: [Result]
}

struct SetupFailure: Error, CustomStringConvertible {
    let description: String
}

func check(_ condition: Bool, _ what: String) throws {
    if !condition { throw SetupFailure(description: "setup check failed: \(what)") }
}

func microseconds(_ duration: Duration) -> Double {
    let (seconds, attoseconds) = duration.components
    return Double(seconds) * 1e6 + Double(attoseconds) / 1e12
}

/// Keeps a small value from each call observable so none is optimized away.
nonisolated(unsafe) var sink = 0

func measure(_ benchmark: String, _ fixture: String, _ op: () async throws -> Int) async throws -> Result {
    let clock = ContinuousClock()
    let start = clock.now
    var warmupOps = 0
    while clock.now - start < warmup {
        sink &+= try await op()
        warmupOps += 1
    }
    let perOp = microseconds(clock.now - start) / Double(warmupOps)
    let ops = max(1, Int(microseconds(minSample) / perOp) + 1)
    var samples: [Double] = []
    for _ in 0..<sampleCount {
        let sampleStart = clock.now
        for _ in 0..<ops {
            sink &+= try await op()
        }
        samples.append(microseconds(clock.now - sampleStart) / Double(ops))
    }
    samples.sort()
    let median = (samples[sampleCount / 2 - 1] + samples[sampleCount / 2]) / 2
    FileHandle.standardError.write(
        Data(
            (benchmark.padding(toLength: 24, withPad: " ", startingAt: 0) + " "
                + fixture.padding(toLength: 24, withPad: " ", startingAt: 0)
                + String(format: " %12.1f us/op\n", median)).utf8))
    return Result(
        benchmark: benchmark, fixture: fixture, us_per_op_median: median,
        us_per_op_min: samples[0], us_per_op_max: samples[sampleCount - 1], ops_per_sample: ops)
}

/// Flips one bit in the middle of the SignerInfo signature, the byte
/// java-bench's flipSignatureByte flips. In both fixtures the signature is a
/// 256-byte OCTET STRING that ends the DER (openssl asn1parse shows it), so
/// its middle byte is 128 from the end; setup proves the flip landed there by
/// requiring INVALID_SIGNATURE.
func tamper(_ der: Data) -> Data {
    var tampered = der
    tampered[tampered.endIndex - 128] ^= 0x01
    return tampered
}

func jsonObject(_ body: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any] ?? [:]
}

func rejectionReason(_ der: Data, _ roots: [Data]) async -> VerificationError.Reason? {
    do {
        _ = try await ReceiptVerifier.verifyCore(receipt: der, trustedRoots: roots)
        return nil
    } catch let error as VerificationError {
        return error.reason
    } catch {
        return nil
    }
}

/// Prepares one fixture's inputs, checks every answer, then times the
/// operations. A function rather than top-level code so its locals are not
/// main-actor state shared with the library's nonisolated methods.
func run(_ fixture: (name: String, bundleId: String, inAppCount: Int), repository: URL, roots: [Data]) async throws -> [Result] {
    let path = repository.appendingPathComponent("fixtures/public-receipts/\(fixture.name).b64")
    guard let der = Data(base64Encoded: try Data(contentsOf: path), options: .ignoreUnknownCharacters) else {
        throw SetupFailure(description: "\(fixture.name) is not base64")
    }
    let base64 = der.base64EncodedString()
    let request: [String: Any] = ["receipt-data": base64]
    let requestJSON = "{\"receipt-data\":\"\(base64)\"}"
    let tampered = tamper(der)
    let verifier = try ReceiptVerifier(trustedRoots: roots, bundleId: fixture.bundleId)
    let fixed = now
    let sandbox = try VerifyReceiptEndpoint(trustedRoots: roots, environment: .sandbox, clock: { fixed })
    let production = try VerifyReceiptEndpoint(trustedRoots: roots, environment: .production, clock: { fixed })

    // Every call once, with the answer the conformance suite expects, so no
    // benchmark can time a fast failure by accident.
    for receipt in [
        try await ReceiptVerifier.verifyCore(receipt: der, trustedRoots: roots),
        try await verifier.verify(base64Receipt: base64),
    ] {
        try check(receipt.bundleId == fixture.bundleId && receipt.inAppPurchases.count == fixture.inAppCount, "receipt")
    }
    let ok = try jsonObject(await sandbox.verifyReceiptJSON(requestJSON))
    try check(
        ok["status"] as? Int == 0
            && ((ok["receipt"] as? [String: Any])?["in_app"] as? [Any])?.count == fixture.inAppCount,
        "endpointJson")
    let retry = try jsonObject(await production.verifyReceiptResult(request).json(for: .sandbox))
    try check(retry["status"] as? Int == 0 && retry["environment"] as? String == "Sandbox", "retryViaResult")
    try check(await rejectionReason(tampered, roots) == .invalidSignature, "rejectTamperedSignature")

    return [
        try await measure("core", fixture.name) {
            try await ReceiptVerifier.verifyCore(receipt: der, trustedRoots: roots).inAppPurchases.count
        },
        try await measure("verifierBase64", fixture.name) {
            try await verifier.verify(base64Receipt: base64).inAppPurchases.count
        },
        try await measure("endpointJson", fixture.name) {
            await sandbox.verifyReceiptJSON(requestJSON).utf8.count
        },
        try await measure("retryViaResult", fixture.name) {
            try await production.verifyReceiptResult(request).json(for: .sandbox).utf8.count
        },
        try await measure("rejectTamperedSignature", fixture.name) {
            await rejectionReason(tampered, roots) == nil ? 0 : 1
        },
    ]
}

let repository = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
let roots = appleReceiptRoots()
var results: [Result] = []
for fixture in fixtures {
    results += try await run(fixture, repository: repository, roots: roots)
}

let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
let report = Report(
    port: "swift", tool: "swift/bench (ContinuousClock)",
    settings: [
        "warmup_s": 1, "samples": Double(sampleCount), "min_sample_s": 0.1,
    ],
    results: results)
print(String(decoding: try encoder.encode(report), as: UTF8.self))
