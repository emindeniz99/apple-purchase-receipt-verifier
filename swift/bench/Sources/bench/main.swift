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
//     swift run -c release --package-path swift/bench bench --worst-case
//
// times, the same way, every shared case in fixtures/cases.json that
// carries a `maxMillis` budget: the hostile inputs (oversized untrusted keys,
// certificate meshes, encoding oddities inside certificates) the shared
// suite bounds in time. Each call is run once first and must give the answer
// the case expects. The README's worst-case CPU figure comes from this mode.
//
//     swift run -c release --package-path swift/bench bench --threads
//
// is the host's own speed: calls per second and per CPU-second of the
// process, for the g5 receipt and the fixture StoreKit 2 JWS, on one thread
// and on four threads sharing one Verifier, plus the start-up to the first
// answer. It counts every call that returned, whatever the verdict, so it
// also runs on a module whose answers this package does not read (the
// round-13 stand-in), and prints the verdict it got beside each row.
// APRV_BENCH_SECONDS sets each window (default 10).
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
let nowMillis: Int64 = 1_767_225_600_000

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

func measure(_ benchmark: String, _ fixture: String, _ op: () -> Int) -> Result {
    let clock = ContinuousClock()
    let start = clock.now
    var warmupOps = 0
    while clock.now - start < warmup {
        sink &+= op()
        warmupOps += 1
    }
    let perOp = microseconds(clock.now - start) / Double(warmupOps)
    let ops = max(1, Int(microseconds(minSample) / perOp) + 1)
    var samples: [Double] = []
    for _ in 0..<sampleCount {
        let sampleStart = clock.now
        for _ in 0..<ops {
            sink &+= op()
        }
        samples.append(microseconds(clock.now - sampleStart) / Double(ops))
    }
    samples.sort()
    let median = (samples[sampleCount / 2 - 1] + samples[sampleCount / 2]) / 2
    FileHandle.standardError.write(
        Data(
            (benchmark.padding(toLength: 24, withPad: " ", startingAt: 0) + " "
                + fixture.padding(toLength: 24, withPad: " ", startingAt: 0)
                + String(format: " %12.1f us/op (max %.1f)\n", median, samples[sampleCount - 1])).utf8))
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

/// The failure a verify call answered with, or nil when it verified.
func reason<T>(_ result: VerificationResult<T>) -> Reason? { result.failure?.reason }

/// Prepares one fixture's inputs, checks every answer, then times the
/// operations.
func run(
    _ fixture: (name: String, bundleId: String, inAppCount: Int), repository: URL, verifier: Verifier
) throws -> [Result] {
    let path = repository.appendingPathComponent("fixtures/public-receipts/\(fixture.name).b64")
    guard let der = Data(base64Encoded: try Data(contentsOf: path), options: .ignoreUnknownCharacters) else {
        throw SetupFailure(description: "\(fixture.name) is not base64")
    }
    let base64 = der.base64EncodedString()
    let requestJSON = "{\"receipt-data\":\"\(base64)\"}"
    let tampered = tamper(der).base64EncodedString()

    // Every call once, with the answer the conformance suite expects, so no
    // benchmark can time a fast failure by accident.
    let verified = verifier.verifyReceipt(base64: base64)
    try check(
        verified.payload?.bundleId == fixture.bundleId && verified.payload?.inApp.count == fixture.inAppCount,
        "verifyReceipt")
    let ok = try jsonObject(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: requestJSON))
    try check(
        ok["status"] as? Int == 0
            && ((ok["receipt"] as? [String: Any])?["in_app"] as? [Any])?.count == fixture.inAppCount,
        "endpointJson")
    try check(reason(verifier.verifyReceipt(base64: tampered)) == .invalidSignature, "rejectTamperedSignature")

    return [
        measure("verifyReceipt", fixture.name) {
            verifier.verifyReceipt(base64: base64).payload?.inApp.count ?? -1
        },
        measure("endpointJson", fixture.name) {
            verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: requestJSON).utf8.count
        },
        measure("rejectTamperedSignature", fixture.name) {
            reason(verifier.verifyReceipt(base64: tampered)) == nil ? 0 : 1
        },
    ]
}

// MARK: - worst case: the shared cases with a time budget

/// A registered fixture's logical bytes, per its codec (the same rules the
/// conformance adapter in swift/Tests applies).
func fixtureBytes(_ id: String, registry: [String: [String: Any]], fixturesDirectory: URL) throws -> [UInt8] {
    guard let entry = registry[id], let path = entry["path"] as? String, let codec = entry["codec"] as? String
    else { throw SetupFailure(description: "cases.json registers no fixture \"\(id)\"") }
    let raw = try Data(contentsOf: fixturesDirectory.appendingPathComponent(path))
    switch codec {
    case "raw", "text":
        return [UInt8](raw)
    case "base64":
        guard let decoded = Data(base64Encoded: raw, options: [.ignoreUnknownCharacters]) else {
            throw SetupFailure(description: "fixture \"\(id)\" is not base64")
        }
        return [UInt8](decoded)
    case "utf8":
        return [UInt8](String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).utf8)
    default:
        throw SetupFailure(description: "fixture \"\(id)\" has unknown codec \"\(codec)\"")
    }
}

func worstCase(repository: URL) throws -> [Result] {
    let fixturesDirectory = repository.appendingPathComponent("fixtures")
    let file = try JSONSerialization.jsonObject(
        with: Data(contentsOf: fixturesDirectory.appendingPathComponent("cases.json")))
    guard let file = file as? [String: Any], let registry = file["fixtures"] as? [String: [String: Any]],
        let cases = file["cases"] as? [[String: Any]]
    else { throw SetupFailure(description: "cases.json is not the expected JSON object") }

    var results: [Result] = []
    for kase in cases where kase["maxMillis"] != nil {
        guard let id = kase["id"] as? String, let operation = kase["operation"] as? String,
            let input = kase["input"] as? [String: Any], let fixtureId = input["fixture"] as? String,
            let config = kase["config"] as? [String: Any], let expected = kase["expected"] as? [String: Any],
            let trusted = config["trustedRoots"] as? [String: Any]
        else { throw SetupFailure(description: "a budgeted case is not in the shape this bench reads") }
        var roots: [[UInt8]]?
        if trusted["source"] as? String == "fixtures" {
            let ids = trusted["fixtures"] as? [String] ?? []
            roots = try ids.map { try fixtureBytes($0, registry: registry, fixturesDirectory: fixturesDirectory) }
        }
        let verifier = try Verifier(config: Config(roots: roots, clock: { nowMillis }))
        let bytes = try fixtureBytes(fixtureId, registry: registry, fixturesDirectory: fixturesDirectory)
        let codec = registry[fixtureId]?["codec"] as? String

        // The answer the case expects, before anything is timed.
        let want = expected["reason"] as? String
        let got: Reason?
        let op: () -> Int
        switch operation {
        case "verifyReceipt":
            let base64 =
                codec == "raw" || codec == "base64"
                ? Data(bytes).base64EncodedString() : String(decoding: bytes, as: UTF8.self)
            got = reason(verifier.verifyReceipt(base64: base64))
            op = { reason(verifier.verifyReceipt(base64: base64)) == nil ? 0 : 1 }
        case "verifySignedData":
            let jws = String(decoding: bytes, as: UTF8.self)
            got = reason(verifier.verifySignedData(jws: jws))
            op = { reason(verifier.verifySignedData(jws: jws)) == nil ? 0 : 1 }
        default:
            throw SetupFailure(description: "\(id): no adapter for operation \(operation)")
        }
        if let oneOf = expected["oneOf"] as? [String] {
            let outcome = got?.rawValue ?? "ok"
            try check(oneOf.contains(outcome), "\(id) answered \(outcome), not one of \(oneOf)")
        } else if expected["status"] as? String == "ok" {
            try check(got == nil, "\(id) expected to verify, got \(got?.rawValue ?? "?")")
        } else {
            try check(got?.rawValue == want, "\(id) expected \(want ?? "?"), got \(got?.rawValue ?? "ok")")
        }
        results.append(measure(operation, id, op))
    }
    return results
}

let repository = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
/// CPU time of the whole process, user and system, in seconds.
func cpuSeconds() -> Double {
    var time = timespec()
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time)
    return Double(time.tv_sec) + Double(time.tv_nsec) / 1_000_000_000
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func add(_ n: Int) {
        lock.lock()
        value += n
        lock.unlock()
    }
    var total: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// The `--threads` mode: see the comment at the top.
func threads(repository: URL) throws {
    let fixturesDirectory = repository.appendingPathComponent("fixtures")
    let g5 = try String(
        contentsOf: fixturesDirectory.appendingPathComponent("public-receipts/receipt-sandbox-g5.b64"), encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    let jws = try String(contentsOf: fixturesDirectory.appendingPathComponent("generated/transaction.jws"), encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let jwsRoot = [UInt8](try Data(contentsOf: fixturesDirectory.appendingPathComponent("generated/jws-root.der")))

    let start = ContinuousClock.now
    let apple = try Verifier(config: Config())
    let created = ContinuousClock.now
    let first = apple.verifyReceipt(base64: g5)
    let answered = ContinuousClock.now
    _ = apple.verifyReceipt(base64: g5)
    let second = ContinuousClock.now
    print(
        #"startup: {"verifier_ms":\#(microseconds(created - start) / 1000),"first_g5_ms":\#(microseconds(answered - created) / 1000),"#
            + #""second_g5_ms":\#(microseconds(second - answered) / 1000),"first_answer":"\#(first.failure?.reason.rawValue ?? "verified")"}"#)

    let jwses = try Verifier(config: Config(roots: [jwsRoot]))
    let seconds = Double(ProcessInfo.processInfo.environment["APRV_BENCH_SECONDS"] ?? "") ?? 10
    let rows: [(String, @Sendable () -> String)] = [
        ("g5", { apple.verifyReceipt(base64: g5).failure?.reason.rawValue ?? "verified" }),
        ("jws", { jwses.verifySignedData(jws: jws).failure?.reason.rawValue ?? "verified" }),
    ]
    for (name, call) in rows {
        for threads in [1, 4] {
            // Warm every instance first: WasmKit translates a function on its
            // first call.
            DispatchQueue.concurrentPerform(iterations: threads) { _ in for _ in 0..<3 { _ = call() } }
            let counts = Counter()
            let cpuStart = cpuSeconds()
            let wallStart = Date()
            DispatchQueue.concurrentPerform(iterations: threads) { _ in
                var n = 0
                while Date().timeIntervalSince(wallStart) < seconds {
                    _ = call()
                    n += 1
                }
                counts.add(n)
            }
            let wall = Date().timeIntervalSince(wallStart)
            let cpu = cpuSeconds() - cpuStart
            print(
                #"throughput: {"row":"\#(name)","threads":\#(threads),"answer":"\#(call())","calls":\#(counts.total),"#
                    + #""per_second":\#(String(format: "%.1f", Double(counts.total) / wall)),"#
                    + #""per_cpu_second":\#(String(format: "%.1f", Double(counts.total) / cpu)),"#
                    + #""cpu_ms_per_call":\#(String(format: "%.1f", 1000 * cpu / Double(counts.total)))}"#)
        }
    }
}

/// The process's peak resident set, from /proc on Linux; nil elsewhere.
func peakRssKilobytes() -> Int? {
    guard let status = try? String(contentsOfFile: "/proc/self/status", encoding: .utf8) else { return nil }
    let line = status.split(separator: "\n").first { $0.hasPrefix("VmHWM:") }
    return line?.split(separator: " ").dropFirst().first.flatMap { Int($0) }
}

var results: [Result] = []
let mode: String
if CommandLine.arguments.dropFirst().contains("--threads") {
    try threads(repository: repository)
    print(#"memory: {"peak_rss_kb":\#(peakRssKilobytes().map(String.init) ?? "null")}"#)
    exit(0)
} else if CommandLine.arguments.dropFirst().contains("--worst-case") {
    mode = "worst-case"
    results = try worstCase(repository: repository)
} else {
    mode = "cross-port"
    let verifier = try Verifier(config: Config(clock: { nowMillis }))
    for fixture in fixtures {
        results += try run(fixture, repository: repository, verifier: verifier)
    }
}

let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
let report = Report(
    port: "swift", tool: "swift/bench \(mode) (ContinuousClock)",
    settings: [
        "warmup_s": 1, "samples": Double(sampleCount), "min_sample_s": 0.1,
    ],
    results: results)
print(String(decoding: try encoder.encode(report), as: UTF8.self))
