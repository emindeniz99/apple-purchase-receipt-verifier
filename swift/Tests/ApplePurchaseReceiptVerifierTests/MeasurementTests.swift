import Foundation
import WasmKit
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Measurements, skipped unless asked for: the corpus parity run and the
/// speed of this host. They are here, and not in swift/bench, because both
/// need the package's host layer (the corpus carries JWS inputs that are not
/// UTF-8, which no Swift `String` can hold, so the public API cannot take
/// them). Run them on a release build, where WasmKit is optimised:
///
///     swift test -c release -Xswiftc -enable-testing --filter MeasurementTests
///
/// with the environment below. swift/CI-NOTES.md has the whole procedure.
final class MeasurementTests: XCTestCase {
    static let env = ProcessInfo.processInfo.environment

    /// APRV_CORPUS_CALLS: a directory of round 13's calls files
    /// (`<corpus>.jsonl`, written by the canonical-ABI round's
    /// py/calls_bytes.py). APRV_CORPUS_OUT: where the rows go, as
    /// `<label>-<corpus>.jsonl` in the Node runner's format, which that
    /// round's py/classify.py reads. APRV_CORPUS_LABEL names them (default
    /// `swift`). APRV_CORPUS_MODULE optionally runs another aprv.wasm than
    /// the bundled one, such as a candidate release build.
    ///
    /// Each distinct configuration gets an instance, created and set up with
    /// init on first use and reused; a trap discards it, as the Pool does.
    func testCorpus() throws {
        guard let calls = Self.env["APRV_CORPUS_CALLS"], let out = Self.env["APRV_CORPUS_OUT"] else {
            throw XCTSkip("set APRV_CORPUS_CALLS and APRV_CORPUS_OUT to run the corpus")
        }
        let label = Self.env["APRV_CORPUS_LABEL"] ?? "swift"
        let module: AprvModule
        if let path = Self.env["APRV_CORPUS_MODULE"] {
            module = try AprvModule.load([UInt8](try Data(contentsOf: URL(fileURLWithPath: path))))
        } else {
            module = try AprvModule.bundled.get()
        }
        var ranAny = false
        for corpus in ["cases", "hostile", "algorithms", "substrate", "fuzz"] {
            let input = URL(fileURLWithPath: calls).appendingPathComponent("\(corpus).jsonl")
            guard FileManager.default.fileExists(atPath: input.path) else { continue }
            ranAny = true
            let start = Date()
            var guests: [String: Guest] = [:]
            var rows = 0
            var traps = 0
            var lines: [String] = []
            for line in try String(contentsOf: input, encoding: .utf8).split(separator: "\n") {
                let row = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
                rows += 1
                let id = try Self.jsonString(XCTUnwrap(row["id"] as? String))
                if let map = row["map"] as? String {
                    lines.append(#"{"id":\#(id),"map":\#(try Self.jsonString(map))}"#)
                    continue
                }
                let config = try XCTUnwrap(row["config"] as? String)
                let input = [UInt8](try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(row["b64"] as? String))))
                let now = (row["now"] as? NSNumber).map { UInt64(bitPattern: $0.int64Value) } ?? UInt64(systemMillis())
                var answer: String?
                do {
                    var guest = guests[config]
                    if guest == nil {
                        let fresh = try Guest(module)
                        let reply = try fresh.initialize(Array(config.utf8))
                        if reply == #"{"ok":true}"# { guests[config] = fresh } else { answer = reply }
                        guest = fresh
                    }
                    if answer == nil {
                        switch row["fn"] as? String {
                        case "verify-receipt": answer = try guest!.verifyReceipt(now: now, input)
                        case "verify-signed-data": answer = try guest!.verifySignedData(now: now, input)
                        default:
                            let env = UInt32(truncating: try XCTUnwrap(row["env"] as? NSNumber))
                            answer = try guest!.verifyReceiptEndpoint(env: env, now: now, input)
                        }
                    }
                    lines.append(#"{"id":\#(id),"out":\#(try Self.jsonString(answer!))}"#)
                } catch {
                    traps += 1
                    guests[config] = nil
                    lines.append(#"{"id":\#(id),"trap":\#(try Self.jsonString("\(error)"))}"#)
                }
            }
            let file = URL(fileURLWithPath: out).appendingPathComponent("\(label)-\(corpus).jsonl")
            try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: file)
            let seconds = Date().timeIntervalSince(start)
            print(
                #"corpus: {"host":"wasmkit","corpus":"\#(corpus)","rows":\#(rows),"traps":\#(traps),"seconds":\#(String(format: "%.1f", seconds))}"#
            )
        }
        XCTAssertTrue(ranAny, "no <corpus>.jsonl under \(calls)")
    }

    /// APRV_BENCH=1: start-up (hash and parse, instance, init, first and
    /// second g5 call) and throughput through the public API, g5 and the
    /// shared-sandbox JWS, on one thread and on four threads with one
    /// shared Verifier. APRV_BENCH_SECONDS sets each throughput window
    /// (default 10). Each row also reports calls per CPU-second of the
    /// process, which a busy machine does not skew the way wall time is.
    ///
    /// APRV_BENCH_BOUNDS=mprotect measures WasmKit's other bounds-checking
    /// mode, for comparison only: the package always uses software checks.
    func testSpeed() throws {
        guard Self.env["APRV_BENCH"] == "1" else { throw XCTSkip("set APRV_BENCH=1 to measure") }
        let g5Text = try TestFixtures.text(TestFixtures.g5)
        let g5 = Array(g5Text.utf8)
        let wasm = [UInt8](try Data(contentsOf: try XCTUnwrap(AprvModule.resource("aprv.wasm"))))
        let sum = try String(contentsOf: try XCTUnwrap(AprvModule.resource("aprv.wasm.sha256")), encoding: .utf8)

        let t0 = Date()
        _ = SHA256.hex(wasm)
        let t1 = Date()
        _ = try AprvModule.load(wasm, sumFile: sum)
        let bounds: EngineConfiguration.MemoryBoundsChecking =
            Self.env["APRV_BENCH_BOUNDS"] == "mprotect" ? .mprotect : .software
        let module = try AprvModule.load(wasm, engine: EngineConfiguration(memoryBoundsChecking: bounds))
        print("bounds: \(bounds), engine: \(module.engine.configuration.memoryBoundsChecking)")
        let t2 = Date()
        let guest = try Guest(module)
        let t3 = Date()
        _ = try guest.initialize(Config.initJson([]))
        let t4 = Date()
        _ = try guest.verifyReceipt(now: UInt64(systemMillis()), g5)
        let t5 = Date()
        _ = try guest.verifyReceipt(now: UInt64(systemMillis()), g5)
        let t6 = Date()
        let ms = { (a: Date, b: Date) in String(format: "%.1f", b.timeIntervalSince(a) * 1000) }
        print(
            #"startup: {"hash_ms":\#(ms(t0, t1)),"hash_and_parse_ms":\#(ms(t0, t2)),"instantiate_ms":\#(ms(t2, t3)),"#
                + #""init_ms":\#(ms(t3, t4)),"first_g5_ms":\#(ms(t4, t5)),"second_g5_ms":\#(ms(t5, t6))}"#)

        let seconds = Double(Self.env["APRV_BENCH_SECONDS"] ?? "") ?? 10
        let apple = Verifier(config: .defaults(), module: .success(module))
        let jws = try TestFixtures.text(TestFixtures.jws)
        let jwses = Verifier(
            config: try Config.builder().roots([try TestFixtures.bytes(TestFixtures.jwsRoot)]).build(), module: .success(module))
        // The module must verify both inputs, or the rows would time a
        // refusal. Checked on its raw answer, which is the same with the
        // stand-in module (whose 0.6 wire the public API does not read) and
        // the release one; the rows then time the public API, and count
        // every call that returned.
        XCTAssertTrue(try guest.verifyReceipt(now: UInt64(systemMillis()), g5).contains(#""verified":true"#))
        let jwsGuest = try Guest(module)
        _ = try jwsGuest.initialize(Config.initJson([try TestFixtures.bytes(TestFixtures.jwsRoot)]))
        XCTAssertTrue(try jwsGuest.verifySignedData(now: UInt64(systemMillis()), Array(jws.utf8)).contains(#""verified":true"#))
        let rows: [(String, @Sendable () -> Bool)] = [
            ("g5", { apple.verifyReceipt(base64: g5Text).failure?.message != "the verification module trapped" }),
            ("jws", { jwses.verifySignedData(jws: jws).failure?.message != "the verification module trapped" }),
        ]
        for (name, call) in rows {
            for threads in [1, 4] {
                // Warm every instance the run will use first: the first call
                // on an instance translates functions lazily.
                DispatchQueue.concurrentPerform(iterations: threads) { _ in for _ in 0..<3 { _ = call() } }
                let counts = Counter()
                let cpuStart = Self.cpuSeconds()
                let start = Date()
                DispatchQueue.concurrentPerform(iterations: threads) { _ in
                    var n = 0
                    while Date().timeIntervalSince(start) < seconds {
                        if call() { n += 1 }
                    }
                    counts.add(n)
                }
                let elapsed = Date().timeIntervalSince(start)
                let cpu = Self.cpuSeconds() - cpuStart
                let perSecond = Double(counts.total) / elapsed
                print(
                    #"throughput: {"row":"\#(name)","threads":\#(threads),"calls":\#(counts.total),"#
                        + #""seconds":\#(String(format: "%.1f", elapsed)),"per_second":\#(String(format: "%.1f", perSecond)),"#
                        + #""ms_per_call_per_thread":\#(String(format: "%.2f", 1000 * Double(threads) / perSecond)),"#
                        + #""cpu_seconds":\#(String(format: "%.1f", cpu)),"per_cpu_second":\#(String(format: "%.1f", Double(counts.total) / cpu))}"#)
            }
        }
    }

    /// User and system CPU time of the whole process, in seconds.
    static func cpuSeconds() -> Double {
        var time = timespec()
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time)
        return Double(time.tv_sec) + Double(time.tv_nsec) / 1_000_000_000
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func add(_ n: Int) { lock.lock(); value += n; lock.unlock() }
        var total: Int { lock.lock(); defer { lock.unlock() }; return value }
    }

    static func jsonString(_ s: String) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: [s], options: [.withoutEscapingSlashes])
        return String(decoding: data.dropFirst().dropLast(), as: UTF8.self)
    }
}
