import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The ABI tests of the canonical-ABI final round that apply to a
/// hand-rolled host (docs/evidence/2026-09-29-canonical-abi-final,
/// hosts/wasmkit/Sources/aprv-cabi/Tests.swift), run on the bundled module
/// through this package's own ``Guest``. The misuse cases that round ran
/// against its dynamically typed lowering helper (a UInt32 where the WIT
/// says u64, a wrong argument count) cannot be written here: ``Guest``'s
/// four methods are typed, so the compiler refuses them.
final class AbiTests: XCTestCase {
    static let now = UInt64(1_735_689_600_000)  // 2025-01-01T00:00:00Z

    func module() throws -> AprvModule { try AprvModule.bundled.get() }

    func g5() throws -> [UInt8] { Array(try TestFixtures.text(TestFixtures.g5).utf8) }

    func initialized(_ config: [UInt8] = Config.initJson([])) throws -> Guest {
        let guest = try Guest(module())
        try guest.start(config)
        return guest
    }

    /// An accepting init answer states the most bytes of one input the
    /// module needs (docs/rust-core/DECISIONS.md R42): a positive integer,
    /// and nothing else beside `ok`.
    func assertAccepts(_ answer: String, _ what: String = "", file: StaticString = #filePath, line: UInt = #line) {
        let reply = (try? JSONSerialization.jsonObject(with: Data(answer.utf8))) as? [String: Any]
        XCTAssertEqual(reply.map { Set($0.keys) }, ["ok", "max_input_bytes"], "\(what): \(answer)", file: file, line: line)
        XCTAssertEqual(reply?["ok"] as? Bool, true, "\(what): \(answer)", file: file, line: line)
        XCTAssertGreaterThan(reply?["max_input_bytes"] as? Int ?? 0, 0, "\(what): \(answer)", file: file, line: line)
    }

    func assertTraps(_ body: () throws -> String, _ what: String) {
        do {
            let answer = try body()
            XCTFail("\(what): answered \(answer.prefix(120)) instead of trapping")
        } catch HostError.trap {
        } catch {
            XCTFail("\(what): \(error), want a trap")
        }
    }

    func testTheBundledModuleIsTheOneItsHashNames() throws {
        // The digest is swift-crypto's; this pins the spelling the pin file
        // uses, lowercase and zero-padded ("...8f01cf...").
        XCTAssertEqual(AprvModule.sha256Hex(Array("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        let url = try XCTUnwrap(AprvModule.resource("aprv.wasm"))
        let sum = try XCTUnwrap(AprvModule.resource("aprv.wasm.sha256"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let file = try String(contentsOf: sum, encoding: .utf8)
        XCTAssertEqual(file, AprvModule.sha256Hex(bytes) + "  aprv.wasm\n", "aprv.wasm.sha256 is sha256sum's line for aprv.wasm")
        XCTAssertNoThrow(try AprvModule.bundled.get())
    }

    /// Both choices are the package's, not WasmKit's defaults: mprotect bounds
    /// checking would install a process-wide signal handler, and the
    /// direct-threaded loop crashed the first guest call on macOS arm64 in a
    /// release build (README, known issues). It runs only where this suite has
    /// tested it, so each platform's run of this suite tests the loop it ships.
    func testTheEngineChecksBoundsInSoftwareAndRunsTheDirectLoopOnlyOnLinuxX8664() throws {
        let engine = try AprvModule.bundled.get().engine.configuration
        XCTAssertEqual(engine.memoryBoundsChecking, .software)
        #if os(Linux) && arch(x86_64)
            XCTAssertEqual(engine.threadingModel, .direct)
        #else
            XCTAssertEqual(engine.threadingModel, .token)
        #endif
    }

    func testInitWithNoRootsAcceptsAndASecondInitTraps() throws {
        let guest = try Guest(module())
        assertAccepts(try guest.initialize(Config.initJson([])), "no roots")
        assertTraps({ try guest.initialize(Config.initJson([])) }, "a second init")
        let empty = try Guest(module())
        assertAccepts(try empty.initialize([]), "an empty configuration is the built-in roots too")
    }

    /// A started instance holds the input length its own init answer stated;
    /// before init it knows none and cuts nothing.
    func testAStartedInstanceHoldsTheInputLengthItsInitStated() throws {
        let raw = try Guest(module())
        XCTAssertNil(raw.maxInputBytes)
        let answer = try raw.initialize(Config.initJson([]))
        let reply = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any])
        let stated = try XCTUnwrap(reply["max_input_bytes"] as? Int)
        XCTAssertNil(raw.maxInputBytes, "initialize(_:) only calls the export")
        XCTAssertEqual(try initialized().maxInputBytes, stated)
    }

    func testAVerifyBeforeInitTraps() throws {
        let guest = try Guest(module())
        assertTraps({ try guest.verifyReceipt(now: Self.now, try self.g5()) }, "verify before init")
    }

    func testAConfigurationThatIsNotJsonIsRefusedAndInitCanBeRetried() throws {
        let guest = try Guest(module())
        let refused = try guest.initialize(Array("{not json".utf8))
        XCTAssertTrue(refused.contains(#""ok":false"#), refused)
        assertAccepts(try guest.initialize(Config.initJson([])), "after a refusal")
    }

    /// init's argument, byte for byte, as the other ports write it: padded
    /// standard base64 with `/` unescaped, an empty root as `""`, no
    /// whitespace. `JSONEncoder` chooses these bytes, so this pins them.
    func testTheConfigurationIsWrittenAsTheOtherPortsWriteIt() {
        XCTAssertEqual(Config.initJson([[0xFB, 0xFF], []]), Array(#"{"roots":["+/8=",""]}"#.utf8))
        XCTAssertEqual(Config.initJson([]), Array(#"{"roots":[]}"#.utf8))
    }

    func testTheFourOperationsAnswer() throws {
        let guest = try initialized()
        let receipt = try guest.verifyReceipt(now: Self.now, try g5())
        XCTAssertTrue(receipt.contains(#""verified":true"#), String(receipt.prefix(200)))
        let request = Array(#"{"receipt-data":""#.utf8) + (try g5()) + Array(#""}"#.utf8)
        let endpoint = try guest.verifyReceiptEndpoint(env: 1, now: Self.now, request)
        XCTAssertTrue(endpoint.contains(#""status":0"#), String(endpoint.prefix(200)))
        let jwsGuest = try initialized(Config.initJson([try TestFixtures.bytes(TestFixtures.jwsRoot)]))
        let jws = try jwsGuest.verifySignedData(now: Self.now, Array(try TestFixtures.text(TestFixtures.jws).utf8))
        XCTAssertTrue(jws.contains(#""verified":true"#), String(jws.prefix(200)))
    }

    /// Inputs cross as bytes, so a JWS that is not UTF-8 reaches the module
    /// and is answered as a value, not a trap.
    func testAJwsThatIsNotUtf8IsAnAnswerNotATrap() throws {
        let answer = try initialized().verifySignedData(now: Self.now, [0x65, 0x79, 0xFF, 0xFE, 0x2E, 0x78])
        let parsed = try JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any]
        XCTAssertEqual(parsed?["verified"] as? Bool, false, answer)
    }

    func testAnEnvironmentOtherThanZeroOrOneTraps() throws {
        let request = Array(#"{"receipt-data":""#.utf8) + (try g5()) + Array(#""}"#.utf8)
        for env: UInt32 in [2, 255, 0xFFFF_FFFF] {
            let guest = try initialized()
            assertTraps({ try guest.verifyReceiptEndpoint(env: env, now: Self.now, request) }, "env \(env)")
        }
    }

    /// random-get must answer exactly the length asked for; the module traps
    /// otherwise. ECDSA verification draws random bytes, so a JWS reaches it.
    func testRandomGetAnsweringTheWrongLengthTraps() throws {
        let guest = try Guest(module(), random: { n in [UInt8](repeating: 7, count: max(n - 1, 0)) })
        try guest.start(Config.initJson([try TestFixtures.bytes(TestFixtures.jwsRoot)]))
        assertTraps(
            { try guest.verifySignedData(now: Self.now, Array(try TestFixtures.text(TestFixtures.jws).utf8)) }, "short random-get")
    }

    /// A trap in one instance leaves another verifying, and the trapped one
    /// is discarded: it answers nothing more, rather than keep running in
    /// whatever state the trap left, which WasmKit would allow.
    func testATrapIsIsolatedAndTheTrappedInstanceIsDiscarded() throws {
        let a = try initialized()
        let b = try initialized()
        let g5 = try g5()
        XCTAssertTrue(try b.verifyReceipt(now: Self.now, g5).contains(#""verified":true"#))
        assertTraps({ try a.verifyReceiptEndpoint(env: 2, now: Self.now, []) }, "env 2")
        XCTAssertTrue(a.dead)
        XCTAssertTrue(try b.verifyReceipt(now: Self.now, g5).contains(#""verified":true"#))
        assertTraps({ try a.verifyReceipt(now: Self.now, g5) }, "the discarded instance")
    }

    /// An input over the core's largest cap is cut to the length init
    /// stated, one byte over it, before it is copied in: the core still
    /// answers TOO_LARGE (21002 at the endpoint), byte for byte what it
    /// answers for exactly one byte over, and the guest's memory never has to
    /// hold the whole input.
    func testAnInputOverTheCapIsCutAndTheCoreStillRefusesIt() throws {
        let huge = [UInt8](repeating: 0x41, count: 4 << 20)
        let receipt = try initialized()
        let maxInputBytes = try XCTUnwrap(receipt.maxInputBytes)
        XCTAssertLessThan(maxInputBytes, huge.count)
        let oneOver = [UInt8](repeating: 0x41, count: maxInputBytes)
        let answer = try receipt.verifyReceipt(now: Self.now, huge)
        XCTAssertEqual(answer, try initialized().verifyReceipt(now: Self.now, oneOver))
        XCTAssertTrue(answer.contains(#""reason":"TOO_LARGE""#), answer)
        // A fresh instance has 2 MiB; holding the whole input would take it
        // past 6 MiB. The capped input (3 MiB) fits under that.
        XCTAssertLessThan(receipt.memoryBytes, (2 << 20) + (4 << 20), "the guest never held the 4 MiB input")
        print("memory: \(receipt.memoryBytes) bytes of linear memory after a 4 MiB receipt")
        let body = Array(#"{"receipt-data":""#.utf8) + huge + Array(#""}"#.utf8)
        let endpoint = try initialized().verifyReceiptEndpoint(env: 1, now: Self.now, body)
        XCTAssertEqual(
            endpoint, try initialized().verifyReceiptEndpoint(env: 1, now: Self.now, Array(body.prefix(maxInputBytes))))
        XCTAssertEqual(endpoint, #"{"status":21002}"#)
        let jws = try initialized().verifySignedData(now: Self.now, huge)
        XCTAssertTrue(jws.contains(#""reason":"TOO_LARGE""#), jws)

        let verifier = Verifier(config: .defaults())
        let text = String(repeating: "A", count: 4 << 20)
        XCTAssertEqual(verifier.verifyReceipt(base64: text).failure?.reason, .tooLarge)
        XCTAssertEqual(verifier.verifySignedData(jws: text).failure?.reason, .tooLarge)
        XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: text), #"{"status":21002}"#)
    }

    /// An input of exactly the cap, one byte under the length init states
    /// (3,145,728 bytes today), passes whole: the core answers about its
    /// content, not its size.
    func testAnInputAtTheCapIsPassedWhole() throws {
        let guest = try initialized()
        let cap = try XCTUnwrap(guest.maxInputBytes) - 1
        let atCap = String(repeating: "A", count: cap)
        let failure = try XCTUnwrap(Verifier(config: .defaults()).verifyReceipt(base64: atCap).failure)
        XCTAssertNotEqual(failure.reason, .tooLarge, failure.message)
        _ = try guest.verifyReceipt(now: Self.now, Array(atCap.utf8))
        XCTAssertGreaterThanOrEqual(guest.memoryBytes, cap, "the whole input reached linear memory")
    }

    /// Many calls on one instance leave its linear memory the same size:
    /// every input buffer and every result is freed.
    func testRepeatedCallsLeaveMemoryTheSameSize() throws {
        let guest = try initialized()
        let g5 = try g5()
        let request = Array(#"{"receipt-data":""#.utf8) + g5 + Array(#""}"#.utf8)
        func round() throws {
            _ = try guest.verifyReceipt(now: Self.now, g5)
            _ = try guest.verifyReceiptEndpoint(env: 0, now: Self.now, request)
            _ = try guest.verifyReceipt(now: Self.now, Array("not base64".utf8))
            _ = try guest.verifySignedData(now: Self.now, Array("a.b.c".utf8))
        }
        for _ in 0..<5 { try round() }
        let before = guest.memoryBytes
        for _ in 0..<Self.rounds { try round() }
        XCTAssertEqual(guest.memoryBytes, before)
        print("memory: linear memory \(before) bytes before and \(guest.memoryBytes) after \(4 * Self.rounds) calls")
    }

    /// 125 rounds of four calls: 500 calls, as round 13 ran on WasmKit (2,000
    /// on the faster runtimes). APRV_ABI_ROUNDS changes it.
    static var rounds: Int { Int(ProcessInfo.processInfo.environment["APRV_ABI_ROUNDS"] ?? "") ?? 125 }
}

/// The facade over a test double of the ABI (Resources/double.wat), which
/// answers what a test passes in, so every outcome the module can produce
/// can be produced on purpose.
final class FacadeTests: XCTestCase {
    func verifier(clock: @escaping @Sendable () -> Int64 = { 1_735_689_600_000 }) throws -> Verifier {
        Verifier(config: try Config.builder().clock(clock).build(), module: .success(try TestFixtures.double()))
    }

    static let receiptJson =
        #"{"receipt_type":"ProductionSandbox","app_item_id":"123456789012345678","bundle_id":"b","bundle_id_bytes":"DAFi","#
        + #""application_version":"1","opaque_value":null,"sha1_hash":"Ag==","receipt_creation_date_ms":6000,"#
        + #""download_id":"-7","version_external_identifier":null,"in_app":[{"quantity":1,"product_id":"p","#
        + #""transaction_id":"t","purchase_date_ms":1000,"original_transaction_id":"o","#
        + #""original_purchase_date_ms":2000,"expires_date_ms":null,"web_order_line_item_id":"4","#
        + #""cancellation_date_ms":null,"is_trial_period":false,"is_in_intro_offer_period":true,"#
        + #""unknown_attributes":{"1720":["AQ=="]}}],"original_purchase_date_ms":9000,"#
        + #""original_application_version":"0","expiration_date_ms":null,"unknown_attributes":{"13":["Aw==","BA=="]}}"#

    // MARK: the six outcomes (ARCHITECTURE.md §4)

    func testVerifiedIsThePayload() throws {
        let result = try verifier().verifyReceipt(
            base64: #"{"verified":true,"payload":\#(Self.receiptJson),"environment":"Sandbox"}"#)
        let payload = try XCTUnwrap(result.payload, "\(String(describing: result.failure))")
        XCTAssertEqual(payload.environment, .sandbox)
        XCTAssertEqual(payload.appItemId, 123_456_789_012_345_678)
        XCTAssertEqual(payload.downloadId, -7)
        XCTAssertEqual(payload.bundleIdBytes, [0x0C, 0x01, 0x62])
        XCTAssertNil(payload.opaqueValue)
        XCTAssertEqual(payload.inApp.first?.isInIntroOfferPeriod, true)
        XCTAssertEqual(payload.inApp.first?.unknownAttributes, [1720: [[0x01]]])
        XCTAssertEqual(payload.unknownAttributes, [13: [[0x03], [0x04]]])
        let same = try JSONSerialization.jsonObject(with: Data(payload.toJson().utf8))
        XCTAssertTrue(sameJsonValue(same, try JSONSerialization.jsonObject(with: Data(Self.receiptJson.utf8))), payload.toJson())

        let jws = try verifier().verifySignedData(jws: #"{"verified":true,"payload":"{\"a\":1,\"a\":2}","environment":null}"#)
        XCTAssertEqual(jws.payload?.json, #"{"a":1,"a":2}"#, "the signed payload, exactly")
        XCTAssertNotNil(jws.payload)
        XCTAssertNil(jws.payload?.environment)
        let production = try verifier().verifySignedData(jws: #"{"verified":true,"payload":"{}","environment":"Production"}"#)
        XCTAssertEqual(production.payload?.environment, .production)
    }

    func testAVerificationFailureIsTheModulesReason() throws {
        for reason in Reason.allCases {
            let result = try verifier().verifySignedData(jws: #"{"verified":false,"reason":"\#(reason.rawValue)","message":"m"}"#)
            XCTAssertEqual(result.failure?.reason, reason)
            XCTAssertEqual(result.failure?.message, "m")
            XCTAssertNil(result.failure?.cause)
        }
    }

    /// Caller misuse: an empty root set, and a root the module refuses, are
    /// the language's programmer error at startup, never a verdict.
    func testCallerMisuseIsAConfigErrorAtStartup() throws {
        XCTAssertThrowsError(try Config.builder().roots([]).build()) { XCTAssertTrue($0 is ConfigError, "\($0)") }
        XCTAssertThrowsError(try Config.builder().roots([Array("not a certificate".utf8)])) {
            XCTAssertTrue(($0 as? ConfigError)?.detail.hasPrefix("trust anchor is not a certificate") == true, "\($0)")
        }
        XCTAssertNoThrow(try Config.builder().roots([try TestFixtures.bytes(TestFixtures.receiptRoot)]).build())
    }

    /// A module without the @0.1.0 exports, or with an import beyond
    /// random-get, is refused when it loads, naming the version this package
    /// binds; a Verifier over it answers INTERNAL_ERROR, never a verdict.
    func testAnAbiMismatchIsRefusedAtLoad() throws {
        let other = TinyModules.otherVersion
        XCTAssertThrowsError(try AprvModule.load(other)) { error in
            guard case HostError.abiMismatch(let detail) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(detail.contains("aprv:verifier@0.1.0") && detail.contains("verify@2.0.0#init"), detail)
        }
        let imports = TinyModules.wasiImport
        XCTAssertThrowsError(try AprvModule.load(imports)) { error in
            guard case HostError.abiMismatch(let detail) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(detail.contains("fd_write"), detail)
        }
        let verifier = Verifier(config: .defaults(), module: Result { () throws(HostError) in try AprvModule.load(other) })
        let failure = try XCTUnwrap(verifier.verifyReceipt(base64: "AAAA").failure)
        XCTAssertEqual(failure.reason, .internalError)
        XCTAssertTrue(failure.cause is HostError, "\(String(describing: failure.cause))")
        XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: "{}"), #"{"status":21009}"#)
    }

    /// A module whose bytes are not the ones its hash file names is refused
    /// before it is parsed.
    func testAModuleThatDoesNotMatchItsHashIsRefused() throws {
        let double = try doubleBytes()
        XCTAssertNoThrow(try AprvModule.load(double, sumFile: AprvModule.sha256Hex(double) + "  aprv.wasm\n"))
        var changed = double
        changed[changed.count - 1] ^= 1
        XCTAssertThrowsError(try AprvModule.load(changed, sumFile: AprvModule.sha256Hex(double) + "  aprv.wasm\n")) { error in
            guard case HostError.moduleUnavailable = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(try AprvModule.load(double, sumFile: "")) { error in
            guard case HostError.moduleUnavailable = error else { return XCTFail("\(error)") }
        }
    }

    /// A trap is INTERNAL_ERROR with the trap in the cause, 21009 at the
    /// endpoint; the instance is discarded and the next call runs on a fresh
    /// one.
    func testATrapIsAnInternalErrorAndTheNextCallRecovers() throws {
        let verifier = try verifier()
        let failure = try XCTUnwrap(verifier.verifyReceipt(base64: "!").failure)
        XCTAssertEqual(failure.reason, .internalError)
        XCTAssertEqual(failure.message, "the verification module trapped")
        guard case HostError.trap = try XCTUnwrap(failure.cause as? HostError) else { return XCTFail("\(failure)") }
        XCTAssertEqual(verifier.pool.idleCount, 0, "the trapped instance is not kept")
        XCTAssertEqual(verifier.verifySignedData(jws: #"{"verified":true,"payload":"{}","environment":null}"#).payload?.json, "{}")
        XCTAssertEqual(verifier.pool.idleCount, 1)
        XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .production, requestJson: "!"), #"{"status":21009}"#)
    }

    /// WasmKit stops the process on an out-of-range host access, so a result
    /// pointer or a return area outside memory must be caught before memory
    /// is touched: INTERNAL_ERROR, no crash, and the instance discarded.
    func testAnOutOfRangeResultIsAnInternalErrorNotACrash() throws {
        let verifier = try verifier()
        for input in ["%", "^"] {
            let failure = try XCTUnwrap(verifier.verifyReceipt(base64: input).failure, input)
            XCTAssertEqual(failure.reason, .internalError, input)
            guard case HostError.unusableAnswer(_, let detail) = try XCTUnwrap(failure.cause as? HostError) else {
                return XCTFail("\(failure)")
            }
            XCTAssertTrue(detail.contains("outside memory"), detail)
            XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: input), #"{"status":21009}"#)
        }
        XCTAssertEqual(verifier.pool.idleCount, 0)
        XCTAssertTrue(verifier.verifySignedData(jws: #"{"verified":true,"payload":"{}","environment":null}"#).verified)
    }

    /// An answer not in the wire's shape is INTERNAL_ERROR: this package
    /// never guesses what a module meant.
    func testAnUnusableAnswerIsAnInternalError() throws {
        let verifier = try verifier()
        for answer in [
            "", "not json", #"{"verified":"yes"}"#, #"{"verified":true}"#, #"{"verified":false}"#,
            #"{"verified":false,"reason":"NOT_A_REASON","message":"m"}"#,
            #"{"verified":true,"payload":"{}","reason":"MALFORMED"}"#, #"{"verified":false,"reason":"MALFORMED","payload":"{}"}"#,
            #"{"verified":true,"payload":"{}","extra":1}"#, #"{"verified":true,"payload":{}}"#,
            // The environment: present on a verified answer, one of the
            // three values, and absent from a failed one.
            #"{"verified":true,"payload":"{}"}"#, #"{"verified":true,"payload":"{}","environment":"Xcode"}"#,
            #"{"verified":true,"payload":"{}","environment":"PRODUCTION"}"#,
            #"{"verified":true,"payload":"{}","environment":1}"#,
            #"{"verified":false,"reason":"MALFORMED","message":"m","environment":null}"#,
        ] {
            let failure = verifier.verifySignedData(jws: answer).failure
            XCTAssertEqual(failure?.reason, .internalError, answer)
            XCTAssertEqual(failure?.message, "the verification module's answer was unusable", answer)
        }
        for payload in [
            #"{"app_item_id":1}"#, #"{"download_id":"x"}"#, #"{"sha1_hash":"*"}"#, #"{"unknown_attributes":{"x":[]}}"#,
            #"{"surprise":null}"#,
        ] {
            let failure = verifier.verifyReceipt(base64: #"{"verified":true,"payload":\#(payload),"environment":null}"#).failure
            XCTAssertEqual(failure?.reason, .internalError, payload)
        }
        XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: "not json"), #"{"status":21009}"#)
    }

    // MARK: the clock and the environment

    /// The clock is read once per call, before the input is looked at,
    /// whatever the input (docs/rust-core/ARCHITECTURE.md §6).
    func testTheClockIsReadOncePerCall() throws {
        let clock = CountingClock(1_735_689_600_000)
        let verifier = try verifier(clock: clock.read)
        _ = verifier.verifyReceipt(base64: "")
        _ = verifier.verifySignedData(jws: #"{"verified":true,"payload":"{}","environment":null}"#)
        _ = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: "!")
        XCTAssertEqual(clock.reads, 3)
    }

    /// A time before 1970 cannot cross as `now-ms: u64`: INTERNAL_ERROR, and
    /// 21009 at the endpoint, before the module is called.
    func testAClockBefore1970IsAnInternalError() throws {
        let verifier = try verifier(clock: { -1 })
        XCTAssertEqual(verifier.verifyReceipt(base64: "!").failure?.reason, .internalError)
        XCTAssertEqual(verifier.verifySignedData(jws: "!").failure?.reason, .internalError)
        XCTAssertEqual(verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: "!"), #"{"status":21009}"#)
        XCTAssertEqual(verifier.pool.idleCount, 0, "no instance was created: the module was never called")
    }

    /// The clock's value is the module's now-ms (request_date_ms), and
    /// `Environment` maps onto 0 and 1: the genuine sandbox receipt is 21007
    /// on production and 0 on sandbox.
    func testTheClockAndTheEnvironmentReachTheModule() throws {
        let verifier = Verifier(config: try Config.builder().clock { 1_735_689_600_000 }.build())
        let body = #"{"receipt-data":"\#(try TestFixtures.text(TestFixtures.g5))"}"#
        let sandbox = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body)
        XCTAssertEqual(TestFixtures.status(sandbox), 0, String(sandbox.prefix(200)))
        XCTAssertTrue(sandbox.contains(#""request_date_ms":"1735689600000""#), String(sandbox.prefix(400)))
        XCTAssertEqual(TestFixtures.status(verifier.verifyReceiptEndpoint(environment: .production, requestJson: body)), 21007)
    }

    // MARK: init's answer

    /// An accepting init answer without max_input_bytes comes from a module
    /// of another ABI version: the instance is refused as an unusable
    /// answer, never used.
    func testAnInitAnswerWithoutAnInputLengthIsUnusable() throws {
        let pool = Pool(module: .success(try TestFixtures.double()), config: Array("old".utf8))
        XCTAssertThrowsError(try pool.create()) { error in
            guard case HostError.unusableAnswer(let export, let detail) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(export, "init")
            XCTAssertTrue(detail.contains("max_input_bytes"), detail)
        }
        for answer in [
            #"{"ok":true}"#, #"{"ok":true,"max_input_bytes":0}"#, #"{"ok":true,"max_input_bytes":-1}"#,
            #"{"ok":true,"max_input_bytes":"3145729"}"#, #"{"ok":true,"max_input_bytes":1.5}"#,
            #"{"ok":true,"max_input_bytes":null}"#, "not json",
        ] {
            XCTAssertThrowsError(try Wire.initAnswer(answer), answer) { error in
                guard case HostError.unusableAnswer(let export, _) = error, export == "init" else {
                    return XCTFail("\(answer): \(error)")
                }
            }
        }
        XCTAssertEqual(try Wire.initAnswer(#"{"ok":true,"max_input_bytes":3145729}"#), 3_145_729)
        XCTAssertThrowsError(try Wire.initAnswer(#"{"ok":false,"message":"no"}"#)) { error in
            guard case HostError.initRefused(let message) = error, message == "no" else { return XCTFail("\(error)") }
        }
    }

    /// The input length is the module's: an instance cuts every input to
    /// what its own init answer stated, here the double's 4 bytes, which the
    /// double's echo makes visible.
    func testEachInstanceCutsInputToTheLengthItsInitStated() throws {
        let pool = Pool(module: .success(try TestFixtures.double()), config: Array("s".utf8))
        let echoed = try pool.with { guest throws(HostError) in
            try guest.verifySignedData(now: 0, "abcdefgh".utf8)
        }
        XCTAssertEqual(echoed, "abcd")
        let guest = try pool.create()
        XCTAssertEqual(guest.maxInputBytes, 4)
        XCTAssertEqual(try guest.verifyReceipt(now: 0, Array("abcdefgh".utf8)), "abcd")
        XCTAssertEqual(try guest.verifyReceiptEndpoint(env: 1, now: 0, Array("abc".utf8)), "abc")
    }

    // MARK: the pool

    /// An instance whose memory grew past the reuse limit is dropped after
    /// its call rather than kept for the next caller.
    func testAnInstanceThatGrewIsNotReused() throws {
        let verifier = try verifier()
        XCTAssertTrue(verifier.verifySignedData(jws: #"{"verified":true,"payload":"{}","environment":null}"#).verified)
        XCTAssertEqual(verifier.pool.idleCount, 1)
        let grown = verifier.verifySignedData(jws: #"+"#)
        XCTAssertEqual(grown.failure?.reason, .internalError, "'+' is not a verification result")
        XCTAssertEqual(verifier.pool.idleCount, 0)
    }

    // MARK: helpers

    func doubleBytes() throws -> [UInt8] {
        [UInt8](try Data(contentsOf: try XCTUnwrap(Bundle.module.url(forResource: "double", withExtension: "wasm"))))
    }

}

/// Two modules too small to be worth a file, assembled with
/// `wasm-tools parse` from the text in their comments.
enum TinyModules {
    /// (module (memory (export "memory") 1)
    ///   (func (export "aprv:verifier/verify@2.0.0#init") (param i32 i32) (result i32) i32.const 0))
    static let otherVersion: [UInt8] = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01,
        0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x2c, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x1f, 0x61,
        0x70, 0x72, 0x76, 0x3a, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x40,
        0x32, 0x2e, 0x30, 0x2e, 0x30, 0x23, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0b,
    ]

    /// (module (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32))))
    static let wasiImport: [UInt8] = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x09, 0x01, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x02,
        0x23, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65,
        0x76, 0x69, 0x65, 0x77, 0x31, 0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00,
    ]
}

/// Four threads on one shared Verifier give the single-thread rows: the
/// same answer, byte for byte, as one sequential call.
final class ThreadTests: XCTestCase {
    func testFourThreadsGiveTheSingleThreadRows() throws {
        let clock: @Sendable () -> Int64 = { 1_735_689_600_000 }
        let receipts = Verifier(
            config: try Config.builder().roots([try TestFixtures.bytes(TestFixtures.receiptRoot)]).clock(clock).build())
        let jwses = Verifier(
            config: try Config.builder().roots([try TestFixtures.bytes(TestFixtures.jwsRoot)]).clock(clock).build())
        let apple = Verifier(config: try Config.builder().clock(clock).build())
        let receipt = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let g5 = try TestFixtures.text(TestFixtures.g5)
        let jws = try TestFixtures.text(TestFixtures.jws)
        let rows: [@Sendable () -> String] = [
            { describe(receipts.verifyReceipt(base64: receipt)) },
            { describe(apple.verifyReceipt(base64: g5)) },
            { apple.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(g5)"}"#) },
            { describe(jwses.verifySignedData(jws: jws)) },
            { describe(apple.verifySignedData(jws: jws)) },
            { describe(receipts.verifyReceipt(base64: "not base64")) },
        ]
        let expected = rows.map { $0() }
        XCTAssertEqual(TestFixtures.status(expected[2]), 0, "the genuine g5 receipt verifies at the endpoint")
        let results = Results(count: 4)
        DispatchQueue.concurrentPerform(iterations: 4) { thread in
            var got: [String] = []
            for round in 0..<3 {
                for i in rows.indices { got.append(rows[(i + thread + round) % rows.count]()) }
            }
            results.set(thread, got)
        }
        for thread in 0..<4 {
            var want: [String] = []
            for round in 0..<3 {
                for i in rows.indices { want.append(expected[(i + thread + round) % rows.count]) }
            }
            XCTAssertEqual(results.get(thread), want, "thread \(thread)")
        }
    }

    private final class Results: @unchecked Sendable {
        private let lock = NSLock()
        private var rows: [[String]]
        init(count: Int) { rows = Array(repeating: [], count: count) }
        func set(_ i: Int, _ value: [String]) { lock.lock(); rows[i] = value; lock.unlock() }
        func get(_ i: Int) -> [String] { lock.lock(); defer { lock.unlock() }; return rows[i] }
    }
}

func describe(_ result: VerificationResult<ReceiptPayload>) -> String {
    result.payload?.toJson() ?? "FAILED:\(result.failure!.reason.rawValue):\(result.failure!.message)"
}

func describe(_ result: VerificationResult<JsonPayload>) -> String {
    result.payload?.json ?? "FAILED:\(result.failure!.reason.rawValue):\(result.failure!.message)"
}
