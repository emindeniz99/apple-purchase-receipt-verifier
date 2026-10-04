import Foundation

/// Verifies what Apple signed, offline, against the pinned roots of a
/// ``Config``.
///
/// Every decision is made by aprv.wasm, the one verification module every
/// port of this library runs, which ships inside this package and runs on
/// WasmKit, an interpreter written in Swift: no native code is generated
/// and none of the verification runs outside the WebAssembly sandbox. A
/// `Verifier` reads the clock, moves the input in and the answer out, and
/// turns what the module says into Swift values. It holds no parser, no
/// cryptography and no trust decision of its own.
///
/// Immutable and thread-safe (`Sendable`); share one across threads. It
/// owns a small pool of module instances: each is set up with the roots once,
/// serves one call at a time, and is discarded if the module traps. There
/// is nothing to close.
///
/// The verify methods never throw for any input. A failure of the machinery
/// itself (the module trapped, gave an answer this package cannot read, or
/// could not be loaded, or the clock answered a time before 1970) is
/// ``Reason/internalError``, with the category in ``Failure/cause``.
///
/// ```swift
/// let verifier = try Verifier(config: Config())
/// let result = verifier.verifyReceipt(base64: receiptString)
/// if let payload = result.payload {
///     print(payload.toJson())
/// } else if let failure = result.failure {
///     print("rejected: \(failure.reason)")
/// }
/// ```
public struct Verifier: Sendable {
    let pool: Pool
    private let clock: @Sendable () -> Int64

    /// A verifier for `config`. The first `Verifier` of a process loads
    /// aprv.wasm (checks its SHA-256 and parses it, a few milliseconds);
    /// the instances are created on first use.
    ///
    /// - Throws: ``ConfigError`` for an empty root set, or when the
    ///   verification module refuses one of the caller's roots as a
    ///   certificate or cannot be loaded to check them. The roots are
    ///   handed to a fresh module instance here, so a bad one is refused
    ///   at startup rather than on the first call. The default roots are
    ///   not checked here and never throw.
    public init(config: Config) throws {
        try config.check()
        self.init(config: config, module: AprvModule.bundled)
    }

    init(
        config: Config, module: Result<AprvModule, HostError>,
        random: @escaping @Sendable (Int) -> [UInt8] = Guest.systemRandomBytes
    ) {
        self.pool = Pool(module: module, config: config.initJson, random: random)
        self.clock = config.clock
    }

    /// Verifies a legacy PKCS#7 app receipt, given as the base64 string a
    /// client sends, and decodes its payload.
    public func verifyReceipt(base64: String) -> VerificationResult<ReceiptPayload> {
        let now: UInt64
        switch readClock() {
        case .success(let value): now = value
        case .failure(let failure): return VerificationResult(failure: failure)
        }
        let export = "verify-receipt"
        do {
            let answer = try pool.with { guest throws(HostError) in try guest.verifyReceipt(now: now, base64.utf8) }
            return Wire.result(answer, export, ReceiptPayload.self) { decoded, environment in
                var payload = decoded
                payload.environment = environment
                return payload
            }
        } catch {
            return VerificationResult(failure: Self.failure(error))
        }
    }

    /// Verifies an Apple-signed compact JWS and returns its payload,
    /// unchanged.
    public func verifySignedData(jws: String) -> VerificationResult<JsonPayload> {
        let now: UInt64
        switch readClock() {
        case .success(let value): now = value
        case .failure(let failure): return VerificationResult(failure: failure)
        }
        let export = "verify-signed-data"
        do {
            let answer = try pool.with { guest throws(HostError) in try guest.verifySignedData(now: now, jws.utf8) }
            return Wire.result(answer, export, String.self) { JsonPayload(json: $0, environment: $1) }
        } catch {
            return VerificationResult(failure: Self.failure(error))
        }
    }

    /// The response body Apple's `verifyReceipt` endpoint at `environment`
    /// would return for `requestJson`. Never fails: every verdict is the
    /// `status` inside the body, and a failure of the machinery or the clock
    /// is ``AppleStatus/internalDataAccessError``.
    public func verifyReceiptEndpoint(environment: Environment, requestJson: String) -> String {
        let failed = #"{"status":\#(AppleStatus.internalDataAccessError)}"#
        guard case .success(let now) = readClock() else { return failed }
        let env: UInt32 = environment == .production ? 0 : 1
        guard
            let answer = try? pool.with({ guest throws(HostError) in
                try guest.verifyReceiptEndpoint(env: env, now: now, requestJson.utf8)
            }),
            (try? JSONSerialization.jsonObject(with: Data(answer.utf8))) is [String: Any]
        else { return failed }
        return answer
    }

    /// Reads the configured clock once per call, before the input is looked
    /// at, as epoch milliseconds for the module. A time before 1970 is the
    /// caller's clock failing, not the input: ``Reason/internalError``.
    private func readClock() -> Result<UInt64, Failure> {
        let millis = clock()
        guard let now = UInt64(exactly: millis) else {
            return .failure(Failure(.internalError, "the configured clock answered a time before 1970"))
        }
        return .success(now)
    }

    /// A call that ended in the machinery, not in a verdict. The message
    /// names the category; the cause has the detail.
    private static func failure(_ error: HostError) -> Failure {
        let message: String
        switch error {
        case .trap: message = "the verification module trapped"
        case .unusableAnswer: message = "the verification module's answer was unusable"
        case .initRefused: message = "the verification module refused the configuration"
        case .abiMismatch, .moduleUnavailable: message = "the verification module could not be loaded"
        }
        return Failure(.internalError, message, cause: error)
    }
}
