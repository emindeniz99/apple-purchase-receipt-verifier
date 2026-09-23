import Foundation
import X509

/// Drop-in local replacement for Apple's deprecated `verifyReceipt`
/// endpoint: same request body, same response body shape, same status
/// codes — but verified offline against the pinned Apple root instead of by
/// calling Apple. Field-by-field fidelity and the unavoidable gaps (fields
/// that only exist in Apple's server-side subscription database, like
/// `latest_receipt_info` / `pending_renewal_info`) are documented in
/// COMPARISON.md.
///
/// Like Apple's endpoint, this does NOT check the bundle id — the caller
/// compares `receipt["bundle_id"]`, exactly as with the real endpoint.
public struct VerifyReceiptEndpoint: Sendable {
    public static let statusOK = 0
    /// Malformed request or receipt-data property.
    public static let statusMalformed = 21002
    /// Receipt could not be authenticated.
    public static let statusNotAuthenticated = 21003
    /// Sandbox receipt sent to the production environment.
    public static let statusSandboxReceiptOnProduction = 21007
    /// Production receipt sent to the sandbox environment.
    public static let statusProductionReceiptOnSandbox = 21008
    /// Internal error.
    public static let statusInternal = 21009

    /// Ceiling on a raw JSON request body, in UTF-8 bytes: Apple's own limit,
    /// a fixed constant in every port. Measured on 2026-09-23 against both
    /// of Apple's verifyReceipt endpoints, a body of 3,145,728 bytes is
    /// answered and one of 3,145,729 bytes gets HTTP 413, counted in UTF-8
    /// bytes rather than characters. A larger body fails with
    /// ``VerificationError/Reason/requestTooLarge``, status 21002, before
    /// the depth scan and the parse: JSON parsing allocates a multiple of the
    /// body, and that happens before any verification.
    ///
    /// Measured with `utf8.count`, which is constant time for a native Swift
    /// string (UTF-8 storage) and exact, though linear, for a bridged one. A
    /// body already decoded to a dictionary is not measured.
    public static let maxRequestBytes = 3_145_728

    /// How deep a JSON structure the request body may nest; the Java
    /// port's number. A verifyReceipt body is a flat object of strings.
    /// `JSONSerialization` takes no depth option, so the depth is counted
    /// before it runs.
    static let maxJsonNestingDepth = 64

    private let roots: [Certificate]
    private let environment: AppleEnvironment
    private let clock: @Sendable () -> Date
    /// The verification primitive, ``ReceiptVerifier/verifyCore(receipt:roots:)``
    /// outside tests. A stored closure only so a test can make it throw
    /// something other than a ``VerificationError``, which no input reaches
    /// today, and watch that become ``VerificationError/Reason/internalError``.
    let core: @Sendable (Data, [Certificate]) async throws -> AppReceipt

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleReceiptRoots()``)
    ///   - environment: which environment this instance emulates
    ///     (drives 21007/21008 routing). ``AppleEnvironment/production`` or
    ///     ``AppleEnvironment/sandbox``. Apple's verifyReceipt endpoint has
    ///     no other environment to emulate, and the two it does not name
    ///     (`Xcode`, `LocalTesting`) are rejected here rather than folded into
    ///     one of them. This is the `environment` enum node, python and
    ///     fixtures/cases.json use.
    ///   - clock: the source of "now" for the response's `request_date`
    ///     fields, which Apple's endpoint stamps with the wall-clock time the
    ///     request was served. Same type and same meaning as
    ///     ``JwsVerifier/init(trustedRoots:bundleId:acceptedEnvironments:appAppleId:maxSignedAgeMillis:clock:)``:
    ///     omitted, the system clock is read. It is read once per call, and
    ///     not at all when the call passes its own `now`. It moves no
    ///     verdict: the status code and every verified field are unaffected.
    ///     In particular it never reaches a certificate-validity decision: the
    ///     receipt path takes no clock at all, and judges chain validity at
    ///     the receipt's creation date, falling back to the system clock.
    public init(
        trustedRoots: [Data], environment: AppleEnvironment,
        clock: (@Sendable () -> Date)? = nil
    ) throws {
        try Self.requireEmulated(environment)
        guard !trustedRoots.isEmpty else {
            throw VerificationError(.invalidCertificate, "trustedRoots is required")
        }
        // No ReceiptVerifier, and so no bundle id: the endpoint accepts any
        // bundle exactly as Apple's does (callers compare bundle_id), and
        // ``ReceiptVerifier/verifyCore(receipt:trustedRoots:)`` is that
        // primitive without the claim check. It used to hold a verifier built
        // with a wildcard bundle id — a stand-in for a check that never ran.
        self.roots = try trustedRoots.map { try Certificate(derEncoded: [UInt8]($0)) }
        self.environment = environment
        self.clock = clock ?? { Date() }
        self.core = { try await ReceiptVerifier.verifyCore(receipt: $0, roots: $1) }
    }

    init(_ endpoint: VerifyReceiptEndpoint, core: @escaping @Sendable (Data, [Certificate]) async throws -> AppReceipt) {
        self.roots = endpoint.roots
        self.environment = endpoint.environment
        self.clock = endpoint.clock
        self.core = core
    }

    /// Refuses an environment Apple's verifyReceipt endpoint cannot emulate,
    /// for the initializer and for ``VerifyReceiptResult/response(for:)``.
    static func requireEmulated(_ environment: AppleEnvironment) throws {
        guard environment == .production || environment == .sandbox else {
            throw VerificationError(
                .wrongEnvironment,
                "verifyReceipt emulates Production or Sandbox, not \(environment.rawValue)")
        }
    }

    /// Handles one verifyReceipt request body. Never throws: like the real
    /// endpoint, failures are reported through the result's ``VerifyReceiptResult/status``
    /// and ``VerifyReceiptResult/failureReason``.
    ///
    /// - Parameter now: the instant to render as `request_date`; nil reads
    ///   the endpoint's clock, once. It feeds `request_date` and nothing
    ///   else.
    public func verifyReceiptResult(_ requestBody: [String: Any]?, now: Date? = nil) async -> VerifyReceiptResult {
        let at = now ?? clock()
        guard let receiptData = requestBody?["receipt-data"] as? String else {
            return failed(.malformedRequest, at)
        }
        return await verify(receiptData, at)
    }

    /// Handles one verifyReceipt request body in its raw wire form, the JSON
    /// text an HTTP framework hands over. Never throws.
    ///
    /// A body over ``maxRequestBytes`` UTF-8 bytes fails with
    /// ``VerificationError/Reason/requestTooLarge``, status 21002, before
    /// anything else looks at it; Apple answers that body with HTTP 413. A
    /// body that is not a JSON object (unparseable, `null`, an array, a
    /// scalar) or nests more than 64 levels deep fails with
    /// ``VerificationError/Reason/malformedRequest``, status 21002, and the
    /// depth is checked before it is parsed. Apple has no status code for
    /// "that wasn't JSON"; 21002 ("The data in the receipt-data property was
    /// malformed or missing") is the closest, and it is what a JSON object
    /// without usable `receipt-data` gets anyway.
    public func verifyReceiptResult(_ body: String, now: Date? = nil) async -> VerifyReceiptResult {
        let at = now ?? clock()
        guard body.utf8.count <= Self.maxRequestBytes else {
            return failed(.requestTooLarge, at)
        }
        guard !jsonNestingExceeds(body.utf8, limit: Self.maxJsonNestingDepth),
            let data = body.data(using: .utf8),
            let parsed = try? JSONSerialization.jsonObject(with: data),
            let requestBody = parsed as? [String: Any]
        else {
            return failed(.malformedRequest, at)
        }
        return await verifyReceiptResult(requestBody, now: at)
    }

    /// Verifies a bare base64 receipt, the value a request body would carry
    /// as `receipt-data`, with no envelope around it. Never throws; a nil or
    /// empty string fails with ``VerificationError/Reason/malformedRequest``,
    /// as a missing `receipt-data` does.
    public func verifyReceiptData(_ base64: String?, now: Date? = nil) async -> VerifyReceiptResult {
        await verify(base64, now ?? clock())
    }

    /// Handles one verifyReceipt request body in its raw wire form: the
    /// JSON request body in, the JSON response body out, so an HTTP
    /// framework's body can be piped straight through without a DTO in
    /// between. The same as `verifyReceiptResult(body).json()`.
    ///
    /// Output is deterministic: Swift dictionaries have no insertion
    /// order, so keys are serialized sorted (`.sortedKeys`). Key order is
    /// not part of the JSON contract, only the bytes being reproducible
    /// is.
    public func verifyReceiptJSON(_ body: String) async -> String {
        await verifyReceiptResult(body).json()
    }

    /// The one verification path every entry point ends in. `at` only
    /// becomes `request_date`: certificate validity is judged inside
    /// ``ReceiptVerifier/verifyCore(receipt:roots:)``, which takes no time
    /// input.
    private func verify(_ receiptData: String?, _ at: Date) async -> VerifyReceiptResult {
        guard let receiptData, !receiptData.isEmpty else {
            return failed(.malformedRequest, at)
        }
        // The decode below runs before verifyCore could apply its own cap, so
        // the cap is applied to the string here, as
        // ReceiptVerifier.verify(base64Receipt:) does, before anything is
        // allocated.
        guard receiptData.utf8.count <= ReceiptVerifier.maxReceiptBytes else {
            return failed(.invalidReceiptFormat, at)
        }
        guard let der = decodeReceiptBase64(receiptData) else {
            return failed(.invalidReceiptFormat, at)
        }
        do {
            // The primitive itself, not a ReceiptVerifier built around a
            // wildcard bundle id: like Apple's endpoint, no bundle-id claim
            // is checked here (callers compare receipt.bundle_id).
            let receipt = try await core(der, roots)
            return VerifyReceiptResult(environment: environment, outcome: .verified(receipt), requestDate: at)
        } catch let error as VerificationError {
            return failed(error.reason, at)
        } catch {
            return VerifyReceiptResult(
                environment: environment, outcome: .failed(reason: .internalError, cause: error), requestDate: at)
        }
    }

    private func failed(_ reason: VerificationError.Reason, _ at: Date) -> VerifyReceiptResult {
        VerifyReceiptResult(environment: environment, outcome: .failed(reason: reason, cause: nil), requestDate: at)
    }
}
