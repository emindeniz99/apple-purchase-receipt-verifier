/// Verifies what Apple signed, offline, against the pinned roots of a
/// ``Config``.
///
/// Immutable and thread-safe (`Sendable`); share one across threads. The
/// verify methods never throw for any input: before a signature has
/// verified it is ``Reason/malformed``, as the input nobody vouched for must
/// not be able to raise the internal-error alarm at will; while the signed
/// receipt payload is read it is ``Reason/unreadablePayload``; anywhere
/// else, ``Reason/internalError``.
///
/// Swift has no equivalent of Java's `catch (Throwable)` or Rust's
/// `catch_unwind`: an out-of-bounds array access or a forced unwrap traps
/// and cannot be recovered, in this library or any other. Containment here
/// therefore comes from the same discipline the parsers in this library
/// apply throughout — bounds-checked access and `throw` instead of a trap or
/// a force-unwrap — rather than from a runtime safety net that could catch a
/// trap after the fact. Every unexpected `Error` an internal call throws
/// (not only this library's own ``Failure``) is still mapped to the right
/// ``Reason`` by which phase it happened in — before the signature, while
/// the payload is read, or after.
///
/// ```swift
/// let verifier = Verifier(config: .defaults())
/// let result = verifier.verifyReceipt(base64: receiptString)
/// if let payload = result.payload {
///     print(payload.toJson())
/// } else if let failure = result.failure {
///     print("rejected: \(failure.reason)")
/// }
/// ```
public struct Verifier: Sendable {
    private let config: Config

    /// A verifier for `config`. The roots are parsed once, when the
    /// ``Config`` is built, and never per call.
    public init(config: Config) {
        self.config = config
    }

    /// Verifies a legacy PKCS#7 app receipt, given as the base64 string a
    /// client sends, and decodes its payload.
    public func verifyReceipt(base64: String) -> VerificationResult<ReceiptPayload> {
        guard !config.roots.isEmpty else { return noAnchors() }
        return ApplePurchaseReceiptVerifier.verifyReceipt(base64: base64, roots: config.roots, clock: config.clock)
    }

    /// Verifies an Apple-signed compact JWS and returns its payload,
    /// unchanged.
    public func verifySignedData(jws: String) -> VerificationResult<JsonPayload> {
        guard !config.roots.isEmpty else { return noAnchors() }
        return ApplePurchaseReceiptVerifier.verifySignedData(jws: jws, roots: config.roots, clock: config.clock)
    }

    /// The response body Apple's `verifyReceipt` endpoint at `environment`
    /// would return for `requestJson`. Never fails: every verdict is the
    /// `status` inside the body.
    public func verifyReceiptEndpoint(environment: Environment, requestJson: String) -> String {
        ApplePurchaseReceiptVerifier.verifyReceiptEndpoint(
            environment: environment, requestJson: requestJson, roots: config.roots, clock: config.clock)
    }

    /// Only ``Config/defaults()`` can hand over an empty root set, when the
    /// bundled roots did not load; every verdict without an anchor would be
    /// a misleading ``Reason/untrustedChain``.
    private func noAnchors<T>() -> VerificationResult<T> {
        VerificationResult(
            failure: Failure(.internalError, "no trust anchors: the bundled Apple roots did not load"))
    }
}
