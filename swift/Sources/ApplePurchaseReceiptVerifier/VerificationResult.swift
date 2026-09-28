/// The outcome of a verify call: exactly one of ``payload`` or ``failure`` is
/// set.
public struct VerificationResult<T: Sendable>: Sendable {
    public let payload: T?
    public let failure: Failure?

    public var verified: Bool { payload != nil }

    init(payload: T) {
        self.payload = payload
        self.failure = nil
    }

    init(failure: Failure) {
        self.payload = nil
        self.failure = failure
    }
}
