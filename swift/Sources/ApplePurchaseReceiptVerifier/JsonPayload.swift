/// A verified JWS payload: the JSON object Apple signed, unchanged.
///
/// The library reads only `signedDate` from it. Parse ``json`` with the JSON
/// library of your choice, into a type declaring the claims you use; Apple's
/// claims are epoch milliseconds already. Public initializer so callers can
/// build one by hand in their own tests.
public struct JsonPayload: Sendable, Equatable {
    public let json: String
    /// The environment the verifier read from the payload
    /// (docs/rust-core/DECISIONS.md R42): the first of the top-level
    /// `environment` claim, a notification's `data.environment` and a summary
    /// notification's `summary.environment` that is present, `nil` when that
    /// one names neither environment (`Xcode`, `LocalTesting`) or none is.
    public let environment: Environment?

    public init(json: String, environment: Environment?) {
        self.json = json
        self.environment = environment
    }
}
