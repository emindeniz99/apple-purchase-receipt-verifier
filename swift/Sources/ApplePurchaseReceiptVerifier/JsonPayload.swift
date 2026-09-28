/// A verified JWS payload: the JSON object Apple signed, unchanged.
///
/// The library reads only `signedDate` from it. Parse ``json`` with the JSON
/// library of your choice, into a type declaring the claims you use; Apple's
/// claims are epoch milliseconds already. Public initializer so callers can
/// build one by hand in their own tests.
public struct JsonPayload: Sendable, Equatable {
    public let json: String

    public init(json: String) { self.json = json }
}
