/// Which of Apple's two `verifyReceipt` URLs a call imitates, and what a
/// receipt's `receipt_type` or a JWS `environment` claim names.
public enum Environment: String, Sendable {
    case production = "Production"
    case sandbox = "Sandbox"

    /// Apple's spelling, as the endpoint response writes it.
    public var appleValue: String { rawValue }

    /// What a receipt's `receipt_type` means: `Production` and
    /// `ProductionVPP` are ``production``, `ProductionSandbox` and
    /// `ProductionVPPSandbox` are ``sandbox``, anything else (`Xcode`, a
    /// missing value) is `nil`. It states what Apple's value means and
    /// decides nothing; the endpoint routes 21007 and 21008 on the same rule.
    public static func fromReceiptType(_ receiptType: String?) -> Environment? {
        switch receiptType {
        case "Production", "ProductionVPP": return .production
        case "ProductionSandbox", "ProductionVPPSandbox": return .sandbox
        default: return nil
        }
    }

    /// What a JWS `environment` claim means: `Production` and `Sandbox`,
    /// anything else `nil`.
    public static func fromJwsEnvironment(_ environment: String?) -> Environment? {
        switch environment {
        case "Production": return .production
        case "Sandbox": return .sandbox
        default: return nil
        }
    }
}
