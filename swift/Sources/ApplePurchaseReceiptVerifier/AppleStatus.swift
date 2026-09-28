/// The status codes Apple documents for `verifyReceipt`, so callers do not
/// write `21007` by hand.
///
/// ``Verifier/verifyReceiptEndpoint(environment:requestJson:)`` returns ``ok``, ``malformedReceiptData``,
/// ``receiptNotAuthenticated``, ``sandboxReceiptOnProduction``,
/// ``productionReceiptOnSandbox`` and ``internalDataAccessError``, and never
/// the others. 21009 is deterministic for the same input: alert on it, do
/// not retry.
public enum AppleStatus {
    /// 0: the receipt is valid.
    public static let ok = 0
    /// 21000: the request was not an HTTP POST.
    public static let requestNotPost = 21000
    /// 21001: no longer sent by Apple.
    public static let noLongerSent = 21001
    /// 21002: the `receipt-data` was malformed or missing.
    public static let malformedReceiptData = 21002
    /// 21003: the receipt could not be authenticated.
    public static let receiptNotAuthenticated = 21003
    /// 21004: the shared secret does not match.
    public static let sharedSecretMismatch = 21004
    /// 21005: Apple's receipt server was unavailable.
    public static let serverUnavailable = 21005
    /// 21006: the receipt is valid but the subscription has expired.
    public static let subscriptionExpired = 21006
    /// 21007: a sandbox receipt was sent to the production endpoint.
    public static let sandboxReceiptOnProduction = 21007
    /// 21008: a production receipt was sent to the sandbox endpoint.
    public static let productionReceiptOnSandbox = 21008
    /// 21009: internal data access error.
    public static let internalDataAccessError = 21009
    /// 21010: the user account cannot be found or has been deleted.
    public static let accountNotFound = 21010
    /// 21100: first of Apple's internal data access error range.
    public static let internalDataAccessErrorRangeFirst = 21100
    /// 21199: last of Apple's internal data access error range.
    public static let internalDataAccessErrorRangeLast = 21199
}
