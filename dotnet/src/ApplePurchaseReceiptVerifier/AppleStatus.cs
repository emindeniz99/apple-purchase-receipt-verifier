namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Named constants for every status code Apple documents for
    /// <c>verifyReceipt</c> (21000 to 21010, and the 21100 to 21199 range),
    /// so a caller need not write <c>21007</c> by hand. Only a subset can
    /// actually come out of <see cref="IVerifier.VerifyReceiptEndpoint"/>;
    /// each constant's remarks say whether it can.
    /// </summary>
    public static class AppleStatus
    {
        /// <summary>The receipt is valid. Returned by the endpoint.</summary>
        public const int Ok = 0;

        /// <summary>The App Store could not read the JSON object you provided. Not returned by the endpoint.</summary>
        public const int InvalidJson = 21000;

        /// <summary>The receipt-data property was malformed or missing. Returned by the endpoint (<c>MALFORMED</c>, <c>TOO_LARGE</c>).</summary>
        public const int MalformedReceiptData = 21002;

        /// <summary>The receipt could not be authenticated. Returned by the endpoint (<c>INVALID_SIGNATURE</c>, <c>UNTRUSTED_CHAIN</c>, <c>INVALID_CERTIFICATE</c>, <c>INVALID_CERTIFICATE_PURPOSE</c>).</summary>
        public const int NotAuthenticated = 21003;

        /// <summary>The shared secret does not match. Not applicable; not returned.</summary>
        public const int InvalidSharedSecret = 21004;

        /// <summary>The receipt server is temporarily unable to provide the receipt. Not returned by the endpoint, which never fails transiently.</summary>
        public const int ServerUnavailable = 21005;

        /// <summary>Valid receipt, but the subscription has expired. Not applicable to a verifier with no subscription database; not returned.</summary>
        public const int SubscriptionExpired = 21006;

        /// <summary>This receipt is a sandbox receipt, sent to the production service. Returned by the endpoint.</summary>
        public const int SandboxReceiptOnProduction = 21007;

        /// <summary>This receipt is a production receipt, sent to the sandbox service. Returned by the endpoint.</summary>
        public const int ProductionReceiptOnSandbox = 21008;

        /// <summary>Internal data access error. Returned by the endpoint (<c>UNREADABLE_PAYLOAD</c>, <c>INTERNAL_ERROR</c>); deterministic here, alert rather than retry.</summary>
        public const int InternalDataAccessError = 21009;

        /// <summary>The user account cannot be found or has been deleted. Not applicable; not returned.</summary>
        public const int UserAccountNotFound = 21010;
    }
}
