namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// A verifier, not business logic: it answers one question — did Apple
    /// sign this data, under a pinned Apple root? If so, it returns the data.
    /// Bundle id, environment, product id, device binding, refunds and
    /// idempotency are the caller's decisions; this library takes no
    /// parameter for any of them.
    /// </summary>
    /// <remarks>
    /// Implementations are immutable, thread-safe, and never throw for any
    /// input to these three methods — callers mock this interface in their own
    /// tests, which is the reason it exists as an interface at all.
    /// </remarks>
    public interface IVerifier
    {
        /// <summary>Verifies a legacy PKCS#7 app receipt, base64-encoded.</summary>
        VerificationResult<ReceiptPayload> VerifyReceipt(string base64);

        /// <summary>
        /// Verifies any Apple-signed compact JWS: StoreKit 2 transactions,
        /// renewal info, app transactions, and App Store Server Notifications
        /// V2 (including its nested JWS — verify each one by calling this
        /// again).
        /// </summary>
        VerificationResult<JsonPayload> VerifySignedData(string jws);

        /// <summary>
        /// A drop-in local replacement for Apple's deprecated
        /// <c>verifyReceipt</c> endpoint: runs <see cref="VerifyReceipt"/> and
        /// renders the result in Apple's response format, as JSON text.
        /// </summary>
        string VerifyReceiptEndpoint(AppleEnvironment environment, string requestJson);
    }

    /// <summary>Builds an <see cref="IVerifier"/>.</summary>
    public static class Verifier
    {
        /// <summary>Creates a verifier from <paramref name="config"/>.</summary>
        public static IVerifier Create(Config config)
        {
            return new Internal.VerifierImpl(config ?? throw new System.ArgumentNullException(nameof(config)));
        }
    }
}
