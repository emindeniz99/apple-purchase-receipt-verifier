using System.Collections.Generic;

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

        /// <summary>
        /// The URLs of the revocation lists this verifier expects, as the
        /// verification module states them (docs/design/revocation.md §7): with
        /// Apple's roots, the lists of Apple Root CA, Apple Root CA - G3, WWDR G5
        /// and WWDR G6, then the distribution points of added
        /// <see cref="Config.RevocationIssuers"/>. Download these with your own
        /// HTTP client, on your own schedule, and pass the bytes as
        /// <c>revocationLists</c> to a new verifier. Empty with your own roots
        /// and no added issuers. Unmodifiable.
        /// </summary>
        IReadOnlyList<string> RevocationUrls { get; }

        /// <summary>
        /// The earliest <c>nextUpdate</c> among the revocation lists held for
        /// the issuers this verifier expects a list from, in epoch milliseconds
        /// (UTC), like every date this library reports.
        /// <see langword="null"/> when any of them has no list held (none passed,
        /// or the list was ignored): live revocation is then not fully in force.
        /// A time in the past means a list is stale. Monitor both; neither fails
        /// a call.
        /// </summary>
        long? RevocationValidUntilMs { get; }
    }

    /// <summary>Builds an <see cref="IVerifier"/>.</summary>
    public static class Verifier
    {
        /// <summary>Creates a verifier from <paramref name="config"/>.</summary>
        /// <remarks>
        /// One module instance starts here and checks the configuration; it
        /// then serves the first call. To take new revocation lists, create a
        /// new verifier and swap the reference.
        /// </remarks>
        /// <exception cref="System.ArgumentException">
        /// The verification module refused the configuration: a root that is
        /// not a certificate, or a revocation setting it refuses. The message
        /// names the first problem and its index.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">The verification module cannot be hosted.</exception>
        public static IVerifier Create(Config config)
        {
            return new Internal.VerifierImpl(config ?? throw new System.ArgumentNullException(nameof(config)));
        }
    }
}
