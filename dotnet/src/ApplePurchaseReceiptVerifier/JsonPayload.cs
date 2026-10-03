namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// A verified Apple JWS payload: the JSON object Apple signed, unchanged.
    /// Covers every Apple JWS — transactions, renewal info, app transactions,
    /// and App Store Server Notifications V2. Deserialise <see cref="Json"/>
    /// with your own JSON library; this library ships no typed claim models.
    /// </summary>
    public sealed class JsonPayload
    {
        private JsonPayload(string json, AppleEnvironment? environment)
        {
            Json = json;
            Environment = environment;
        }

        /// <summary>The verified payload's JSON text, exactly as signed.</summary>
        public string Json { get; }

        /// <summary>
        /// The environment the verifier read from the payload
        /// (docs/rust-core/DECISIONS.md R42): the first of the top-level
        /// <c>environment</c> claim, a notification's <c>data.environment</c>
        /// and a summary notification's <c>summary.environment</c> that is
        /// present, <see langword="null"/> when that one names neither
        /// environment (<c>Xcode</c>, <c>LocalTesting</c>) or none is.
        /// </summary>
        public AppleEnvironment? Environment { get; }

        /// <summary>Builds a payload by hand, for a caller's own tests.</summary>
        public static JsonPayload Create(string json, AppleEnvironment? environment) => new JsonPayload(json, environment);
    }
}
