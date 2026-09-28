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
        private JsonPayload(string json)
        {
            Json = json;
        }

        /// <summary>The verified payload's JSON text, exactly as signed.</summary>
        public string Json { get; }

        /// <summary>Builds a payload by hand, for a caller's own tests.</summary>
        public static JsonPayload Create(string json) => new JsonPayload(json);
    }
}
