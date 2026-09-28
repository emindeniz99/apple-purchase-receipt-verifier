using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Apple's two verifyReceipt server environments.
    /// </summary>
    /// <remarks>
    /// <para>Named <c>AppleEnvironment</c> rather than <c>Environment</c> because
    /// <see cref="System.Environment"/> exists and an unqualified
    /// <c>Environment</c> in a consumer's file is a resolution trap.</para>
    /// <para>0.7 drops the 0.6 <c>Xcode</c> and <c>LocalTesting</c> members: they
    /// only ever named JWS <c>environment</c> strings, such payloads are not
    /// Apple-signed and fail the chain check regardless, and the caller now
    /// reads that string from the verified JSON itself.</para>
    /// </remarks>
    public enum AppleEnvironment
    {
        /// <summary>Apple's production verifyReceipt URL.</summary>
        Production,

        /// <summary>Apple's sandbox verifyReceipt URL.</summary>
        Sandbox,
    }

    /// <summary>
    /// Maps Apple's <c>receipt_type</c> and JWS <c>environment</c> claim strings
    /// onto <see cref="AppleEnvironment"/>. States what Apple's value means and
    /// decides nothing.
    /// </summary>
    public static class AppleEnvironments
    {
        /// <summary>
        /// Maps a receipt's <c>receipt_type</c> attribute: <c>Production</c> and
        /// <c>ProductionVPP</c> to <see cref="AppleEnvironment.Production"/>,
        /// <c>ProductionSandbox</c> and <c>ProductionVPPSandbox</c> to
        /// <see cref="AppleEnvironment.Sandbox"/>, anything else to
        /// <see langword="null"/>. <see cref="IVerifier.VerifyReceiptEndpoint"/>
        /// uses the same rule for its 21007/21008 routing.
        /// </summary>
        public static AppleEnvironment? FromReceiptType(string? receiptType)
        {
            switch (receiptType)
            {
                case "Production":
                case "ProductionVPP":
                    return AppleEnvironment.Production;
                case "ProductionSandbox":
                case "ProductionVPPSandbox":
                    return AppleEnvironment.Sandbox;
                default:
                    return null;
            }
        }

        /// <summary>
        /// Maps a JWS <c>environment</c> claim: <c>Production</c> to
        /// <see cref="AppleEnvironment.Production"/>, <c>Sandbox</c> to
        /// <see cref="AppleEnvironment.Sandbox"/>, anything else to
        /// <see langword="null"/>.
        /// </summary>
        public static AppleEnvironment? FromJwsEnvironment(string? environment)
        {
            switch (environment)
            {
                case "Production": return AppleEnvironment.Production;
                case "Sandbox": return AppleEnvironment.Sandbox;
                default: return null;
            }
        }

        /// <summary>The wire spelling Apple's endpoint response uses for <paramref name="environment"/>.</summary>
        internal static string ToValue(AppleEnvironment environment)
        {
            switch (environment)
            {
                case AppleEnvironment.Production: return "Production";
                case AppleEnvironment.Sandbox: return "Sandbox";
                default:
                    throw new ArgumentOutOfRangeException(nameof(environment), environment,
                        "no claim value for this environment");
            }
        }
    }
}
