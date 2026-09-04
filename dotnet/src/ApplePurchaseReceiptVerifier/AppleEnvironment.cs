using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// The App Store server environment a signed payload was produced in.
    /// </summary>
    /// <remarks>
    /// Named <c>AppleEnvironment</c> rather than <c>Environment</c> because
    /// <see cref="System.Environment"/> exists and an unqualified
    /// <c>Environment</c> in a consumer's file is a resolution trap.
    /// </remarks>
    public enum AppleEnvironment
    {
        /// <summary>The <c>"Production"</c> claim value.</summary>
        Production,

        /// <summary>The <c>"Sandbox"</c> claim value.</summary>
        Sandbox,

        /// <summary>The <c>"Xcode"</c> claim value (StoreKit Testing in Xcode).</summary>
        Xcode,

        /// <summary>The <c>"LocalTesting"</c> claim value.</summary>
        LocalTesting,
    }

    /// <summary>
    /// Converts between <see cref="AppleEnvironment"/> and the claim strings
    /// Apple ships in <c>environment</c> / <c>receiptType</c>.
    /// </summary>
    public static class AppleEnvironments
    {
        /// <summary>The claim value, e.g. <c>"Production"</c>.</summary>
        /// <exception cref="ArgumentOutOfRangeException">Not a declared member.</exception>
        public static string ToValue(AppleEnvironment environment)
        {
            switch (environment)
            {
                case AppleEnvironment.Production: return "Production";
                case AppleEnvironment.Sandbox: return "Sandbox";
                case AppleEnvironment.Xcode: return "Xcode";
                case AppleEnvironment.LocalTesting: return "LocalTesting";
                default:
                    throw new ArgumentOutOfRangeException(nameof(environment), environment,
                        "no claim value for this environment");
            }
        }

        /// <summary>Maps a payload claim value onto an <see cref="AppleEnvironment"/>.</summary>
        public static bool TryParse(string? value, out AppleEnvironment environment)
        {
            switch (value)
            {
                case "Production": environment = AppleEnvironment.Production; return true;
                case "Sandbox": environment = AppleEnvironment.Sandbox; return true;
                case "Xcode": environment = AppleEnvironment.Xcode; return true;
                case "LocalTesting": environment = AppleEnvironment.LocalTesting; return true;
                default: environment = default; return false;
            }
        }
    }
}
