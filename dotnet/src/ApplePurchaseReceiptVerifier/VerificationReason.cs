using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// The machine-readable cause of a failed verification. The vocabulary is
    /// closed and shared by every language port; the canonical wire spelling of
    /// each member is its <see cref="VerificationReasonCodes.ToCode"/> value,
    /// which is what <c>fixtures/cases.schema.json</c> pins.
    /// </summary>
    /// <remarks>
    /// Members are PascalCase because that is the .NET naming rule; the
    /// SCREAMING_SNAKE token lives in <see cref="VerificationReasonCodes"/>.
    /// </remarks>
    public enum VerificationReason
    {
        /// <summary>Not a parseable compact JWS, wrong <c>alg</c>, or a malformed <c>x5c</c> header.</summary>
        InvalidJwsFormat,

        /// <summary>A certificate in the JWS header could not be decoded.</summary>
        InvalidCertificate,

        /// <summary>Leaf, intermediate or receipt signer is missing the required Apple marker OID.</summary>
        InvalidCertificatePurpose,

        /// <summary>The certificate chain does not validate to a pinned Apple root.</summary>
        InvalidChain,

        /// <summary>A cryptographic signature check failed.</summary>
        InvalidSignature,

        /// <summary>The payload's bundle id does not match the configured one.</summary>
        WrongBundleId,

        /// <summary>The payload's environment is outside the accepted set.</summary>
        WrongEnvironment,

        /// <summary>The payload's app Apple id does not match (Production only).</summary>
        WrongAppAppleId,

        /// <summary>The receipt is not parseable PKCS#7/CMS, or its payload is malformed.</summary>
        InvalidReceiptFormat,

        /// <summary>The SHA-1 device-hash binding check failed.</summary>
        DeviceHashMismatch,

        /// <summary>The payload is older than the verifier's configured max signed age.</summary>
        StalePayload,
    }

    /// <summary>
    /// Converts between <see cref="VerificationReason"/> and the canonical
    /// SCREAMING_SNAKE token every port reports.
    /// </summary>
    public static class VerificationReasonCodes
    {
        /// <summary>
        /// The canonical token for <paramref name="reason"/>, e.g.
        /// <c>"INVALID_CHAIN"</c>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="reason"/> is not a declared member. The mapping is a
        /// hand-written switch rather than a mechanical name conversion so that
        /// adding a member without a code fails loudly instead of inventing a
        /// token no other port knows.
        /// </exception>
        public static string ToCode(VerificationReason reason)
        {
            switch (reason)
            {
                case VerificationReason.InvalidJwsFormat: return "INVALID_JWS_FORMAT";
                case VerificationReason.InvalidCertificate: return "INVALID_CERTIFICATE";
                case VerificationReason.InvalidCertificatePurpose: return "INVALID_CERTIFICATE_PURPOSE";
                case VerificationReason.InvalidChain: return "INVALID_CHAIN";
                case VerificationReason.InvalidSignature: return "INVALID_SIGNATURE";
                case VerificationReason.WrongBundleId: return "WRONG_BUNDLE_ID";
                case VerificationReason.WrongEnvironment: return "WRONG_ENVIRONMENT";
                case VerificationReason.WrongAppAppleId: return "WRONG_APP_APPLE_ID";
                case VerificationReason.InvalidReceiptFormat: return "INVALID_RECEIPT_FORMAT";
                case VerificationReason.DeviceHashMismatch: return "DEVICE_HASH_MISMATCH";
                case VerificationReason.StalePayload: return "STALE_PAYLOAD";
                default:
                    throw new ArgumentOutOfRangeException(nameof(reason), reason,
                        "no canonical code for this reason");
            }
        }

        /// <summary>Parses a canonical token back into a <see cref="VerificationReason"/>.</summary>
        /// <returns><see langword="true"/> when <paramref name="code"/> is one of the eleven tokens.</returns>
        public static bool TryParse(string? code, out VerificationReason reason)
        {
            switch (code)
            {
                case "INVALID_JWS_FORMAT": reason = VerificationReason.InvalidJwsFormat; return true;
                case "INVALID_CERTIFICATE": reason = VerificationReason.InvalidCertificate; return true;
                case "INVALID_CERTIFICATE_PURPOSE": reason = VerificationReason.InvalidCertificatePurpose; return true;
                case "INVALID_CHAIN": reason = VerificationReason.InvalidChain; return true;
                case "INVALID_SIGNATURE": reason = VerificationReason.InvalidSignature; return true;
                case "WRONG_BUNDLE_ID": reason = VerificationReason.WrongBundleId; return true;
                case "WRONG_ENVIRONMENT": reason = VerificationReason.WrongEnvironment; return true;
                case "WRONG_APP_APPLE_ID": reason = VerificationReason.WrongAppAppleId; return true;
                case "INVALID_RECEIPT_FORMAT": reason = VerificationReason.InvalidReceiptFormat; return true;
                case "DEVICE_HASH_MISMATCH": reason = VerificationReason.DeviceHashMismatch; return true;
                case "STALE_PAYLOAD": reason = VerificationReason.StalePayload; return true;
                default: reason = default; return false;
            }
        }
    }
}
