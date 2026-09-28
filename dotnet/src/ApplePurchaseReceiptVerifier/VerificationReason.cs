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
    /// This is the 0.7 set (docs/design/0.7-api.md, Result): eight values,
    /// none shared with the 0.6 vocabulary's <c>WRONG_*</c> or
    /// <c>DEVICE_HASH_MISMATCH</c> members, which 0.7 drops along with the
    /// policy the library no longer judges.
    /// </remarks>
    public enum VerificationReason
    {
        /// <summary>Base64, ASN.1, CMS or JWS structure is broken.</summary>
        Malformed,

        /// <summary>Input over a fixed cap (design doc, Bounds).</summary>
        TooLarge,

        /// <summary>The signature does not match the content.</summary>
        InvalidSignature,

        /// <summary>The chain does not reach a pinned root.</summary>
        UntrustedChain,

        /// <summary>An unreadable certificate, or one outside its validity window at the chain instant.</summary>
        InvalidCertificate,

        /// <summary>A valid Apple certificate of the wrong kind: marker OID missing.</summary>
        InvalidCertificatePurpose,

        /// <summary>Apple signed it, but the content does not parse.</summary>
        UnreadablePayload,

        /// <summary>The library failed; alert, do not retry.</summary>
        InternalError,
    }

    /// <summary>
    /// Converts between <see cref="VerificationReason"/> and the canonical
    /// SCREAMING_SNAKE token every port reports.
    /// </summary>
    public static class VerificationReasonCodes
    {
        /// <summary>The canonical token for <paramref name="reason"/>, e.g. <c>"UNTRUSTED_CHAIN"</c>.</summary>
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
                case VerificationReason.Malformed: return "MALFORMED";
                case VerificationReason.TooLarge: return "TOO_LARGE";
                case VerificationReason.InvalidSignature: return "INVALID_SIGNATURE";
                case VerificationReason.UntrustedChain: return "UNTRUSTED_CHAIN";
                case VerificationReason.InvalidCertificate: return "INVALID_CERTIFICATE";
                case VerificationReason.InvalidCertificatePurpose: return "INVALID_CERTIFICATE_PURPOSE";
                case VerificationReason.UnreadablePayload: return "UNREADABLE_PAYLOAD";
                case VerificationReason.InternalError: return "INTERNAL_ERROR";
                default:
                    throw new ArgumentOutOfRangeException(nameof(reason), reason,
                        "no canonical code for this reason");
            }
        }

        /// <summary>Parses a canonical token back into a <see cref="VerificationReason"/>.</summary>
        /// <returns><see langword="true"/> when <paramref name="code"/> is one of the eight tokens.</returns>
        public static bool TryParse(string? code, out VerificationReason reason)
        {
            switch (code)
            {
                case "MALFORMED": reason = VerificationReason.Malformed; return true;
                case "TOO_LARGE": reason = VerificationReason.TooLarge; return true;
                case "INVALID_SIGNATURE": reason = VerificationReason.InvalidSignature; return true;
                case "UNTRUSTED_CHAIN": reason = VerificationReason.UntrustedChain; return true;
                case "INVALID_CERTIFICATE": reason = VerificationReason.InvalidCertificate; return true;
                case "INVALID_CERTIFICATE_PURPOSE": reason = VerificationReason.InvalidCertificatePurpose; return true;
                case "UNREADABLE_PAYLOAD": reason = VerificationReason.UnreadablePayload; return true;
                case "INTERNAL_ERROR": reason = VerificationReason.InternalError; return true;
                default: reason = default; return false;
            }
        }
    }
}
