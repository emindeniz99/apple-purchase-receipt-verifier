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
    /// <para>Members are PascalCase because that is the .NET naming rule; the
    /// SCREAMING_SNAKE token lives in <see cref="VerificationReasonCodes"/>.</para>
    /// <para>The first eleven and <see cref="InternalError"/> are the verifier
    /// vocabulary the schema pins. <see cref="InternalError"/> keeps the
    /// position it had when it was endpoint-only, so no member's numeric
    /// value moved. <see cref="MalformedRequest"/> and
    /// <see cref="RequestTooLarge"/> appear only on a
    /// <see cref="Receipt.VerifyReceiptResult"/>: no
    /// <see cref="VerificationException"/> is ever thrown with either, so a
    /// <c>switch</c> over a caught exception's reason never sees them.</para>
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

        /// <summary>
        /// The verifyReceipt request envelope is unusable: the body is not a
        /// JSON object or nests deeper than 64, or <c>receipt-data</c> is
        /// missing, empty or not a string. Reported only by
        /// <see cref="Receipt.VerifyReceiptResult.FailureReason"/>; never
        /// thrown.
        /// </summary>
        MalformedRequest,

        /// <summary>
        /// Not the client's fault, status 21009 at the endpoint. Thrown when a
        /// trusted signer signed receipt content this library cannot read
        /// (found only after the chain and the signature passed; the parser's
        /// error is the <see cref="Exception.InnerException"/>), and reported
        /// by the endpoint for an unexpected exception inside it, with the
        /// exception in <see cref="Receipt.VerifyReceiptResult.FailureCause"/>.
        /// Alert and retry or escalate; do not deny the user on it.
        /// </summary>
        InternalError,

        /// <summary>
        /// The raw verifyReceipt request body is over
        /// <see cref="Receipt.VerifyReceiptEndpoint.MaxRequestBytes"/>
        /// (3,145,728 UTF-8 bytes), the size at which Apple's endpoint answers
        /// HTTP 413. Status 21002 in the response body; an HTTP layer can map
        /// it to 413 as Apple does. Reported only by
        /// <see cref="Receipt.VerifyReceiptResult.FailureReason"/>; never
        /// thrown.
        /// </summary>
        RequestTooLarge,
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
                case VerificationReason.MalformedRequest: return "MALFORMED_REQUEST";
                case VerificationReason.InternalError: return "INTERNAL_ERROR";
                case VerificationReason.RequestTooLarge: return "REQUEST_TOO_LARGE";
                default:
                    throw new ArgumentOutOfRangeException(nameof(reason), reason,
                        "no canonical code for this reason");
            }
        }

        /// <summary>Parses a canonical token back into a <see cref="VerificationReason"/>.</summary>
        /// <returns><see langword="true"/> when <paramref name="code"/> is one of the fourteen tokens.</returns>
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
                case "MALFORMED_REQUEST": reason = VerificationReason.MalformedRequest; return true;
                case "INTERNAL_ERROR": reason = VerificationReason.InternalError; return true;
                case "REQUEST_TOO_LARGE": reason = VerificationReason.RequestTooLarge; return true;
                default: reason = default; return false;
            }
        }
    }
}
