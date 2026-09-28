using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Internal control-flow exception carrying a <see cref="VerificationReason"/>
    /// up to the boundary in <c>Internal.VerifierImpl</c>, which converts it into
    /// a <see cref="Failure"/> and never lets it escape a public method.
    /// </summary>
    /// <remarks>
    /// 0.7's <c>Verifier</c> methods never throw for any input (docs/design/0.7-api.md,
    /// Setup): this type is no longer part of the public contract, only the
    /// mechanism the implementation uses internally to unwind out of a deeply
    /// nested parse the moment a check fails.
    /// </remarks>
    internal class VerificationException : Exception
    {
        internal VerificationException(VerificationReason reason, string message)
            : base(VerificationReasonCodes.ToCode(reason) + ": " + message)
        {
            Reason = reason;
        }

        internal VerificationException(VerificationReason reason, string message, Exception? innerException)
            : base(VerificationReasonCodes.ToCode(reason) + ": " + message, innerException)
        {
            Reason = reason;
        }

        /// <summary>The machine-readable cause.</summary>
        internal VerificationReason Reason { get; }

        /// <summary>The canonical cross-port token for <see cref="Reason"/>.</summary>
        internal string ReasonCode => VerificationReasonCodes.ToCode(Reason);

        /// <summary>The message with the leading "REASON: " prefix stripped, for building a <see cref="Failure"/>.</summary>
        internal string Detail => Message.Substring(ReasonCode.Length + 2);
    }
}
