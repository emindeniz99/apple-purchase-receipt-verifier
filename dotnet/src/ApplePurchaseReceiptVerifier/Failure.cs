using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Why a <see cref="VerificationResult{T}"/> did not verify.
    /// </summary>
    /// <remarks>
    /// <see cref="Message"/> never embeds raw input: every message this library
    /// builds is fixed text, optionally with a bounded number or a fixed OID
    /// constant, never a substring of the bytes being verified. That is a
    /// simpler and stronger guarantee than sanitising quoted input after the
    /// fact, and it is safe to put in a log line as is. Switch on
    /// <see cref="Reason"/>; the text may change between releases.
    /// </remarks>
    public sealed class Failure
    {
        /// <summary>Builds a failure by hand, for callers mocking <see cref="IVerifier"/>.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="message"/> is <see langword="null"/>.</exception>
        public Failure(VerificationReason reason, string message, Exception? cause)
        {
            Reason = reason;
            Message = message ?? throw new ArgumentNullException(nameof(message));
            Cause = cause;
        }

        /// <summary>The machine-readable cause. Switch on this, never on <see cref="Message"/>.</summary>
        public VerificationReason Reason { get; }

        /// <summary>Human-readable detail, safe to log, not meant to be parsed.</summary>
        public string Message { get; }

        /// <summary>
        /// The inner exception behind <see cref="VerificationReason.UnreadablePayload"/>
        /// and <see cref="VerificationReason.InternalError"/>, so an operator can see
        /// why Apple-signed content did not parse. <see langword="null"/> for every
        /// other reason.
        /// </summary>
        public Exception? Cause { get; }

        /// <inheritdoc/>
        public override string ToString() => VerificationReasonCodes.ToCode(Reason) + ": " + Message;
    }
}
