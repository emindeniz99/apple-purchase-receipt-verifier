using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Why a <see cref="VerificationResult{T}"/> did not verify.
    /// </summary>
    /// <remarks>
    /// <see cref="Message"/> never embeds raw input: every message is fixed text,
    /// optionally with a bounded number or a fixed OID constant, never a
    /// substring of the bytes being verified. That is a
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
        /// The exception behind an <see cref="VerificationReason.InternalError"/>
        /// that this library raised itself: the verification module trapped, its
        /// answer could not be read, or the configured clock failed. A verdict of
        /// the module, whichever reason it carries, has none, and neither does any
        /// other reason: the module's messages are all a caller gets about the input.
        /// </summary>
        public Exception? Cause { get; }

        /// <inheritdoc/>
        public override string ToString() => VerificationReasonCodes.ToCode(Reason) + ": " + Message;
    }
}
