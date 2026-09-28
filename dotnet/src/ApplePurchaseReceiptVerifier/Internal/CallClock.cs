using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Reads the configured clock on behalf of a verification.</summary>
    internal static class CallClock
    {
        /// <summary>
        /// The configured clock's "now", in epoch milliseconds. A clock that
        /// throws is the host's fault, not the input's, so it surfaces as
        /// <see cref="VerificationReason.InternalError"/> with the clock's
        /// exception as the cause: a <see cref="VerificationException"/> the
        /// guards that report unexpected errors on unverified input as
        /// <see cref="VerificationReason.Malformed"/> pass through unchanged.
        /// </summary>
        internal static long Read(Func<long> clock)
        {
            try
            {
                return clock();
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                throw new VerificationException(VerificationReason.InternalError, "the configured clock failed", e);
            }
        }
    }
}
