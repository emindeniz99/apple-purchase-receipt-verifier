using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// An injectable source of "now" for the one output that genuinely moves
    /// with wall-clock time.
    /// </summary>
    /// <remarks>
    /// <para>The clock is read in exactly one place in this library: the
    /// <c>request_date</c> triple in
    /// <see cref="Receipt.VerifyReceiptEndpoint"/>.</para>
    /// <para>It never reaches a certificate-validity judgement. Those are made
    /// at the payload's own signing date, and where the input states none, at
    /// the <em>system</em> clock — so a caller injecting a clock (to pin a
    /// test, or to work around skew) cannot thereby accept a chain that is
    /// expired in real time. <see cref="Jws.JwsVerifier"/> and
    /// <see cref="Receipt.ReceiptVerifier"/> therefore take no clock at all.</para>
    /// </remarks>
    public interface IClock
    {
        /// <summary>The current instant, in UTC.</summary>
        DateTimeOffset UtcNow { get; }
    }

    /// <summary>The wall clock. The default for <see cref="Receipt.VerifyReceiptEndpoint"/>.</summary>
    public sealed class SystemClock : IClock
    {
        /// <summary>The shared instance.</summary>
        public static readonly SystemClock Instance = new SystemClock();

        private SystemClock()
        {
        }

        /// <inheritdoc/>
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }

    /// <summary>A clock frozen at one instant — for tests and for replaying a request.</summary>
    public sealed class FixedClock : IClock
    {
        /// <summary>Freezes the clock at <paramref name="at"/>.</summary>
        public FixedClock(DateTimeOffset at)
        {
            UtcNow = at.ToUniversalTime();
        }

        /// <inheritdoc/>
        public DateTimeOffset UtcNow { get; }
    }
}
