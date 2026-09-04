using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// An injectable source of "now" for the two checks that genuinely move
    /// with wall-clock time.
    /// </summary>
    /// <remarks>
    /// <para>The clock is read in exactly two places in this library:</para>
    /// <list type="number">
    ///   <item>the <see cref="VerificationReason.StalePayload"/> comparison in
    ///   <see cref="Jws.JwsVerifier"/>;</item>
    ///   <item>the <c>request_date</c> triple in
    ///   <see cref="Receipt.VerifyReceiptEndpoint"/>.</item>
    /// </list>
    /// <para>It never reaches a certificate-validity judgement. Those are made
    /// at the payload's own signing date, and where the input states none, at
    /// the <em>system</em> clock — so a caller injecting a clock (to pin a
    /// test, or to work around skew) cannot thereby accept a chain that is
    /// expired in real time. <see cref="Receipt.ReceiptVerifier"/> therefore
    /// takes no clock at all.</para>
    /// </remarks>
    public interface IClock
    {
        /// <summary>The current instant, in UTC.</summary>
        DateTimeOffset UtcNow { get; }
    }

    /// <summary>The wall clock. The default for every verifier.</summary>
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
