using System;
using System.Globalization;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What the payload's stated <c>signedDate</c> is allowed to do. It picks the
/// certificate-validity instant, so the rule for reading it is part of the
/// trust decision (design, "Which failure a parse problem gets"): a number a
/// signed 64-bit value holds is the instant, a fraction is truncated, and
/// anything else — absent, not a number, no representable instant — counts
/// as not stated, so the config clock stands in.
/// </summary>
public class SigningTimeTests
{
    private static readonly DateTimeOffset Jan2024 = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A chain valid 2024-01-01 to 2025-01-01, minted once.</summary>
    private static readonly Lazy<TestPki.JwsChain> ShortChain =
        new(() => TestPki.NewJwsChain(Jan2024, new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)));

    /// <summary>2030-01-01T00:00:00Z: after <see cref="ShortChain"/> expired, so a clock fallback fails it.</summary>
    private const long After = 1893456000000L;

    private static string Jws(TestPki.JwsChain chain, string signedDateLiteral) =>
        chain.Sign("{\"bundleId\":\"com.example.app\",\"signedDate\":" + signedDateLiteral + "}");

    /// <summary>
    /// A non-integral <c>signedDate</c> is still a stated signing time. Java,
    /// Node and Python all take it, so it must move the certificate-validity
    /// instant: judged at the clock (2030), this chain has expired.
    /// </summary>
    [Fact]
    public void AFractionalSignedDateDrivesTheCertificateValidityInstant()
    {
        TestPki.JwsChain chain = ShortChain.Value;
        Assert.True(chain.Verifier(After).VerifySignedData(Jws(chain, "1722945600000.5")).Verified);
        Assert.True(chain.Verifier(After).VerifySignedData(Jws(chain, "1.7229456e12")).Verified);
    }

    /// <summary>
    /// A signing time a signed 64-bit millisecond count holds is the instant,
    /// even where <see cref="DateTimeOffset"/> cannot represent it: the chain
    /// is judged there and fails its validity window rather than throwing or
    /// quietly falling back to the clock (which, inside the window, would
    /// verify). The Java reference reads the same claim with
    /// <c>getLongValue()</c> and judges at that instant.
    /// </summary>
    [Theory]
    [InlineData("253402300800000")]        // one millisecond past DateTimeOffset.MaxValue
    [InlineData("9223372036854775807")]    // long.MaxValue
    [InlineData("9223372036854775000")]
    [InlineData("-62135596800001")]        // one millisecond before DateTimeOffset.MinValue
    [InlineData("-9223372036854775808")]   // long.MinValue
    public void ASigningTimeALongHoldsIsTheInstantEvenOutsideTheCalendar(string literal)
    {
        TestPki.JwsChain chain = ShortChain.Value;
        Assert.Equal(
            VerificationReason.InvalidCertificate,
            chain.Verifier(TestPki.SignedAtMs).VerifySignedData(Jws(chain, literal)).Failure?.Reason);
    }

    /// <summary>
    /// A number no signed 64-bit value holds is no instant (owner,
    /// 2026-09-27: "such as 1e300"), including one whose literal overflows a
    /// double to infinity and an integer one past <c>long.MaxValue</c>. It
    /// counts as not stated: the clock decides, inside the window here.
    /// </summary>
    [Theory]
    [InlineData("1e300")]
    [InlineData("-1e300")]
    [InlineData("1e999")]
    [InlineData("9223372036854775808")]
    [InlineData("-9223372036854775809")]
    public void ANumberNoLongHoldsFallsBackToTheClock(string literal)
    {
        TestPki.JwsChain chain = ShortChain.Value;
        string jws = Jws(chain, literal);
        Assert.True(chain.Verifier(TestPki.SignedAtMs).VerifySignedData(jws).Verified);
        Assert.Equal(VerificationReason.InvalidCertificate, chain.Verifier(After).VerifySignedData(jws).Failure?.Reason);
    }

    /// <summary>
    /// A <c>signedDate</c> that is not a number at all is the genuine "no
    /// signing time" case: the clock stands in. Proved from both sides of
    /// the window, so it cannot pass by being ignored.
    /// </summary>
    [Theory]
    [InlineData("\"1722945600000\"")]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("{\"ms\":1722945600000}")]
    [InlineData("[1722945600000]")]
    public void ANonNumericSigningTimeFallsBackToTheClock(string literal)
    {
        TestPki.JwsChain chain = ShortChain.Value;
        string jws = Jws(chain, literal);
        Assert.True(chain.Verifier(TestPki.SignedAtMs).VerifySignedData(jws).Verified);
        Assert.Equal(VerificationReason.InvalidCertificate, chain.Verifier(After).VerifySignedData(jws).Failure?.Reason);
    }

    /// <summary>
    /// An in-range fractional claim truncates toward zero for the validity
    /// instant, the way <c>new Date(x)</c> and Jackson's <c>asLong()</c> do —
    /// asserted at the boundary, where a round-half-up would cross into the
    /// next millisecond and out of the leaf's window.
    /// </summary>
    [Fact]
    public void AFractionalSigningTimeTruncatesTowardZero()
    {
        DateTimeOffset notAfter = new(2024, 8, 6, 12, 0, 0, TimeSpan.Zero);
        TestPki.JwsChain chain = TestPki.NewJwsChain(Jan2024, notAfter);
        long exact = notAfter.ToUnixTimeMilliseconds();
        IVerifier verifier = chain.Verifier(TestPki.SignedAtMs);

        Assert.True(verifier.VerifySignedData(Jws(chain, exact.ToString(CultureInfo.InvariantCulture) + ".9")).Verified);
        Assert.Equal(
            VerificationReason.InvalidCertificate,
            verifier.VerifySignedData(Jws(chain, (exact + 1).ToString(CultureInfo.InvariantCulture) + ".0")).Failure?.Reason);
    }
}
