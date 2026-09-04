using System;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Jws;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What the payload's stated signing time is allowed to do. It drives two
/// separate rules — the certificate-validity instant (step 9) and the
/// staleness rule (step 11) — so a claim the reader cannot represent must be
/// a rejection, never a silent "the payload states no signing time".
/// </summary>
public class SigningTimeTests
{
    // 2024-08-06T12:00:00Z, the instant the shared fixtures are signed at.
    private static readonly DateTimeOffset SignedAt = new(2024, 8, 6, 12, 0, 0, TimeSpan.Zero);

    private sealed record Pki(X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf);

    private static Pki Mint(DateTimeOffset? leafNotBefore = null, DateTimeOffset? leafNotAfter = null)
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(
            intermediate, "CN=Signing", false, TestPki.LeafOid, leafNotBefore, leafNotAfter);
        return new Pki(root, intermediate, leaf);
    }

    private static string Jws(Pki pki, string signedDateLiteral) =>
        TestPki.SignJws(
            pki.Leaf,
            new[] { pki.Leaf, pki.Intermediate, pki.Root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":"
            + signedDateLiteral + "}");

    private static JwsVerifier Verifier(Pki pki, TimeSpan? maxAge = null, IClock? clock = null) =>
        new(new[] { TestPki.Public(pki.Root) }, "com.example.app",
            new[] { AppleEnvironment.Sandbox }, null, maxAge, clock);

    /// <summary>
    /// A non-integral <c>signedDate</c> is still a stated signing time. Java
    /// (<c>canConvertToLong</c>), Node (<c>typeof === 'number'</c>) and Python
    /// (<c>isinstance(int, float)</c>) all take it, so the staleness rule must
    /// run. Reading it as "absent" would skip the rule instead of failing it.
    /// </summary>
    [Fact]
    public void AFractionalSignedDateStillDrivesTheStalenessRule()
    {
        Pki pki = Mint();
        string jws = Jws(pki, "1722945600000.5");

        using JwsVerifier verifier = Verifier(
            pki, TimeSpan.FromSeconds(60), new FixedClock(SignedAt.AddSeconds(61)));
        Assert.Equal(
            VerificationReason.StalePayload,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    /// <summary>
    /// The other half of the same defect: a fractional claim must also move the
    /// certificate-validity instant. This leaf expired in 2025, so judging it
    /// at the system clock rejects a payload the reference ports accept.
    /// </summary>
    [Fact]
    public void AFractionalSignedDateDrivesTheCertificateValidityInstant()
    {
        Pki pki = Mint(
            new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        string jws = Jws(pki, "1722945600000.5");

        using JwsVerifier verifier = Verifier(pki);
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
    }

    /// <summary>
    /// A signing time no instant can represent is a failed check, not a skipped
    /// one: CONTRACT.md §2.1 step 9 owns the effective date, and its reason is
    /// <see cref="VerificationReason.InvalidChain"/> — which is also where Java
    /// (<c>new Date(long)</c> past the leaf's notAfter) and Node (an Invalid
    /// Date whose NaN comparisons fail <c>validAt</c>) land.
    /// </summary>
    [Theory]
    [InlineData("253402300800000")]        // one millisecond past DateTimeOffset.MaxValue
    [InlineData("9223372036854775807")]    // long.MaxValue
    [InlineData("-62135596800001")]        // one millisecond before DateTimeOffset.MinValue
    [InlineData("1e300")]                  // a double no long can hold
    [InlineData("-1e300")]
    public void AnUnrepresentableSignedDateIsAnInvalidChain(string literal)
    {
        Pki pki = Mint();
        string jws = Jws(pki, literal);

        using JwsVerifier verifier = Verifier(pki);
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    /// <summary>
    /// A number literal that overflows to infinity is rejected one step
    /// earlier, by the reader itself (CONTRACT.md §2.1 step 8): the JSON reader
    /// is deliberately bounded and produces no non-finite value, so such a
    /// payload never reaches the effective-date rule. Node's JSON.parse yields
    /// <c>Infinity</c> and reports INVALID_CHAIN instead — a pre-existing,
    /// documented difference in the number grammar, and the narrower of the
    /// two accept sets. Asserted so it stays a decision rather than an
    /// accident.
    /// </summary>
    [Fact]
    public void ASigningTimeThatOverflowsToInfinityIsRejectedByTheReader()
    {
        Pki pki = Mint();
        string jws = Jws(pki, "1e999");

        using JwsVerifier verifier = Verifier(pki);
        Assert.Equal(
            VerificationReason.InvalidJwsFormat,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    /// <summary>
    /// The same claim on the <c>AppTransaction</c> spelling, which reads
    /// <c>receiptCreationDate</c> through the identical conversion.
    /// </summary>
    [Fact]
    public void AnUnrepresentableReceiptCreationDateIsAnInvalidChain()
    {
        Pki pki = Mint();
        string jws = TestPki.SignJws(
            pki.Leaf,
            new[] { pki.Leaf, pki.Intermediate, pki.Root },
            "{\"bundleId\":\"com.example.app\",\"receiptType\":\"Sandbox\","
            + "\"receiptCreationDate\":253402300800000}");

        using JwsVerifier verifier = Verifier(pki);
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(() => verifier.VerifyAppTransaction(jws)).Reason);
    }

    /// <summary>
    /// A fractional <c>receiptCreationDate</c> is a stated signing time too, so
    /// the fallback to <c>receiptCreationDate</c> must see it.
    /// </summary>
    [Fact]
    public void AFractionalReceiptCreationDateDrivesTheStalenessRule()
    {
        Pki pki = Mint();
        string jws = TestPki.SignJws(
            pki.Leaf,
            new[] { pki.Leaf, pki.Intermediate, pki.Root },
            "{\"bundleId\":\"com.example.app\",\"receiptType\":\"Sandbox\","
            + "\"receiptCreationDate\":1722945600000.5}");

        using JwsVerifier verifier = Verifier(
            pki, TimeSpan.FromSeconds(60), new FixedClock(SignedAt.AddSeconds(61)));
        Assert.Equal(
            VerificationReason.StalePayload,
            Assert.Throws<VerificationException>(() => verifier.VerifyAppTransaction(jws)).Reason);
    }

    /// <summary>
    /// The genuine "no signing time" case is unchanged: a payload carrying
    /// neither claim, and one whose claim is not a number at all, falls back to
    /// the system clock and has no age to be stale by.
    /// </summary>
    [Theory]
    [InlineData("{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\"}")]
    [InlineData("{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":\"2024\"}")]
    [InlineData("{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":null}")]
    public void APayloadWithNoNumericSigningTimeUsesTheSystemClockAndIsNeverStale(string payload)
    {
        Pki pki = Mint();
        string jws = TestPki.SignJws(pki.Leaf, new[] { pki.Leaf, pki.Intermediate, pki.Root }, payload);

        using JwsVerifier verifier = Verifier(
            pki, TimeSpan.FromSeconds(1), new FixedClock(SignedAt.AddYears(50)));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
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
        DateTimeOffset notAfter = SignedAt;
        Pki pki = Mint(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), notAfter);
        long exact = notAfter.ToUnixTimeMilliseconds();

        using JwsVerifier verifier = Verifier(pki);
        Assert.Equal(
            "com.example.app",
            verifier.VerifyTransaction(
                Jws(pki, exact.ToString(CultureInfo.InvariantCulture) + ".9")).BundleId);
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyTransaction(
                    Jws(pki, (exact + 1).ToString(CultureInfo.InvariantCulture) + ".0"))).Reason);
    }
}
