using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What a caller relies on from a <see cref="VerificationResult{T}"/>: exactly
/// one of payload and failure, <see cref="VerificationResult{T}.Verified"/>
/// saying which, and a <see cref="Failure"/> that is safe to log and carries
/// an inner exception only where it explains Apple-signed content the
/// library could not read, or the library's own failure.
/// </summary>
public class VerificationResultTests
{
    /// <summary>2025-01-01T00:00:00Z.</summary>
    private const long Now = 1735689600000L;

    private static readonly Lazy<IVerifier> EveryRoot = new(() =>
    {
        List<X509Certificate2> roots = AppleRootCertificates.Bundled().ToList();
        roots.AddRange(TestPki.RootFixtureIds.Select(TestPki.FixtureCertificate));
        return TestPki.Verifier(roots, Now);
    });

    private static IEnumerable<string> ReceiptFixtures() => TestPki.ReceiptFixtureIds();

    private static IEnumerable<string> JwsFixtures() =>
        Fixtures070.Ids.Where(id => (Fixtures070.Codec(id) == "utf8" && id != "device-guid")
            || id.StartsWith("limit-jws-", StringComparison.Ordinal));

    /// <summary>
    /// The invariant over every receipt and every JWS the repository
    /// registers, verified against every root it registers: whatever the
    /// verdict, the result is well formed, and together the corpus reaches
    /// both a pass and a failure of every kind an input can cause.
    /// </summary>
    [Fact]
    public void TheResultInvariantHoldsOverTheWholeCorpus()
    {
        HashSet<VerificationReason?> seen = new();
        foreach (string id in ReceiptFixtures())
        {
            VerificationResult<ReceiptPayload> result = EveryRoot.Value.VerifyReceipt(Fixtures070.ForReceipt(id));
            AssertInvariant(result, id);
            seen.Add(result.Failure?.Reason);
        }

        foreach (string id in JwsFixtures())
        {
            string jws = Fixtures070.Codec(id) == "text"
                ? System.Text.Encoding.UTF8.GetString(Fixtures070.Bytes(id))
                : Fixtures070.ForSignedData(id);
            VerificationResult<JsonPayload> result = EveryRoot.Value.VerifySignedData(jws);
            AssertInvariant(result, id);
            seen.Add(result.Failure?.Reason);
        }

        Assert.Contains(null, seen);
        foreach (VerificationReason reason in Enum.GetValues<VerificationReason>())
        {
            if (reason != VerificationReason.InternalError)
            {
                Assert.Contains(reason, seen);
            }
        }
    }

    /// <summary>
    /// A trusted signer signed content the library cannot read: not the
    /// client's fault, and the parser's own verdict is kept as the cause so an
    /// operator can see why.
    /// </summary>
    [Fact]
    public void UnreadableSignedContentKeepsTheParsersVerdictAsItsCause()
    {
        IVerifier verifier = TestPki.FixtureVerifier("verification-order-root", Now);
        Failure failure = verifier.VerifyReceipt(Fixtures070.ForReceipt("receipt-unreadable-entry")).Failure!;

        Assert.Equal(VerificationReason.UnreadablePayload, failure.Reason);
        Assert.NotNull(failure.Cause);
    }

    /// <summary>
    /// Input nobody has vouched for gets no inner exception on its failure:
    /// a library's message can quote what it failed on, and the cause is only
    /// for the two reasons that are about Apple-signed content or the library
    /// itself (the Java reference's <c>VerificationException.toFailure</c>).
    /// </summary>
    [Theory]
    [InlineData("MA==")]
    [InlineData("MAsGCSqGSIb3")]
    [InlineData("not base64")]
    public void AFailureCausedByUnvouchedInputCarriesNoInnerException(string receipt)
    {
        Failure failure = EveryRoot.Value.VerifyReceipt(receipt).Failure!;
        Assert.Equal(VerificationReason.Malformed, failure.Reason);
        Assert.Null(failure.Cause);

        Failure header = EveryRoot.Value.VerifySignedData("eyJhbGci.e30.AAAA").Failure!;
        Assert.Equal(VerificationReason.Malformed, header.Reason);
        Assert.Null(header.Cause);
    }

    private static void AssertInvariant<T>(VerificationResult<T> result, string label)
        where T : class
    {
        Assert.True((result.Payload is null) != (result.Failure is null), label + ": exactly one of Payload and Failure");
        Assert.Equal(result.Payload is not null, result.Verified);
        if (result.Failure is not Failure failure)
        {
            return;
        }

        Assert.True(
            failure.Cause is null
                || failure.Reason is VerificationReason.UnreadablePayload or VerificationReason.InternalError,
            $"{label}: {failure.Reason} carries a cause ({failure.Cause?.GetType().Name})");
        Assert.NotEqual(VerificationReason.InternalError, failure.Reason);
        Assert.False(string.IsNullOrEmpty(failure.Message), label + ": empty message");
        Assert.True(failure.Message.Length <= 512, label + ": message longer than a log line should be");
        foreach (char c in failure.Message)
        {
            Assert.False(
                char.IsControl(c) || c is '\u2028' or '\u2029' or '\u202E',
                $"{label}: message carries U+{(int)c:X4}");
        }

        Assert.Equal(VerificationReasonCodes.ToCode(failure.Reason) + ": " + failure.Message, failure.ToString());
    }
}
