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
/// an inner exception only where the wrapper itself failed.
/// </summary>
public class VerificationResultTests
{
    /// <summary>2025-01-01T00:00:00Z.</summary>
    private const long Now = 1735689600000L;

    private static readonly Lazy<IVerifier> EveryRoot = new(() =>
    {
        List<X509Certificate2> roots = AppleRootCertificates.Bundled().ToList();
        roots.AddRange(TestRoots.RootFixtureIds.Select(TestRoots.FixtureCertificate));
        return TestRoots.Verifier(roots, Now);
    });

    private static IEnumerable<string> ReceiptFixtures() => TestRoots.ReceiptFixtureIds();

    private static IEnumerable<string> JwsFixtures() =>
        Fixtures070.Ids.Where(id => (Fixtures070.Codec(id) == "utf8" && id != "device-guid")
            || id.StartsWith("limit-jws-", StringComparison.Ordinal));

    /// <summary>
    /// The invariant over every receipt and every JWS the repository
    /// registers, verified against every root it registers: whatever the
    /// verdict, the result is well formed. A cause is present exactly when
    /// the wrapper itself failed (INTERNAL_ERROR), never for the module's
    /// verdicts, and every call comes back as a value.
    /// </summary>
    [Fact]
    public void TheResultInvariantHoldsOverTheWholeCorpus()
    {
        int checkedCount = 0;
        foreach (string id in ReceiptFixtures())
        {
            AssertInvariant(EveryRoot.Value.VerifyReceipt(Fixtures070.ForReceipt(id)), id);
            checkedCount++;
        }

        foreach (string id in JwsFixtures())
        {
            string jws = Fixtures070.Codec(id) == "text"
                ? System.Text.Encoding.UTF8.GetString(Fixtures070.Bytes(id))
                : Fixtures070.ForSignedData(id);
            AssertInvariant(EveryRoot.Value.VerifySignedData(jws), id);
            checkedCount++;
        }

        Assert.True(checkedCount > 100, "the fixture registry shrank: " + checkedCount);
    }

    /// <summary>
    /// A caller's own tests can stand in for <see cref="IVerifier"/> with
    /// results built by hand, and those results keep the same invariant as
    /// the library's: exactly one of payload and failure.
    /// </summary>
    [Fact]
    public void CallersCanMockTheVerifierWithHandBuiltResults()
    {
        JsonPayload payload = JsonPayload.Create("{}");
        Failure failure = new(VerificationReason.UntrustedChain, "not ours", null);
        IVerifier stub = new StubVerifier(
            VerificationResult<ReceiptPayload>.Failed(failure),
            VerificationResult<JsonPayload>.Of(payload));

        VerificationResult<ReceiptPayload> receipt = stub.VerifyReceipt("ignored");
        Assert.False(receipt.Verified);
        Assert.Same(failure, receipt.Failure);
        Assert.Equal(VerificationReason.UntrustedChain, receipt.Failure!.Reason);
        Assert.Equal("not ours", receipt.Failure.Message);
        Assert.Null(receipt.Failure.Cause);
        AssertInvariant(receipt, "hand-built failure");

        VerificationResult<JsonPayload> jws = stub.VerifySignedData("ignored");
        Assert.True(jws.Verified);
        Assert.Same(payload, jws.Payload);
        AssertInvariant(jws, "hand-built success");

        InvalidOperationException cause = new("parser said no");
        Assert.Same(cause, new Failure(VerificationReason.UnreadablePayload, "unreadable", cause).Cause);
    }

    /// <summary>
    /// A result with neither payload nor failure would break the invariant
    /// every caller relies on, so the factories refuse <see langword="null"/>.
    /// </summary>
    [Fact]
    public void TheFactoriesRefuseNull()
    {
        Assert.Throws<ArgumentNullException>(() => VerificationResult<JsonPayload>.Of(null!));
        Assert.Throws<ArgumentNullException>(() => VerificationResult<JsonPayload>.Failed((Failure)null!));
        Assert.Throws<ArgumentNullException>(() => new Failure(VerificationReason.Malformed, null!, null));
    }

    private sealed class StubVerifier : IVerifier
    {
        private readonly VerificationResult<ReceiptPayload> _receipt;
        private readonly VerificationResult<JsonPayload> _jws;

        public StubVerifier(VerificationResult<ReceiptPayload> receipt, VerificationResult<JsonPayload> jws)
        {
            _receipt = receipt;
            _jws = jws;
        }

        public VerificationResult<ReceiptPayload> VerifyReceipt(string base64) => _receipt;

        public VerificationResult<JsonPayload> VerifySignedData(string jws) => _jws;

        public string VerifyReceiptEndpoint(AppleEnvironment environment, string requestJson) => "{\"status\":21002}";
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
            (failure.Reason == VerificationReason.InternalError) == (failure.Cause is not null),
            $"{label}: {failure.Reason} and a cause of {failure.Cause?.GetType().Name ?? "none"}: only the wrapper's own INTERNAL_ERROR carries one");
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
