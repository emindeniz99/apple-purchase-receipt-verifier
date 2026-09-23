using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What a caller relies on from a <see cref="VerifyReceiptResult"/>: it says
/// whether the receipt verified independently of which environment answered,
/// it can answer for the other environment without a second verification, it
/// carries exactly one request date, and it renders exactly what the endpoint
/// answered before the result type existed.
/// </summary>
public class VerifyReceiptResultTests
{
    private static readonly DateTimeOffset ClockNow = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Explicit = new(2025, 6, 15, 12, 34, 56, 789, TimeSpan.Zero);
    private static readonly AppleEnvironment[] Environments = { AppleEnvironment.Production, AppleEnvironment.Sandbox };

    private static VerifyReceiptEndpoint Endpoint(
        AppleEnvironment environment, string root = "receipt-root", IClock? clock = null) =>
        new(new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes(root)) }, environment, clock ?? new CountingClock());

    private static string B64(string fixture) => Convert.ToBase64String(Fixtures.Bytes(fixture));

    private static string Body(string receiptData)
    {
        OrderedMap body = new();
        body.Set("receipt-data", receiptData);
        return Json.Write(body);
    }

    private static long Status(IReadOnlyDictionary<string, object?> response) =>
        Convert.ToInt64(response["status"], CultureInfo.InvariantCulture);

    private static void AssertInvariant(VerifyReceiptResult result, string label)
    {
        Assert.True(
            (result.Receipt is null) != (result.FailureReason is null),
            label + ": exactly one of Receipt and FailureReason must be set");
        Assert.Equal(result.Receipt is not null, result.IsVerified);
        Assert.True(
            (result.FailureReason == VerificationReason.InternalError) == (result.FailureCause is not null),
            label + ": FailureCause is set exactly for InternalError");
        Assert.Equal(result.Status, Status(result.ToResponse()));
        Assert.Equal(TimeSpan.Zero, result.RequestDate.Offset);
    }

    [Fact]
    public void ExactlyOneOfReceiptAndFailureReasonForEveryStatus()
    {
        Dictionary<string, VerifyReceiptResult> results = new(StringComparer.Ordinal)
        {
            ["0 sandbox"] = Endpoint(AppleEnvironment.Sandbox).VerifyReceiptData(B64("receipt")),
            ["0 production"] = Endpoint(AppleEnvironment.Production).VerifyReceiptData(B64("receipt-type-production")),
            ["21007"] = Endpoint(AppleEnvironment.Production).VerifyReceiptData(B64("receipt")),
            ["21008"] = Endpoint(AppleEnvironment.Sandbox).VerifyReceiptData(B64("receipt-type-production")),
            ["21002"] = Endpoint(AppleEnvironment.Sandbox).VerifyReceiptData("AQIDBA=="),
            ["21003"] = Endpoint(AppleEnvironment.Sandbox).VerifyReceiptData(B64("receipt-foreign")),
            ["21009"] = Endpoint(AppleEnvironment.Sandbox).VerifyReceiptResult(new ThrowingBody()),
        };

        foreach (KeyValuePair<string, VerifyReceiptResult> entry in results)
        {
            AssertInvariant(entry.Value, entry.Key);
            Assert.Equal(int.Parse(entry.Key.Split(' ')[0], CultureInfo.InvariantCulture), entry.Value.Status);
        }

        // 21007 and 21008 are routing answers, not failures: the receipt
        // verified, so IsVerified is not the same check as Status == 0.
        foreach (string label in new[] { "0 sandbox", "0 production", "21007", "21008" })
        {
            Assert.True(results[label].IsVerified, label);
            Assert.NotNull(results[label].Receipt);
        }

        foreach (string label in new[] { "21002", "21003", "21009" })
        {
            Assert.False(results[label].IsVerified, label);
        }
    }

    /// <summary>
    /// A production receipt is 0 on Production and 21008 on Sandbox; a sandbox
    /// one (and one with no receipt_type, which fails closed as sandbox) is
    /// 21007 on Production and 0 on Sandbox; a failure keeps its status. The
    /// same whichever environment verified it, and each render is byte for
    /// byte what an endpoint of that environment answers on its own.
    /// </summary>
    [Theory]
    [InlineData("receipt-type-production", "receipt-root", 0, 21008)]
    [InlineData("receipt-type-vpp", "receipt-root", 0, 21008)]
    [InlineData("receipt", "receipt-root", 21007, 0)]
    [InlineData("receipt-type-vpp-sandbox", "receipt-root", 21007, 0)]
    [InlineData("receipt-no-type", "receipt-root", 21007, 0)]
    [InlineData("receipt-foreign", "receipt-root", 21003, 21003)]
    [InlineData("receipt-tampered-payload", "gaps-receipt-root", 21003, 21003)]
    public void ReRendersForEitherEnvironmentFromTheReceiptsOwnType(
        string fixture, string root, int onProduction, int onSandbox)
    {
        foreach (AppleEnvironment own in Environments)
        {
            using VerifyReceiptEndpoint endpoint = Endpoint(own, root);
            VerifyReceiptResult result = endpoint.VerifyReceiptData(B64(fixture), Explicit);
            Assert.Equal(onProduction, Status(result.ToResponse(AppleEnvironment.Production)));
            Assert.Equal(onSandbox, Status(result.ToResponse(AppleEnvironment.Sandbox)));
            foreach (AppleEnvironment target in Environments)
            {
                using VerifyReceiptEndpoint direct = Endpoint(target, root);
                Assert.Equal(direct.VerifyReceiptData(B64(fixture), Explicit).ToJson(), result.ToJson(target));
            }
        }
    }

    [Theory]
    [InlineData("receipt")]
    [InlineData("receipt-type-vpp-sandbox")]
    [InlineData("receipt-no-type")]
    public void ASandboxReceiptNeverRendersAProductionZero(string fixture)
    {
        foreach (AppleEnvironment own in Environments)
        {
            using VerifyReceiptEndpoint endpoint = Endpoint(own);
            VerifyReceiptResult result = endpoint.VerifyReceiptData(B64(fixture));
            Assert.True(result.IsVerified);
            Assert.Equal("{\"status\":21007}", result.ToJson(AppleEnvironment.Production));
            Assert.Single(result.ToResponse(AppleEnvironment.Production));
        }
    }

    [Theory]
    [InlineData(AppleEnvironment.Xcode)]
    [InlineData(AppleEnvironment.LocalTesting)]
    [InlineData((AppleEnvironment)99)]
    public void RenderingForAnEnvironmentApplesEndpointDoesNotHaveIsRefused(AppleEnvironment environment)
    {
        using VerifyReceiptEndpoint endpoint = Endpoint(AppleEnvironment.Sandbox);
        VerifyReceiptResult verified = endpoint.VerifyReceiptData(B64("receipt"));
        VerifyReceiptResult failed = endpoint.VerifyReceiptData("AQIDBA==");
        foreach (VerifyReceiptResult result in new[] { verified, failed })
        {
            Assert.Throws<ArgumentException>(() => result.ToResponse(environment));
            Assert.Throws<ArgumentException>(() => result.ToJson(environment));
        }
    }

    [Fact]
    public void AnExplicitNowSetsRequestDateAndTheClockIsReadOnce()
    {
        CountingClock clock = new();
        using VerifyReceiptEndpoint sandbox = Endpoint(AppleEnvironment.Sandbox, clock: clock);
        string receiptData = B64("receipt");
        string body = Body(receiptData);
        Dictionary<string, object?> map = new(StringComparer.Ordinal) { ["receipt-data"] = receiptData };

        VerifyReceiptResult explicitNow = sandbox.VerifyReceiptResult(map, Explicit);
        Assert.Equal(0, clock.Reads);
        Assert.Equal(Explicit, explicitNow.RequestDate);
        IReadOnlyDictionary<string, object?> receipt =
            (IReadOnlyDictionary<string, object?>)explicitNow.ToResponse()["receipt"]!;
        Assert.Equal("2025-06-15 12:34:56 Etc/GMT", receipt["request_date"]);
        Assert.Equal("1749990896789", receipt["request_date_ms"]);
        Assert.Equal("2025-06-15 05:34:56 America/Los_Angeles", receipt["request_date_pst"]);

        // Any offset names the same instant, and every entry point agrees.
        DateTimeOffset eastern = Explicit.ToOffset(TimeSpan.FromHours(-4));
        Assert.Equal(explicitNow.ToJson(), sandbox.VerifyReceiptData(receiptData, eastern).ToJson());
        Assert.Equal(explicitNow.ToJson(), sandbox.VerifyReceiptResult(body, Explicit).ToJson());
        Assert.Equal(0, clock.Reads);

        // Without one, each call reads the clock exactly once, and rendering
        // (in either environment, any number of times) never reads it again,
        // so one result cannot carry two request dates.
        Func<VerifyReceiptResult>[] clocked =
        {
            () => sandbox.VerifyReceiptResult(map),
            () => sandbox.VerifyReceiptResult(body),
            () => sandbox.VerifyReceiptData(receiptData),
        };
        foreach (Func<VerifyReceiptResult> call in clocked)
        {
            int before = clock.Reads;
            VerifyReceiptResult result = call();
            result.ToJson();
            result.ToJson(AppleEnvironment.Production);
            result.ToResponse();
            Assert.Equal(before + 1, clock.Reads);
            Assert.Equal(ClockNow, result.RequestDate);
        }

        int beforeJson = clock.Reads;
        sandbox.VerifyReceiptJson(body);
        Assert.Equal(beforeJson + 1, clock.Reads);
    }

    /// <summary>
    /// receipt-expired-fresh was created after its signing certificate expired;
    /// 2020-06-01 is inside that certificate's window. A <c>now</c> that
    /// reached the chain check would rescue it.
    /// </summary>
    [Fact]
    public void AnExplicitNowDoesNotMoveCertificateValidity()
    {
        using VerifyReceiptEndpoint sandbox = Endpoint(AppleEnvironment.Sandbox, "receipt-expired-root");
        DateTimeOffset insideWindow = new(2020, 6, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.True(sandbox.VerifyReceiptData(B64("receipt-expired-historical")).IsVerified);

        VerifyReceiptResult result = sandbox.VerifyReceiptData(B64("receipt-expired-fresh"), insideWindow);
        Assert.Equal(21003, result.Status);
        Assert.Equal(VerificationReason.InvalidChain, result.FailureReason);
    }

    /// <summary>
    /// Every receipt the repository registers, including the base64 contract
    /// strings verbatim (whitespace, base64url, bad padding), through both the
    /// bare entry point and a JSON body carrying it.
    /// </summary>
    [Fact]
    public void TheBareReceiptAnswersAsTheJsonBodyOverEveryReceiptFixture()
    {
        List<string> ids = Fixtures.Ids.Where(id => id.Contains("receipt", StringComparison.Ordinal)).ToList();
        List<X509Certificate2> roots = AppleRootCertificates.ReceiptRoots().ToList();
        roots.AddRange(ids
            .Where(id => id.EndsWith("root", StringComparison.Ordinal))
            .Select(id => X509CertificateLoader.LoadCertificate(Fixtures.Bytes(id))));
        List<string> receiptData = ids
            .Where(id => !id.EndsWith("root", StringComparison.Ordinal)
                && !id.StartsWith("public-receipts-", StringComparison.Ordinal))
            .Select(id => Fixtures.Codec(id) == "text" ? Encoding.UTF8.GetString(Fixtures.Bytes(id)) : B64(id))
            .ToList();
        Assert.True(receiptData.Count > 40, "only " + receiptData.Count + " receipts");

        HashSet<int> statuses = new();
        foreach (AppleEnvironment environment in Environments)
        {
            using VerifyReceiptEndpoint pinned = new(roots, environment, new FixedClock(ClockNow));
            foreach (string data in receiptData)
            {
                string label = data.Substring(0, Math.Min(40, data.Length));
                VerifyReceiptResult bare = pinned.VerifyReceiptData(data);
                string body = Body(data);
                if (Encoding.UTF8.GetByteCount(body) > VerifyReceiptEndpoint.MaxRequestBytes)
                {
                    // A receipt string over the receipt cap: as a JSON body it
                    // is over the request cap too and never parsed.
                    Assert.Equal(VerificationReason.RequestTooLarge, pinned.VerifyReceiptResult(body).FailureReason);
                    Assert.Equal("{\"status\":21002}", pinned.VerifyReceiptJson(body));
                }
                else
                {
                    Assert.Equal(pinned.VerifyReceiptJson(body), bare.ToJson());
                }

                Assert.NotEqual(VerificationReason.InternalError, bare.FailureReason);
                AssertInvariant(bare, label);
                statuses.Add(bare.Status);
            }
        }

        // The corpus reaches every status except the internal error.
        Assert.Equal(new HashSet<int> { 0, 21002, 21003, 21007, 21008 }, statuses);
    }

    [Fact]
    public void EachFailureNamesItsReason()
    {
        using VerifyReceiptEndpoint sandbox = Endpoint(AppleEnvironment.Sandbox);
        Dictionary<string, VerifyReceiptResult> malformed = new(StringComparer.Ordinal)
        {
            ["body not JSON"] = sandbox.VerifyReceiptResult("not json"),
            ["body a JSON array"] = sandbox.VerifyReceiptResult("[{\"receipt-data\":\"AQIDBA==\"}]"),
            ["body JSON null"] = sandbox.VerifyReceiptResult("null"),
            ["body nested too deep"] = sandbox.VerifyReceiptResult(new string('[', 100_000)),
            ["null JSON body"] = sandbox.VerifyReceiptResult((string?)null),
            ["null body"] = sandbox.VerifyReceiptResult((IReadOnlyDictionary<string, object?>?)null),
            ["receipt-data missing"] = sandbox.VerifyReceiptResult(new Dictionary<string, object?>()),
            ["receipt-data empty"] = sandbox.VerifyReceiptResult("{\"receipt-data\":\"\"}"),
            ["receipt-data a number"] = sandbox.VerifyReceiptResult("{\"receipt-data\":5}"),
            ["receipt-data a list"] = sandbox.VerifyReceiptResult("{\"receipt-data\":[\"AQIDBA==\"]}"),
            ["bare receipt null"] = sandbox.VerifyReceiptData(null),
            ["bare receipt empty"] = sandbox.VerifyReceiptData(string.Empty),
        };
        foreach (KeyValuePair<string, VerifyReceiptResult> entry in malformed)
        {
            Assert.True(VerificationReason.MalformedRequest == entry.Value.FailureReason, entry.Key);
            Assert.Equal(21002, entry.Value.Status);
            AssertInvariant(entry.Value, entry.Key);
        }

        Assert.Equal("{\"status\":21002}", sandbox.VerifyReceiptJson(new string('[', 100_000)));

        // Over Apple's request limit: 21002 like the malformed bodies, but its
        // own reason, so an HTTP layer can answer 413 where Apple does.
        VerifyReceiptResult tooLarge = sandbox.VerifyReceiptResult(
            new string(' ', VerifyReceiptEndpoint.MaxRequestBytes + 1));
        Assert.Equal(VerificationReason.RequestTooLarge, tooLarge.FailureReason);
        Assert.Equal(21002, tooLarge.Status);
        AssertInvariant(tooLarge, "body too large");

        Dictionary<string, VerifyReceiptResult> invalid = new(StringComparer.Ordinal)
        {
            ["not base64"] = sandbox.VerifyReceiptResult("{\"receipt-data\":\"not base64!\"}"),
            ["whitespace only"] = sandbox.VerifyReceiptData("  \n"),
            ["not a receipt"] = sandbox.VerifyReceiptData("AQIDBA=="),
        };
        foreach (KeyValuePair<string, VerifyReceiptResult> entry in invalid)
        {
            Assert.True(VerificationReason.InvalidReceiptFormat == entry.Value.FailureReason, entry.Key);
            Assert.Equal(21002, entry.Value.Status);
            AssertInvariant(entry.Value, entry.Key);
        }

        VerifyReceiptResult foreign = sandbox.VerifyReceiptData(B64("receipt-foreign"));
        Assert.Equal(VerificationReason.InvalidChain, foreign.FailureReason);
        Assert.Equal(21003, foreign.Status);

        using VerifyReceiptEndpoint gaps = Endpoint(AppleEnvironment.Sandbox, "gaps-receipt-root");
        VerifyReceiptResult tampered = gaps.VerifyReceiptData(B64("receipt-tampered-payload"));
        Assert.Equal(VerificationReason.InvalidSignature, tampered.FailureReason);
        Assert.Equal(21003, tampered.Status);
    }

    /// <summary>
    /// The endpoint promises never to throw on a request, so a failure outside
    /// the verification verdicts (a caller's dictionary, a caller's clock, a
    /// disposed endpoint) comes back as 21009 with the exception kept for
    /// logging.
    /// </summary>
    [Fact]
    public void AnUnexpectedExceptionIsAnInternalErrorNotAThrow()
    {
        foreach (AppleEnvironment environment in Environments)
        {
            using VerifyReceiptEndpoint endpoint = Endpoint(environment);
            VerifyReceiptResult result = endpoint.VerifyReceiptResult(new ThrowingBody());
            Assert.Equal(VerificationReason.InternalError, result.FailureReason);
            Assert.Same(ThrowingBody.Error, result.FailureCause);
            Assert.Null(result.Receipt);
            foreach (string render in Environments.Select(result.ToJson).Append(result.ToJson()))
            {
                Assert.Equal("{\"status\":21009}", render);
            }
        }

        using VerifyReceiptEndpoint broken = Endpoint(AppleEnvironment.Sandbox, clock: new ThrowingClock());
        VerifyReceiptResult clockFailure = broken.VerifyReceiptData(B64("receipt"));
        Assert.Equal(VerificationReason.InternalError, clockFailure.FailureReason);
        Assert.IsType<InvalidOperationException>(clockFailure.FailureCause);
        Assert.Equal("{\"status\":21009}", broken.VerifyReceiptJson(Body(B64("receipt"))));

        VerifyReceiptEndpoint disposed = Endpoint(AppleEnvironment.Sandbox);
        disposed.Dispose();
        VerifyReceiptResult afterDispose = disposed.VerifyReceiptData(B64("receipt"));
        Assert.Equal(VerificationReason.InternalError, afterDispose.FailureReason);
        Assert.IsType<ObjectDisposedException>(afterDispose.FailureCause);
        AssertInvariant(afterDispose, "disposed");
    }

    [Fact]
    public void ToJsonIsWhatVerifyReceiptJsonAnswers()
    {
        using VerifyReceiptEndpoint sandbox = Endpoint(AppleEnvironment.Sandbox);
        string body = Body(B64("receipt"));
        Assert.Equal(sandbox.VerifyReceiptJson(body), sandbox.VerifyReceiptResult(body).ToJson());
        Assert.Equal(
            sandbox.VerifyReceiptJson(body), sandbox.VerifyReceiptResult(body).ToJson(AppleEnvironment.Sandbox));

        // Each render is a new map, so no caller holding one can change a later render.
        VerifyReceiptResult result = sandbox.VerifyReceiptResult(body);
        Assert.NotSame(result.ToResponse(), result.ToResponse());
        Assert.Equal(Json.Write(result.ToResponse()), result.ToJson());
    }

    /// <summary>A caller must not be able to fabricate a status 0.</summary>
    [Fact]
    public void OnlyTheEndpointCreatesAResultAndItCannotBeChanged()
    {
        Type type = typeof(VerifyReceiptResult);
        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors());
        Assert.DoesNotContain(
            type.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static),
            m => m.ReturnType == type);
        Assert.All(type.GetProperties(), p => Assert.False(p.CanWrite, p.Name));
    }

    /// <summary>
    /// The breaking change: <c>VerifyReceipt(body)</c> is now
    /// <c>VerifyReceiptResult(body).ToResponse()</c>.
    /// </summary>
    [Fact]
    public void TheDictionaryInDictionaryOutMethodIsGone()
    {
        Assert.Null(typeof(VerifyReceiptEndpoint).GetMethod("VerifyReceipt"));
    }

    private sealed class CountingClock : IClock
    {
        internal int Reads { get; private set; }

        public DateTimeOffset UtcNow
        {
            get
            {
                Reads++;
                return ClockNow;
            }
        }
    }

    private sealed class ThrowingClock : IClock
    {
        public DateTimeOffset UtcNow => throw new InvalidOperationException("broken clock");
    }

    /// <summary>A request body whose lookup throws: an unexpected failure reached through the public API.</summary>
    private sealed class ThrowingBody : IReadOnlyDictionary<string, object?>
    {
        internal static readonly InvalidOperationException Error = new("broken request body");

        public int Count => 1;

        public IEnumerable<string> Keys => throw Error;

        public IEnumerable<object?> Values => throw Error;

        public object? this[string key] => throw Error;

        public bool ContainsKey(string key) => throw Error;

        public bool TryGetValue(string key, out object? value) => throw Error;

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => throw Error;

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
