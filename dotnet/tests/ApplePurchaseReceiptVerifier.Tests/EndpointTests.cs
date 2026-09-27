using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The verifyReceipt wire contract: statuses, renderings, and never throwing.</summary>
public class EndpointTests
{
    /// <summary>2025-01-01T00:00:00Z.</summary>
    private const long Now = 1735689600000L;

    private static IVerifier Endpoint(string root = "receipt-root", long now = Now) =>
        TestPki.FixtureVerifier(root, now);

    private static string Body(string receiptData)
    {
        OrderedMap body = new();
        body.Set("receipt-data", receiptData);
        return Json.Write(body);
    }

    private static long Status(string answer) =>
        Convert.ToInt64(Json.ParseObject(answer)["status"], CultureInfo.InvariantCulture);

    // --- the 21002 family ----------------------------------------------------

    /// <summary>A null body is input, like an empty one: 21002, not a throw.</summary>
    [Fact]
    public void ANullRequestBodyAnswers21002()
    {
        Assert.Equal("{\"status\":21002}", Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Sandbox, null!));
        Assert.Equal("{\"status\":21002}", Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Production, null!));
    }

    [Theory]
    [InlineData("{\"receipt-data\":null}")]
    [InlineData("{\"receipt-data\":[]}")]
    [InlineData("{\"receipt-data\":{}}")]
    [InlineData("{\"receipt-data\":true}")]
    [InlineData("{\"Receipt-Data\":\"AAAA\"}")]
    public void AReceiptDataPropertyThatIsNotAStringAnswers21002(string body)
    {
        Assert.Equal("{\"status\":21002}", Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\"receipt\"")]
    [InlineData("{")]
    [InlineData("{\"receipt-data\":}")]
    [InlineData("{\"receipt-data\":\"AAAA\"")]
    [InlineData("not json")]
    public void ARequestBodyThatIsNotAJsonObjectAnswers21002(string json)
    {
        Assert.Equal("{\"status\":21002}", Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Sandbox, json));
    }

    /// <summary>
    /// The endpoint's request body is fully untrusted, so the reader's grammar
    /// is part of the wire contract. A key whose <c>\u</c> escape is not four
    /// hex digits must not decode to <c>receipt-data</c>: JSON.parse,
    /// json.loads and Jackson all reject the body, so every other port answers
    /// 21002 and this one must too.
    /// </summary>
    [Fact]
    public void ARequestBodyWithAMalformedUnicodeEscapeAnswers21002()
    {
        string base64 = Fixtures070.ForReceipt("receipt");
        IVerifier endpoint = Endpoint();

        // The control: the same body spelled correctly is served.
        Assert.StartsWith(
            "{\"status\":0,",
            endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + base64 + "\"}"),
            StringComparison.Ordinal);

        // "receipt\u 02ddata": the four-character window is " 02d", which
        // NumberStyles.HexNumber reads as 0x02D — a hyphen.
        Assert.Equal(
            "{\"status\":21002}",
            endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{\"receipt\\u 02ddata\":\"" + base64 + "\"}"));
    }

    /// <summary>
    /// Every unsuccessful answer carries the status and nothing else: no
    /// receipt, no environment, whatever the reason.
    /// </summary>
    [Fact]
    public void AnUnsuccessfulAnswerCarriesNothingButTheStatus()
    {
        IVerifier endpoint = Endpoint();
        Assert.Equal("{\"status\":21007}", endpoint.VerifyReceiptEndpoint(AppleEnvironment.Production, Body(Fixtures070.ForReceipt("receipt"))));
        Assert.Equal("{\"status\":21002}", endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, Body("AAAA")));
        Assert.Equal("{\"status\":21003}", endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, Body(Fixtures070.ForReceipt("receipt-foreign"))));
        Assert.Equal(
            "{\"status\":21009}",
            Endpoint("verification-order-root").VerifyReceiptEndpoint(AppleEnvironment.Sandbox, Body(Fixtures070.ForReceipt("receipt-unreadable-entry"))));
    }

    // --- renderings ----------------------------------------------------------

    /// <summary>Apple's own key order, which a reader diffing the two answers reads in.</summary>
    [Fact]
    public void TheAppLevelKeysAreEmittedInApplesKeyOrder()
    {
        string body = Endpoint("receipt-ids-root").VerifyReceiptEndpoint(
            AppleEnvironment.Production, Body(Fixtures070.ForReceipt("receipt-ids")));
        string[] keys =
        {
            "\"receipt_type\"", "\"adam_id\"", "\"app_item_id\"", "\"bundle_id\"",
            "\"application_version\"", "\"download_id\"", "\"version_external_identifier\"",
            "\"original_application_version\"", "\"receipt_creation_date\"", "\"request_date\"", "\"in_app\"",
        };

        Assert.StartsWith("{\"status\":0,\"environment\":\"Production\",\"receipt\":{", body, StringComparison.Ordinal);
        for (int i = 1; i < keys.Length; i++)
        {
            int previous = body.IndexOf(keys[i - 1], StringComparison.Ordinal);
            int next = body.IndexOf(keys[i], StringComparison.Ordinal);
            Assert.True(previous >= 0 && previous < next, $"{keys[i - 1]} must precede {keys[i]} in {body}");
        }
    }

    /// <summary>
    /// The <c>_pst</c> field is a real US Pacific rendering, so it moves across
    /// a daylight-saving boundary. A UTC-minus-eight constant would pass a
    /// January test and fail a July one.
    /// </summary>
    [Theory]
    [InlineData("2024-07-15T18:30:00Z", "2024-07-15 11:30:00 America/Los_Angeles")]
    [InlineData("2024-01-15T18:30:00Z", "2024-01-15 10:30:00 America/Los_Angeles")]
    [InlineData("2024-03-10T09:59:00Z", "2024-03-10 01:59:00 America/Los_Angeles")]
    [InlineData("2024-03-10T10:00:00Z", "2024-03-10 03:00:00 America/Los_Angeles")]
    public void RequestDatePstFollowsDaylightSaving(string utc, string expected)
    {
        long now = DateTimeOffset.Parse(utc, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds();
        OrderedMap receipt = (OrderedMap)Json.ParseObject(
            Endpoint(now: now).VerifyReceiptEndpoint(AppleEnvironment.Sandbox, Body(Fixtures070.ForReceipt("receipt"))))["receipt"]!;

        Assert.Equal(expected, receipt["request_date_pst"]);
    }

    /// <summary>
    /// A date the receipt grammar accepts renders, whatever its year: the
    /// grammar takes years 0000 to 9999, and year 0000 is before the first
    /// instant <see cref="DateTimeOffset"/> can hold. The text is what the
    /// Java reference prints (<c>yyyy</c> is year-of-era there, so year 0000
    /// prints as 0001, and Pacific time that far back is local mean time).
    /// </summary>
    [Fact]
    public void EveryDateTheGrammarAcceptsRendersAtTheEndpoint()
    {
        IVerifier verifier = Endpoint("owner-receipt-root");
        string receiptData = Fixtures070.ForReceipt("owner-receipt-date-grammar");
        ReceiptPayload payload = verifier.VerifyReceipt(receiptData).Payload!;
        AppleEnvironment environment =
            AppleEnvironments.FromReceiptType(payload.ReceiptType) ?? AppleEnvironment.Sandbox;

        string answer = verifier.VerifyReceiptEndpoint(environment, Body(receiptData));
        Assert.Equal(0, Status(answer));

        OrderedMap yearZero = InApp(answer, "70000000000201");
        Assert.Equal("-62167219200000", yearZero["purchase_date_ms"]);
        Assert.Equal("0001-01-01 00:00:00 Etc/GMT", yearZero["purchase_date"]);

        // tzdb's local mean time, -07:52:58, as Java prints it, on every
        // platform: Windows' own zone data has no local mean time and would
        // give -08:00 (16:00:00) if the system zone were asked this far back.
        Assert.Equal("0002-12-31 16:07:02 America/Los_Angeles", yearZero["purchase_date_pst"]);

        OrderedMap lastSecond = InApp(answer, "70000000000202");
        Assert.Equal("253402300799000", lastSecond["purchase_date_ms"]);
        Assert.Equal("9999-12-31 23:59:59 Etc/GMT", lastSecond["purchase_date"]);
        Assert.Equal("9999-12-31 15:59:59 America/Los_Angeles", lastSecond["purchase_date_pst"]);
    }

    /// <summary>Equal inputs serialize to equal bytes.</summary>
    [Fact]
    public void JsonOutputIsDeterministic()
    {
        string request = Body(Fixtures070.ForReceipt("receipt"));
        string a = Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Sandbox, request);
        string b = Endpoint().VerifyReceiptEndpoint(AppleEnvironment.Sandbox, request);

        Assert.Equal(a, b);
        Assert.StartsWith("{\"status\":0,\"environment\":\"Sandbox\",\"receipt\":{", a, StringComparison.Ordinal);
    }

    /// <summary>
    /// Environment routing fails closed: only <c>Production</c> and
    /// <c>ProductionVPP</c> count as production; a receipt_type Apple does not
    /// document, or one in another letter case, is non-production.
    /// </summary>
    [Theory]
    [InlineData("Xcode")]
    [InlineData("SomethingApplePublishesLater")]
    [InlineData("production")]
    [InlineData("")]
    public void EnvironmentRoutingFailsClosed(string receiptType)
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        byte[] payload = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (0, TestPki.Utf8(receiptType)),
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
        });
        string body = Body(chain.SignBase64(payload));
        IVerifier verifier = chain.Verifier();

        Assert.Equal("{\"status\":21007}", verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, body));
        Assert.Equal(0, Status(verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body)));
    }

    // --- the endpoint and verifyReceipt agree ---------------------------------

    /// <summary>
    /// The endpoint runs <c>verifyReceipt</c> and renders the result, so for
    /// every receipt the repository registers — the base64 contract strings
    /// verbatim included — its status is the one the design's table assigns
    /// to what <c>verifyReceipt</c> answers, in both environments. The corpus
    /// reaches every status the endpoint can return.
    /// </summary>
    [Fact]
    public void TheEndpointAnswersWhatVerifyReceiptDecidedForEveryReceiptFixture()
    {
        List<string> ids = TestPki.ReceiptFixtureIds().ToList();
        List<X509Certificate2> roots = AppleRootCertificates.Bundled().ToList();
        roots.AddRange(TestPki.RootFixtureIds.Select(TestPki.FixtureCertificate));
        IVerifier verifier = TestPki.Verifier(roots, Now);
        Assert.True(ids.Count > 100, "only " + ids.Count + " receipts");

        HashSet<long> statuses = new();
        foreach (string id in ids)
        {
            string data = Fixtures070.ForReceipt(id);
            VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(data);
            string body = Body(data);
            foreach (AppleEnvironment environment in new[] { AppleEnvironment.Production, AppleEnvironment.Sandbox })
            {
                long expected = Encoding.UTF8.GetByteCount(body) > EndpointCore.MaxRequestBytes
                    ? AppleStatus.MalformedReceiptData
                    : ExpectedStatus(result, environment);
                string answer = verifier.VerifyReceiptEndpoint(environment, body);
                Assert.True(
                    expected == Status(answer),
                    $"{id} on {environment}: verifyReceipt said {result.Failure?.ToString() ?? "verified"}, "
                    + $"so {expected} was due, the endpoint answered {answer.Substring(0, Math.Min(80, answer.Length))}");
                statuses.Add(expected);
            }
        }

        Assert.Equal(new HashSet<long> { 0, 21002, 21003, 21007, 21008, 21009 }, statuses);
    }

    /// <summary>The design's status table, restated here so the endpoint is checked against it, not against itself.</summary>
    private static long ExpectedStatus(VerificationResult<ReceiptPayload> result, AppleEnvironment environment)
    {
        if (result.Verified)
        {
            bool production = AppleEnvironments.FromReceiptType(result.Payload.ReceiptType) == AppleEnvironment.Production;
            return (environment, production) switch
            {
                (AppleEnvironment.Production, false) => 21007,
                (AppleEnvironment.Sandbox, true) => 21008,
                _ => 0,
            };
        }

        return result.Failure.Reason switch
        {
            VerificationReason.Malformed or VerificationReason.TooLarge => 21002,
            VerificationReason.InvalidSignature
                or VerificationReason.UntrustedChain
                or VerificationReason.InvalidCertificate
                or VerificationReason.InvalidCertificatePurpose => 21003,
            _ => 21009,
        };
    }

    private static OrderedMap InApp(string answer, string transactionId)
    {
        OrderedMap receipt = (OrderedMap)Json.ParseObject(answer)["receipt"]!;
        return ((List<object?>)receipt["in_app"]!)
            .Cast<OrderedMap>()
            .Single(p => (string?)p["transaction_id"] == transactionId);
    }
}
