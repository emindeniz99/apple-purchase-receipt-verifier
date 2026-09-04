using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The verifyReceipt wire contract: statuses, renderings, and never throwing.</summary>
public class EndpointTests
{
    private static IReadOnlyList<X509Certificate2> Roots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) };

    private static VerifyReceiptEndpoint Endpoint(
        AppleEnvironment environment = AppleEnvironment.Sandbox, IClock? clock = null) =>
        new(Roots(), environment, clock);

    private static Dictionary<string, object?> Body(params (string Key, object? Value)[] entries)
    {
        Dictionary<string, object?> body = new(StringComparer.Ordinal);
        foreach ((string key, object? value) in entries)
        {
            body[key] = value;
        }

        return body;
    }

    private static long Status(IReadOnlyDictionary<string, object?> response) =>
        Convert.ToInt64(response["status"], System.Globalization.CultureInfo.InvariantCulture);

    // --- the 21002 family ----------------------------------------------------

    [Fact]
    public void AMissingReceiptDataPropertyAnswers21002()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        Assert.Equal(21002, Status(endpoint.VerifyReceipt(Body())));
        Assert.Equal(21002, Status(endpoint.VerifyReceipt(null)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("!!!!")]
    [InlineData("not base64 at all")]
    public void AnUnusableReceiptDataPropertyAnswers21002(string value)
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        Assert.Equal(21002, Status(endpoint.VerifyReceipt(Body(("receipt-data", value)))));
    }

    [Fact]
    public void ANonStringReceiptDataPropertyAnswers21002()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        Assert.Equal(21002, Status(endpoint.VerifyReceipt(Body(("receipt-data", 7L)))));
        Assert.Equal(21002, Status(endpoint.VerifyReceipt(Body(("receipt-data", null)))));
        Assert.Equal(
            21002,
            Status(endpoint.VerifyReceipt(Body(("receipt-data", new List<object?>())))));
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("3")]
    [InlineData("\"receipt\"")]
    [InlineData("{")]
    [InlineData("{\"receipt-data\":}")]
    public void ARequestBodyThatIsNotAJsonObjectAnswers21002(string json)
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        Assert.Equal("{\"status\":21002}", endpoint.VerifyReceiptJson(json));
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
        string base64 = Convert.ToBase64String(Fixtures.Bytes("receipt"));
        using VerifyReceiptEndpoint endpoint = Endpoint();

        // The control: the same body spelled correctly is served.
        Assert.StartsWith(
            "{\"status\":0,",
            endpoint.VerifyReceiptJson("{\"receipt-data\":\"" + base64 + "\"}"),
            StringComparison.Ordinal);

        // "receipt\u 02ddata": the four-character window is " 02d", which
        // NumberStyles.HexNumber reads as 0x02D — a hyphen.
        Assert.Equal(
            "{\"status\":21002}",
            endpoint.VerifyReceiptJson("{\"receipt\\u 02ddata\":\"" + base64 + "\"}"));
    }

    [Fact]
    public void AMalformedReceiptAnswers21002AndAnUnauthenticatedOneAnswers21003()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        Assert.Equal(
            21002,
            Status(endpoint.VerifyReceipt(Body(("receipt-data", Convert.ToBase64String(new byte[] { 1, 2, 3 }))))));
        Assert.Equal(
            21003,
            Status(endpoint.VerifyReceipt(
                Body(("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt-foreign")))))));
    }

    // --- compatibility fields ------------------------------------------------

    [Fact]
    public void PasswordAndExcludeOldTransactionsAreAcceptedAndIgnored()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        IReadOnlyDictionary<string, object?> withExtras = endpoint.VerifyReceipt(Body(
            ("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt"))),
            ("password", "a-shared-secret"),
            ("exclude-old-transactions", true)));
        IReadOnlyDictionary<string, object?> without = endpoint.VerifyReceipt(Body(
            ("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt")))));

        Assert.Equal(0, Status(withExtras));
        Assert.Equal(0, Status(without));
    }

    /// <summary>Apple renders every receipt number as a string.</summary>
    [Fact]
    public void NumbersAreRenderedAsStrings()
    {
        IReadOnlyDictionary<string, object?> receipt = SuccessfulReceipt();
        List<object?> inApp = (List<object?>)receipt["in_app"]!;
        IReadOnlyDictionary<string, object?> first = (IReadOnlyDictionary<string, object?>)inApp[0]!;

        Assert.IsType<string>(first["quantity"]);
        Assert.Equal("1", first["quantity"]);
        Assert.IsType<string>(receipt["receipt_creation_date_ms"]);
    }

    [Fact]
    public void TheDateTripleUsesApplesExactRendering()
    {
        IReadOnlyDictionary<string, object?> receipt = SuccessfulReceipt();
        Assert.Equal("2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"]);
        Assert.Equal("1722945600000", receipt["receipt_creation_date_ms"]);
        Assert.Equal("2024-08-06 05:00:00 America/Los_Angeles", receipt["receipt_creation_date_pst"]);
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
        DateTimeOffset now = DateTimeOffset.Parse(utc, System.Globalization.CultureInfo.InvariantCulture);
        using VerifyReceiptEndpoint endpoint = Endpoint(AppleEnvironment.Sandbox, new FixedClock(now));
        IReadOnlyDictionary<string, object?> receipt =
            (IReadOnlyDictionary<string, object?>)endpoint.VerifyReceipt(
                Body(("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt")))))["receipt"]!;

        Assert.Equal(expected, receipt["request_date_pst"]);
    }

    /// <summary>Equal inputs serialize to equal bytes.</summary>
    [Fact]
    public void JsonOutputIsDeterministic()
    {
        FixedClock clock = new(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        string request = "{\"receipt-data\":\"" + Convert.ToBase64String(Fixtures.Bytes("receipt")) + "\"}";

        using VerifyReceiptEndpoint first = Endpoint(AppleEnvironment.Sandbox, clock);
        using VerifyReceiptEndpoint second = Endpoint(AppleEnvironment.Sandbox, clock);
        string a = first.VerifyReceiptJson(request);
        string b = second.VerifyReceiptJson(request);

        Assert.Equal(a, b);
        Assert.StartsWith("{\"status\":0,\"environment\":\"Sandbox\",\"receipt\":{", a, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnsuccessfulAnswerCarriesNothingButTheStatus()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint(AppleEnvironment.Production);
        IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceipt(
            Body(("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt")))));

        Assert.Equal(21007, Status(response));
        Assert.Single(response);
        Assert.False(response.ContainsKey("receipt"));
        Assert.False(response.ContainsKey("environment"));
    }

    /// <summary>
    /// Environment routing fails closed: only <c>Production</c> and
    /// <c>ProductionVPP</c> count as production.
    /// </summary>
    [Theory]
    [InlineData("Production", true)]
    [InlineData("ProductionVPP", true)]
    [InlineData("ProductionSandbox", false)]
    [InlineData("ProductionVPPSandbox", false)]
    [InlineData("Xcode", false)]
    [InlineData("SomethingApplePublishesLater", false)]
    [InlineData(null, false)]
    public void EnvironmentRoutingFailsClosed(string? receiptType, bool production)
    {
        (byte[] receipt, X509Certificate2 root) = MintReceipt(receiptType);

        using VerifyReceiptEndpoint onProduction = new(new[] { root }, AppleEnvironment.Production);
        using VerifyReceiptEndpoint onSandbox = new(new[] { root }, AppleEnvironment.Sandbox);
        Dictionary<string, object?> body = Body(("receipt-data", Convert.ToBase64String(receipt)));

        Assert.Equal(production ? 0 : 21007, Status(onProduction.VerifyReceipt(body)));
        Assert.Equal(production ? 21008 : 0, Status(onSandbox.VerifyReceipt(body)));
    }

    [Fact]
    public void ADisposedEndpointAnswers21009RatherThanThrowing()
    {
        VerifyReceiptEndpoint endpoint = Endpoint();
        endpoint.Dispose();
        Assert.Equal(
            21009,
            Status(endpoint.VerifyReceipt(
                Body(("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt")))))));
    }

    [Fact]
    public void TheEndpointDoesNotCheckTheBundleIdAtAll()
    {
        // Like Apple's endpoint: the caller compares receipt.bundle_id itself.
        IReadOnlyDictionary<string, object?> receipt = SuccessfulReceipt();
        Assert.Equal("com.example.app", receipt["bundle_id"]);
    }

    private static IReadOnlyDictionary<string, object?> SuccessfulReceipt()
    {
        using VerifyReceiptEndpoint endpoint = Endpoint();
        IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceipt(
            Body(("receipt-data", Convert.ToBase64String(Fixtures.Bytes("receipt")))));
        Assert.Equal(0, Status(response));
        return (IReadOnlyDictionary<string, object?>)response["receipt"]!;
    }

    /// <summary>Mints a receipt with a chosen (or missing) receipt-type attribute.</summary>
    private static (byte[] Receipt, X509Certificate2 Root) MintReceipt(string? receiptType)
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 intermediate = TestPki.RsaChild(root, "CN=Fake WWDR", true);
        X509Certificate2 signer = TestPki.RsaChild(
            intermediate, "CN=Fake Receipt Signing", false, TestPki.LeafOid);

        List<(BigInteger, byte[])> attributes = new()
        {
            (2, TestPki.Utf8("com.example.app")),
            (3, TestPki.Utf8("1.2.3")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
        };
        if (receiptType is not null)
        {
            attributes.Insert(0, (0, TestPki.Utf8(receiptType)));
        }

        byte[] receipt = TestPki.SignReceipt(
            TestPki.AttributeSet(attributes), signer, new[] { intermediate, root });
        return (receipt, TestPki.Public(root));
    }
}
