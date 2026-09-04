using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The single most likely .NET-only bug in this port: a hostile thread culture
/// reaching a parse or a rendering. Turkish has a dotless <c>ı</c> that breaks
/// case-insensitive ASCII comparison, Thai defaults to the Buddhist calendar
/// (year 2567 for 2024), and German writes a comma for the decimal separator.
/// </summary>
public class CultureTests : IDisposable
{
    private readonly CultureInfo _culture = CultureInfo.CurrentCulture;
    private readonly CultureInfo _uiCulture = CultureInfo.CurrentUICulture;

    public static TheoryData<string> HostileCultures => new() { "tr-TR", "th-TH", "de-DE", "ar-SA" };

    public void Dispose()
    {
        Thread.CurrentThread.CurrentCulture = _culture;
        Thread.CurrentThread.CurrentUICulture = _uiCulture;
        GC.SuppressFinalize(this);
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void ReceiptDatesParseIdenticallyUnderAnyThreadCulture(string culture)
    {
        Use(culture);
        using ReceiptVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) },
            "com.example.app");
        AppReceipt receipt = verifier.Verify(Fixtures.Bytes("receipt"));

        Assert.Equal(
            new DateTimeOffset(2024, 8, 6, 12, 0, 0, TimeSpan.Zero), receipt.CreationDate);
        Assert.Equal(
            new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero),
            receipt.InAppPurchases[0].PurchaseDate);
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void TheEndpointRendersIdenticallyUnderAnyThreadCulture(string culture)
    {
        Use(culture);
        using VerifyReceiptEndpoint endpoint = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) },
            AppleEnvironment.Sandbox,
            new FixedClock(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)));

        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["receipt-data"] = Convert.ToBase64String(Fixtures.Bytes("receipt")),
        };
        IReadOnlyDictionary<string, object?> receipt =
            (IReadOnlyDictionary<string, object?>)endpoint.VerifyReceipt(body)["receipt"]!;

        // A Buddhist-calendar culture would render 2567, and a comma-decimal
        // culture would corrupt the millisecond strings.
        Assert.Equal("2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"]);
        Assert.Equal("1722945600000", receipt["receipt_creation_date_ms"]);
        Assert.Equal("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"]);
        List<object?> inApp = (List<object?>)receipt["in_app"]!;
        Assert.Equal("1", ((IReadOnlyDictionary<string, object?>)inApp[0]!)["quantity"]);
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void JwsClaimsAndReasonCodesAreCultureIndependent(string culture)
    {
        Use(culture);
        using JwsVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox });

        TransactionPayload payload = verifier.VerifyTransaction(Fixtures.Text("transaction"));
        Assert.Equal(1722945600000L, payload.SignedDate);
        Assert.Equal("Sandbox", payload.Environment);

        Assert.Equal(
            "INVALID_CERTIFICATE_PURPOSE",
            VerificationReasonCodes.ToCode(VerificationReason.InvalidCertificatePurpose));
        Assert.True(VerificationReasonCodes.TryParse("INVALID_CHAIN", out _));
        Assert.True(AppleEnvironments.TryParse("Production", out _));
    }

    /// <summary>
    /// The Turkish-I trap specifically: an <c>ToLower</c> anywhere near the
    /// vocabulary would turn <c>"INVALID_CHAIN"</c> into something
    /// <c>TryParse</c> no longer recognises.
    /// </summary>
    [Fact]
    public void TheTurkishDotlessIDoesNotReachTheVocabulary()
    {
        Use("tr-TR");
        foreach (VerificationReason reason in Enum.GetValues<VerificationReason>())
        {
            string code = VerificationReasonCodes.ToCode(reason);
            Assert.True(VerificationReasonCodes.TryParse(code, out VerificationReason parsed));
            Assert.Equal(reason, parsed);
        }
    }

    private static void Use(string culture)
    {
        CultureInfo info = new(culture);
        Thread.CurrentThread.CurrentCulture = info;
        Thread.CurrentThread.CurrentUICulture = info;
    }
}
