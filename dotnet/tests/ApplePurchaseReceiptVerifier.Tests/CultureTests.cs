using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The single most likely .NET-only bug in this port: a hostile culture
/// reaching a parse or a rendering. Turkish has a dotless <c>ı</c> that breaks
/// case-insensitive ASCII comparison, Thai defaults to the Buddhist calendar
/// (year 2567 for 2024), German writes a comma for the decimal separator, and
/// Arabic (Saudi Arabia) defaults to the Hijri calendar.
/// </summary>
/// <remarks>
/// The culture is set for the whole process — the current thread and the
/// default for every new thread — not only for the test's own thread, so a
/// rendering done on the thread pool sees it too. That is process-wide
/// state, hence the non-parallel collection.
/// </remarks>
[Collection(ProcessWideCollection.Name)]
public class CultureTests : IDisposable
{
    private readonly CultureInfo _culture = CultureInfo.CurrentCulture;
    private readonly CultureInfo _uiCulture = CultureInfo.CurrentUICulture;
    private readonly CultureInfo? _defaultCulture = CultureInfo.DefaultThreadCurrentCulture;
    private readonly CultureInfo? _defaultUiCulture = CultureInfo.DefaultThreadCurrentUICulture;

    public static TheoryData<string> HostileCultures => new() { "tr-TR", "th-TH", "de-DE", "ar-SA" };

    public void Dispose()
    {
        CultureInfo.CurrentCulture = _culture;
        CultureInfo.CurrentUICulture = _uiCulture;
        CultureInfo.DefaultThreadCurrentCulture = _defaultCulture;
        CultureInfo.DefaultThreadCurrentUICulture = _defaultUiCulture;
        GC.SuppressFinalize(this);
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void ReceiptDatesAndToJsonAreIdenticalUnderAnyCulture(string culture)
    {
        string invariant = VerifyReceipt().ToJson();

        Use(culture);
        ReceiptPayload receipt = VerifyReceipt();

        Assert.Equal(1722945600000L, receipt.ReceiptCreationDateMs);
        Assert.Contains(receipt.InApp, p => p.PurchaseDateMs == 1705320000000L);
        Assert.Equal(invariant, receipt.ToJson());
        Assert.Equal(invariant, Task.Run(() => VerifyReceipt().ToJson()).GetAwaiter().GetResult());
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void TheEndpointRendersIdenticallyUnderAnyCulture(string culture)
    {
        Use(culture);
        OrderedMap receipt = (OrderedMap)Json.ParseObject(EndpointAnswer())["receipt"]!;

        // A Buddhist or Hijri calendar would render another year, and a
        // comma-decimal culture would corrupt the millisecond strings.
        Assert.Equal("2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"]);
        Assert.Equal("2024-08-06 05:00:00 America/Los_Angeles", receipt["receipt_creation_date_pst"]);
        Assert.Equal("1722945600000", receipt["receipt_creation_date_ms"]);
        Assert.Equal("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"]);
        Assert.Equal("1735689600000", receipt["request_date_ms"]);
        OrderedMap first = (OrderedMap)((System.Collections.Generic.List<object?>)receipt["in_app"]!)[0]!;
        Assert.Equal("1", first["quantity"]);

        Assert.Equal(EndpointAnswer(), Task.Run(EndpointAnswer).GetAwaiter().GetResult());
    }

    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void AJwsSignedDateIsReadIdenticallyUnderAnyCulture(string culture)
    {
        Use(culture);

        // The decimal spelling is the one a comma-decimal culture would
        // misread; misread, the signedDate would not parse, the clock (far
        // past the chain) would stand in and the JWS would fail.
        Assert.True(TestPki.FixtureVerifier("jws-root", 4070908800000L)
            .VerifySignedData(Fixtures070.ForSignedData("transaction")).Verified);
        Assert.True(TestPki.FixtureVerifier("hostile-jws-root", 4070908800000L)
            .VerifySignedData(Fixtures070.ForSignedData("transaction-signed-date-decimal")).Verified);
    }

    /// <summary>
    /// The Turkish-I trap specifically: a <c>ToLower</c> or a culture-aware
    /// comparison anywhere near the vocabulary would turn
    /// <c>"INVALID_SIGNATURE"</c> into something <c>TryParse</c> no longer
    /// recognises, and <c>"Production"</c> into something the environment
    /// mapping does not.
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

        Assert.Equal(AppleEnvironment.Production, AppleEnvironments.FromReceiptType("ProductionVPP"));
        Assert.Equal(AppleEnvironment.Sandbox, AppleEnvironments.FromJwsEnvironment("Sandbox"));
        Assert.Equal("Production", AppleEnvironments.ToValue(AppleEnvironment.Production));
    }

    private static ReceiptPayload VerifyReceipt()
    {
        VerificationResult<ReceiptPayload> result =
            TestPki.FixtureVerifier("receipt-root").VerifyReceipt(Fixtures070.ForReceipt("receipt"));
        Assert.True(result.Verified, result.Failure?.ToString());
        return result.Payload;
    }

    private static string EndpointAnswer() =>
        TestPki.FixtureVerifier("receipt-root", 1735689600000L).VerifyReceiptEndpoint(
            AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt") + "\"}");

    private static void Use(string culture)
    {
        CultureInfo info = new(culture);
        CultureInfo.CurrentCulture = info;
        CultureInfo.CurrentUICulture = info;
        CultureInfo.DefaultThreadCurrentCulture = info;
        CultureInfo.DefaultThreadCurrentUICulture = info;
    }
}
