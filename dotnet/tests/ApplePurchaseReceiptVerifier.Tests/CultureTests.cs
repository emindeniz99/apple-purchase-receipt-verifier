using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The single most likely .NET-only bug in this port: a hostile culture
/// reaching a parse or a rendering of what the module answers. Turkish has a dotless <c>ı</c> that breaks
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

    /// <summary>
    /// Reading the module's answer: ids, dates and byte fields come out the
    /// same whatever the culture, on this thread and on another.
    /// </summary>
    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void ReadingAReceiptAnswerIsIdenticalUnderAnyCulture(string culture)
    {
        ReceiptPayload expected = SyntheticAnswers.Receipt();
        string answer = SyntheticAnswers.Verified(expected);
        string invariant = expected.ToJson();

        Use(culture);
        ReceiptPayload receipt = Read(answer);

        Assert.Equal(1722945600000L, receipt.ReceiptCreationDateMs);
        Assert.Equal(1234567890123456789L, receipt.AppItemId);
        Assert.Contains(receipt.InApp, p => p.PurchaseDateMs == 1705320000000L);
        Assert.Equal(invariant, receipt.ToJson());
        Assert.Equal(invariant, Task.Run(() => Read(answer).ToJson()).GetAwaiter().GetResult());
    }

    /// <summary>The endpoint's answer is the module's text, untouched, under any culture.</summary>
    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void TheEndpointAnswerIsPassedThroughIdenticallyUnderAnyCulture(string culture)
    {
        string invariant = EndpointAnswer();

        Use(culture);
        Assert.Equal(invariant, EndpointAnswer());
        Assert.Equal(invariant, Task.Run(EndpointAnswer).GetAwaiter().GetResult());
    }

    /// <summary>A signed JWS payload is the module's string, untouched, under any culture.</summary>
    [Theory]
    [MemberData(nameof(HostileCultures))]
    public void AJwsPayloadIsPassedThroughIdenticallyUnderAnyCulture(string culture)
    {
        string payload = "{\"signedDate\":1722945600000.5,\"price\":1.5,\"n\":\"\u0131\"}";
        AprvRuntime runtime = new(new StubModule { SignedDataAnswer = SyntheticAnswers.VerifiedJws(payload) }.ToWasm(), null);
        VerifierImpl verifier = new(Config.Defaults(), runtime);

        Use(culture);
        Assert.Equal(payload, verifier.VerifySignedData("x").Payload?.Json);
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
    }

    private static ReceiptPayload Read(string answer)
    {
        VerificationResult<ReceiptPayload> result = ModuleAnswers.ReadReceipt(answer);
        Assert.True(result.Verified, result.Failure?.ToString());
        return result.Payload;
    }

    private static string EndpointAnswer() =>
        TestRoots.FixtureVerifier("receipt-root", 1735689600000L).VerifyReceiptEndpoint(
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
