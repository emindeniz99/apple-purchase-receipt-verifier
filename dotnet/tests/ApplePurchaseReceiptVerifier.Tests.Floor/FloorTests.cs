using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests.Floor;

/// <summary>
/// The netstandard2.0 asset, exercised end to end against real fixtures from
/// <c>fixtures/cases.json</c>. The floor exists so a .NET Framework, Mono
/// or Unity consumer can use this package from one asset; a floor nothing
/// runs is a claim, not a fact.
/// </summary>
public class FloorTests
{
    private static readonly string Root = FindFixtures();

    [Fact]
    public void TheAssemblyUnderTestIsTheNetstandardAsset()
    {
        string? framework = typeof(IVerifier).Assembly
            .GetCustomAttribute<System.Runtime.Versioning.TargetFrameworkAttribute>()
            ?.FrameworkName;
        Assert.Equal(".NETStandard,Version=v2.0", framework);
    }

    [Fact]
    public void AGenuineReceiptVerifiesAgainstAPinnedRoot()
    {
        Config config = Config.CreateBuilder().Roots(new[] { Certificate("generated-0.7/receipt-root.der") }).Build();
        IVerifier verifier = Verifier.Create(config);

        VerificationResult<ReceiptPayload> result =
            verifier.VerifyReceipt(Convert.ToBase64String(Bytes("generated-0.7/receipt.der")));

        Assert.True(result.Verified);
        Assert.Equal("com.example.app", result.Payload!.BundleId);
    }

    [Fact]
    public void AGenuineAppleReceiptVerifiesAgainstTheBundledRoots()
    {
        IVerifier verifier = Verifier.Create(Config.Defaults());
        VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(Base64Text("generated/receipt-b64/01-genuine.txt"));

        Assert.True(result.Verified);
        Assert.Equal("ProductionSandbox", result.Payload!.ReceiptType);
        Assert.Equal(2, result.Payload!.InApp.Count);
    }

    [Fact]
    public void AJwsTransactionVerifies()
    {
        Config config = Config.CreateBuilder().Roots(new[] { Certificate("generated/jws-root.der") }).Build();
        IVerifier verifier = Verifier.Create(config);

        VerificationResult<JsonPayload> result = verifier.VerifySignedData(Text("generated/transaction.jws"));

        Assert.True(result.Verified);
        Assert.Contains("\"productId\":\"com.example.app.pro\"", result.Payload!.Json, StringComparison.Ordinal);
    }

    [Fact]
    public void AForeignChainIsRejected()
    {
        IVerifier verifier = Verifier.Create(Config.Defaults());
        VerificationResult<JsonPayload> result = verifier.VerifySignedData(Text("generated/transaction.jws"));

        Assert.False(result.Verified);
        Assert.Equal(VerificationReason.UntrustedChain, result.Failure!.Reason);
    }

    [Fact]
    public void TheEndpointAnswersABody()
    {
        Config config = Config.CreateBuilder()
            .Roots(new[] { Certificate("generated-0.7/receipt-root.der") })
            .Clock(() => new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds())
            .Build();
        IVerifier verifier = Verifier.Create(config);

        string request = "{\"receipt-data\":\""
            + Convert.ToBase64String(Bytes("generated-0.7/receipt.der")) + "\"}";
        string response = verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, request);

        Assert.StartsWith("{\"status\":0,\"environment\":\"Sandbox\"", response, StringComparison.Ordinal);
        Assert.Contains("\"request_date_ms\":\"1735689600000\"", response, StringComparison.Ordinal);
    }

    [Fact]
    public void TheReceiptCapHoldsOnTheFloorAsset()
    {
        // codec "text": the file bytes verbatim, untrimmed.
        string atCap = Encoding.ASCII.GetString(Bytes("generated-0.7/receipt-b64-at-cap.txt"));

        Config config = Config.CreateBuilder().Roots(new[] { Certificate("generated-0.7/receipt-b64-cap-root.der") }).Build();
        IVerifier verifier = Verifier.Create(config);

        VerificationResult<ReceiptPayload> ok = verifier.VerifyReceipt(atCap);
        Assert.True(ok.Verified);
        Assert.Equal("com.example.app", ok.Payload!.BundleId);

        VerificationResult<ReceiptPayload> tooBig = verifier.VerifyReceipt(atCap + "\n");
        Assert.False(tooBig.Verified);
        Assert.Equal(VerificationReason.TooLarge, tooBig.Failure!.Reason);
    }

    [Fact]
    public void TheReasonVocabularyIsIntactOnTheFloorAsset()
    {
        Assert.Equal(8, Enum.GetValues(typeof(VerificationReason)).Length);
        Assert.Equal("UNTRUSTED_CHAIN", VerificationReasonCodes.ToCode(VerificationReason.UntrustedChain));
        Assert.Equal("INTERNAL_ERROR", VerificationReasonCodes.ToCode(VerificationReason.InternalError));
    }

    [Fact]
    public void HostileInputIsStillContained()
    {
        IVerifier verifier = Verifier.Create(Config.Defaults());
        foreach (string input in new[] { "MAsGCSqGSIb3", "!!!!", "", "AAAA" })
        {
            VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(input);
            Assert.False(result.Verified);
        }
    }

    private static byte[] Bytes(string relative) => File.ReadAllBytes(Path.Combine(Root, relative));

    private static string Text(string relative) => File.ReadAllText(Path.Combine(Root, relative)).Trim();

    private static string Base64Text(string relative)
    {
        StringBuilder compact = new();
        foreach (char c in Text(relative))
        {
            if (!char.IsWhiteSpace(c))
            {
                compact.Append(c);
            }
        }

        return compact.ToString();
    }

    private static X509Certificate2 Certificate(string relative) =>
        X509CertificateLoader.LoadCertificate(Bytes(relative));

    private static string FindFixtures()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "fixtures");
            if (File.Exists(Path.Combine(candidate, "cases.json")))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate fixtures/");
    }
}
