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

    /// <summary>
    /// The verdicts below are read through the endpoint's <c>status</c>, which
    /// is the module's own text passed through untouched: the floor asset
    /// proves it can host the module and speak its ABI, and the shared cases
    /// prove what the module decides.
    /// </summary>
    private static string Endpoint(IVerifier verifier, string base64) =>
        verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + base64 + "\"}");

    [Fact]
    public void ANewVerifierCompilesTheModuleAndAnswersOnTheFloorAsset()
    {
        IVerifier verifier = Verifier.Create(new Config());

        Assert.Contains("\"status\":", verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{}"), StringComparison.Ordinal);
    }

    [Fact]
    public void AGenuineReceiptIsAuthenticatedAgainstAPinnedRoot()
    {
        Config config = new Config(roots: new[] { Certificate("generated-0.7/receipt-root.der") });
        IVerifier verifier = Verifier.Create(config);

        string response = Endpoint(verifier, Convert.ToBase64String(Bytes("generated-0.7/receipt.der")));

        Assert.StartsWith("{\"", response, StringComparison.Ordinal);
        Assert.Contains("\"status\":0", response, StringComparison.Ordinal);
    }

    [Fact]
    public void AGenuineAppleReceiptIsAuthenticatedAgainstTheModulesBuiltInRoots()
    {
        IVerifier verifier = Verifier.Create(new Config());

        Assert.Contains("\"status\":0", Endpoint(verifier, Base64Text("generated/receipt-b64/01-genuine.txt")), StringComparison.Ordinal);
    }

    [Fact]
    public void AForeignChainIsNotAuthenticated()
    {
        IVerifier verifier = Verifier.Create(new Config());

        Assert.Equal(
            "{\"status\":21003}",
            Endpoint(verifier, Convert.ToBase64String(Bytes("generated-0.7/receipt.der"))));
    }

    [Fact]
    public void AJwsAnswersAValueOnTheFloorAsset()
    {
        Config config = new Config(roots: new[] { Certificate("generated/jws-root.der") });
        IVerifier verifier = Verifier.Create(config);

        VerificationResult<JsonPayload> result = verifier.VerifySignedData(Text("generated/transaction.jws"));

        Assert.True(result.Verified ? result.Failure is null : result.Failure is not null);
    }

    [Fact]
    public void TheEndpointAnswersABody()
    {
        Config config = new Config(
            roots: new[] { Certificate("generated-0.7/receipt-root.der") },
            clock: () => new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds());
        IVerifier verifier = Verifier.Create(config);

        string response = Endpoint(verifier, Convert.ToBase64String(Bytes("generated-0.7/receipt.der")));

        Assert.Contains("\"status\":0", response, StringComparison.Ordinal);
        Assert.Contains("\"request_date_ms\":\"1735689600000\"", response, StringComparison.Ordinal);
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
        IVerifier verifier = Verifier.Create(new Config());
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

#pragma warning disable SYSLIB0057
    private static X509Certificate2 Certificate(string relative) => new(Bytes(relative));
#pragma warning restore SYSLIB0057

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
