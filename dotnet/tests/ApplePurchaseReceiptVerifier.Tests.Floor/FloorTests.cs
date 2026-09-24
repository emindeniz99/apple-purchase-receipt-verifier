using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests.Floor;

/// <summary>
/// The netstandard2.0 asset, exercised end to end. The floor exists so a .NET
/// Framework, Mono or Unity consumer can use this package from one asset; a
/// floor nothing runs is a claim, not a fact.
/// </summary>
public class FloorTests
{
    private static readonly string Root = FindFixtures();

    [Fact]
    public void TheAssemblyUnderTestIsTheNetstandardAsset()
    {
        string? framework = typeof(JwsVerifier).Assembly
            .GetCustomAttribute<System.Runtime.Versioning.TargetFrameworkAttribute>()
            ?.FrameworkName;
        Assert.Equal(".NETStandard,Version=v2.0", framework);
    }

    [Fact]
    public void AReceiptVerifiesAgainstAPinnedRoot()
    {
        using ReceiptVerifier verifier = new(
            new[] { Certificate("generated/receipt-root.der") }, "com.example.app");
        AppReceipt receipt = verifier.Verify(Bytes("generated/receipt.der"));

        Assert.Equal("com.example.app", receipt.BundleId);
        Assert.Equal("1.2.3", receipt.AppVersion);
        Assert.Equal(new DateTimeOffset(2024, 8, 6, 12, 0, 0, TimeSpan.Zero), receipt.CreationDate);
        Assert.Equal(2, receipt.InAppPurchases.Count);
    }

    [Fact]
    public void AGenuineAppleReceiptVerifiesAgainstTheBundledRoots()
    {
        using ReceiptVerifier verifier = new(
            AppleRootCertificates.ReceiptRoots(), "dev.bonzer.weeka.app");
        Assert.Equal(
            "ProductionSandbox",
            verifier.Verify(Base64("public-receipts/receipt-sandbox-g5.b64")).ReceiptType);
    }

    [Fact]
    public void AJwsTransactionVerifies()
    {
        using JwsVerifier verifier = new(
            new[] { Certificate("generated/jws-root.der") },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox });
        TransactionPayload payload = verifier.VerifyTransaction(Text("generated/transaction.jws"));

        Assert.Equal("com.example.app.pro", payload.ProductId);
        Assert.Equal(1722945600000L, payload.SignedDate);
    }

    [Fact]
    public void AForeignChainIsRejected()
    {
        using JwsVerifier verifier = new(
            AppleRootCertificates.JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyTransaction(Text("generated/transaction.jws"))).Reason);
    }

    [Fact]
    public void TheEndpointAnswersABody()
    {
        using VerifyReceiptEndpoint endpoint = new(
            new[] { Certificate("generated/receipt-root.der") },
            AppleEnvironment.Sandbox,
            new FixedClock(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)));

        string request = "{\"receipt-data\":\""
            + Convert.ToBase64String(Bytes("generated/receipt.der")) + "\"}";
        string response = endpoint.VerifyReceiptJson(request);

        Assert.StartsWith("{\"status\":0,\"environment\":\"Sandbox\"", response, StringComparison.Ordinal);
        Assert.Contains("\"request_date_ms\":\"1735689600000\"", response, StringComparison.Ordinal);
        Assert.Contains(
            "\"receipt_creation_date_pst\":\"2024-08-06 05:00:00 America/Los_Angeles\"",
            response,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The receipt cap on this asset's decoder: a genuinely signed receipt
    /// whose canonical base64 is exactly the cap verifies, and one more
    /// character is refused by the cap, as its message shows.
    /// </summary>
    [Fact]
    public void TheReceiptCapHoldsOnTheFloorAsset()
    {
        string atCap = Encoding.ASCII.GetString(Bytes("limits/receipt-b64-at-cap.txt"));
        Assert.Equal(ReceiptVerifier.MaxReceiptBytes, atCap.Length);

        using ReceiptVerifier verifier = new(
            new[] { Certificate("generated/receipt-b64-cap-root.der") }, "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(atCap).BundleId);

        VerificationException error = Assert.Throws<VerificationException>(() => verifier.Verify(atCap + "\n"));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, error.Reason);
        Assert.Equal(
            "INVALID_RECEIPT_FORMAT: receipt exceeds the maximum accepted size of 3145728 bytes",
            error.Message);
    }

    [Fact]
    public void TheReasonVocabularyIsIntactOnTheFloorAsset()
    {
        // Eleven verifier reasons plus the two only a VerifyReceiptResult carries.
        Assert.Equal(13, Enum.GetValues(typeof(VerificationReason)).Length);
        Assert.Equal("DEVICE_HASH_MISMATCH", VerificationReasonCodes.ToCode(VerificationReason.DeviceHashMismatch));
        Assert.Equal("INTERNAL_ERROR", VerificationReasonCodes.ToCode(VerificationReason.InternalError));
    }

    [Fact]
    public void HostileInputIsStillContained()
    {
        using ReceiptVerifier verifier = new(
            new[] { Certificate("generated/receipt-root.der") }, "com.example.app");
        foreach (string input in new[] { "MAsGCSqGSIb3", "!!!!", "", "AAAA" })
        {
            Assert.IsType<VerificationException>(Record.Exception(() => verifier.Verify(input)));
        }
    }

    private static byte[] Bytes(string relative) => File.ReadAllBytes(Path.Combine(Root, relative));

    private static string Text(string relative) => File.ReadAllText(Path.Combine(Root, relative)).Trim();

    private static byte[] Base64(string relative)
    {
        StringBuilder compact = new();
        foreach (char c in Text(relative))
        {
            if (!char.IsWhiteSpace(c))
            {
                compact.Append(c);
            }
        }

        return Convert.FromBase64String(compact.ToString());
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
