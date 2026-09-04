using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The bundled anchors: which ones, whose bytes, and how they are handed out.</summary>
public class RootsTests
{
    private static readonly string[] Expected =
    {
        "AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer",
    };

    [Fact]
    public void BothSetsCarryAllThreePublishedAppleRoots()
    {
        foreach (IReadOnlyList<X509Certificate2> roots in
            new[] { AppleRootCertificates.JwsRoots(), AppleRootCertificates.ReceiptRoots() })
        {
            Assert.Equal(3, roots.Count);
            string[] subjects = roots.Select(r => r.Subject).ToArray();
            Assert.Contains(subjects, s => s.Contains("Apple Root CA - G2", StringComparison.Ordinal));
            Assert.Contains(subjects, s => s.Contains("Apple Root CA - G3", StringComparison.Ordinal));
            Assert.Contains(subjects, s => s.StartsWith("CN=Apple Root CA,", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// The compiled-in bytes are the repo's <c>certs/</c> bytes. This is what
    /// makes the generated source file safe to trust rather than merely
    /// convenient.
    /// </summary>
    [Fact]
    public void TheCompiledInBytesAreTheRepositoryCertificateBytes()
    {
        string certs = CertsDirectory();
        List<string> onDisk = new();
        foreach (string file in Expected)
        {
            onDisk.Add(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(certs, file)))));
        }

        List<string> compiled = AppleRootCertificates.ReceiptRoots()
            .Select(r => Convert.ToHexString(SHA256.HashData(r.RawData)))
            .ToList();

        Assert.Equal(onDisk.OrderBy(h => h, StringComparer.Ordinal), compiled.OrderBy(h => h, StringComparer.Ordinal));
    }

    /// <summary>
    /// Each call returns independent instances, so a caller disposing one set
    /// cannot break the next call.
    /// </summary>
    [Fact]
    public void EachCallReturnsIndependentInstances()
    {
        IReadOnlyList<X509Certificate2> first = AppleRootCertificates.ReceiptRoots();
        foreach (X509Certificate2 root in first)
        {
            root.Dispose();
        }

        IReadOnlyList<X509Certificate2> second = AppleRootCertificates.ReceiptRoots();
        Assert.Equal(3, second.Count);
        Assert.NotEmpty(second[0].Subject);
        Assert.False(ReferenceEquals(first[0], second[0]));
    }

    /// <summary>
    /// A verifier keeps its own copies, so a caller may dispose the anchors it
    /// passed in.
    /// </summary>
    [Fact]
    public void AVerifierSurvivesTheCallerDisposingTheAnchorsItPassedIn()
    {
        X509Certificate2 root = X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root"));
        using Receipt.ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        root.Dispose();

        Assert.Equal("com.example.app", verifier.Verify(Fixtures.Bytes("receipt")).BundleId);
    }

    /// <summary>The pinned roots are anchors, but their expiry is worth reporting.</summary>
    [Fact]
    public void EveryPinnedRootIsStillWithinItsOwnValidityWindow()
    {
        foreach (X509Certificate2 root in AppleRootCertificates.JwsRoots())
        {
            Assert.True(
                root.NotAfter.ToUniversalTime() > DateTime.UtcNow,
                $"{root.Subject} expired on {root.NotAfter:o} — cut a release with the new roots");
        }
    }

    private static string CertsDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "certs");
            if (File.Exists(Path.Combine(candidate, "AppleRootCA-G3.cer")))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate the repository certs/ directory");
    }
}
