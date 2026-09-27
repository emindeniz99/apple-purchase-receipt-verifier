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
    public void TheBundledSetAndTheDefaultsCarryAllThreePublishedAppleRoots()
    {
        foreach (IReadOnlyList<X509Certificate2> roots in
            new[] { AppleRootCertificates.Bundled(), Config.Defaults().Roots })
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

        List<string> compiled = AppleRootCertificates.Bundled()
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
        IReadOnlyList<X509Certificate2> first = AppleRootCertificates.Bundled();
        foreach (X509Certificate2 root in first)
        {
            root.Dispose();
        }

        IReadOnlyList<X509Certificate2> second = AppleRootCertificates.Bundled();
        Assert.Equal(3, second.Count);
        Assert.NotEmpty(second[0].Subject);
        Assert.False(ReferenceEquals(first[0], second[0]));
    }

    /// <summary>
    /// A config keeps its own copies, so a caller may dispose the anchors it
    /// passed in, or keep adding to the list it passed, without touching a
    /// verifier already built.
    /// </summary>
    [Fact]
    public void AVerifierSurvivesTheCallerDisposingOrChangingTheAnchorsItPassedIn()
    {
        X509Certificate2 root = TestPki.FixtureCertificate("receipt-root");
        List<X509Certificate2> passed = new() { root };
        IVerifier verifier = Verifier.Create(Config.CreateBuilder().Roots(passed).Build());
        root.Dispose();
        passed.Clear();

        Assert.True(verifier.VerifyReceipt(Fixtures070.ForReceipt("receipt")).Verified);
    }

    /// <summary>
    /// <see cref="Config"/> is immutable and its roots are an unmodifiable
    /// copy: nothing a caller does to what <see cref="Config.Roots"/> hands
    /// out — changing the list, disposing a certificate — can add trust to,
    /// or take it from, a verifier built on that config.
    /// </summary>
    [Fact]
    public void WhatConfigRootsHandsOutCannotChangeTheConfig()
    {
        Config config = TestPki.FixtureConfig("receipt-root");
        IVerifier verifier = Verifier.Create(config);
        string receipt = Fixtures070.ForReceipt("receipt");
        string foreign = Fixtures070.ForReceipt("receipt-foreign");

        if (config.Roots is IList<X509Certificate2> list)
        {
            Assert.True(list.IsReadOnly, "Config.Roots is a writable list");
            Assert.ThrowsAny<NotSupportedException>(() => list.Clear());
        }

        foreach (X509Certificate2 root in config.Roots)
        {
            root.Dispose();
        }

        Assert.True(verifier.VerifyReceipt(receipt).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, verifier.VerifyReceipt(foreign).Failure?.Reason);
        Assert.Single(config.Roots);
        Assert.NotEmpty(config.Roots[0].RawData);
    }

    /// <summary>The pinned roots are anchors, but their expiry is worth reporting.</summary>
    [Fact]
    public void EveryPinnedRootIsStillWithinItsOwnValidityWindow()
    {
        foreach (X509Certificate2 root in AppleRootCertificates.Bundled())
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
