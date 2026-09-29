using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The anchors: the module's by default, the caller's when given, and how they are handed out.</summary>
public class RootsTests
{
    /// <summary>
    /// The three published Apple roots the tests pass explicitly, from the
    /// repository's <c>certs/</c>: the same bytes the module compiles in.
    /// </summary>
    [Fact]
    public void TheRepositoryCarriesAllThreePublishedAppleRoots()
    {
        IReadOnlyList<X509Certificate2> roots = TestRoots.AppleRoots();
        Assert.Equal(3, roots.Count);
        string[] subjects = roots.Select(r => r.Subject).ToArray();
        Assert.Contains(subjects, s => s.Contains("Apple Root CA - G2", StringComparison.Ordinal));
        Assert.Contains(subjects, s => s.Contains("Apple Root CA - G3", StringComparison.Ordinal));
        Assert.Contains(subjects, s => s.StartsWith("CN=Apple Root CA,", StringComparison.Ordinal));
    }

    /// <summary>
    /// The defaults list no certificate: the three Apple roots are pinned
    /// inside the module, and the library carries no copy it could disagree
    /// with the module about, not even a public list of them.
    /// </summary>
    [Fact]
    public void TheDefaultsListNoRootBecauseTheModuleHoldsThem()
    {
        Assert.Empty(Config.Defaults().Roots);
        Assert.Empty(Config.CreateBuilder().Build().Roots);
        Assert.Null(typeof(Config).Assembly.GetType("ApplePurchaseReceiptVerifier.AppleRootCertificates"));
        Assert.Null(typeof(Config).Assembly.GetType("ApplePurchaseReceiptVerifier.Internal.AppleRootData"));
    }

    /// <summary>"Apple's roots plus mine" is all four passed in, and the roots that come back are the caller's own.</summary>
    [Fact]
    public void AppleRootsPlusMineAreAllFourPassedIn()
    {
        List<X509Certificate2> roots = TestRoots.AppleRoots().ToList();
        roots.Add(TestRoots.FixtureCertificate("receipt-root"));
        Config config = Config.CreateBuilder().Roots(roots).Build();

        Assert.Equal(4, config.Roots.Count);
        Assert.Equal(
            roots.Select(r => Convert.ToHexString(SHA256.HashData(r.RawData))),
            config.Roots.Select(r => Convert.ToHexString(SHA256.HashData(r.RawData))));
    }

    /// <summary>
    /// A config keeps its own copies, so a caller may dispose the anchors it
    /// passed in, or keep adding to the list it passed, without touching a
    /// verifier already built: what reaches the module's <c>init</c> is the DER
    /// captured when the config was built.
    /// </summary>
    [Fact]
    public void AVerifierSurvivesTheCallerDisposingOrChangingTheAnchorsItPassedIn()
    {
        X509Certificate2 root = TestRoots.FixtureCertificate("receipt-root");
        string der = Convert.ToBase64String(root.RawData);
        List<X509Certificate2> passed = new() { root };
        Config config = Config.CreateBuilder().Roots(passed).Build();
        root.Dispose();
        passed.Clear();

        Assert.Equal("{\"roots\":[\"" + der + "\"]}", System.Text.Encoding.UTF8.GetString(VerifierImpl.ConfigJson(config)));
        IVerifier verifier = new VerifierImpl(config, new AprvRuntime(new StubModule().ToWasm(), null));
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("x").Failure?.Reason);
    }

    /// <summary>The defaults send <c>{}</c>, which the module reads as its built-in roots; several roots are sent in order.</summary>
    [Fact]
    public void InitGetsTheCallersRootsInOrderOrNoneForTheDefaults()
    {
        Assert.Equal("{}", System.Text.Encoding.UTF8.GetString(VerifierImpl.ConfigJson(Config.Defaults())));

        X509Certificate2 first = TestRoots.FixtureCertificate("receipt-root");
        X509Certificate2 second = TestRoots.FixtureCertificate("jws-root");
        Config two = Config.CreateBuilder().Roots(new[] { first, second }).Build();
        Assert.Equal(
            "{\"roots\":[\"" + Convert.ToBase64String(first.RawData) + "\",\"" + Convert.ToBase64String(second.RawData) + "\"]}",
            System.Text.Encoding.UTF8.GetString(VerifierImpl.ConfigJson(two)));
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
        Config config = TestRoots.FixtureConfig("receipt-root");
        string before = System.Text.Encoding.UTF8.GetString(VerifierImpl.ConfigJson(config));

        if (config.Roots is IList<X509Certificate2> list)
        {
            Assert.True(list.IsReadOnly, "Config.Roots is a writable list");
            Assert.ThrowsAny<NotSupportedException>(() => list.Clear());
        }

        foreach (X509Certificate2 root in config.Roots)
        {
            root.Dispose();
        }

        Assert.Equal(before, System.Text.Encoding.UTF8.GetString(VerifierImpl.ConfigJson(config)));
        Assert.NotEmpty(Assert.Single(config.Roots).RawData);
    }

    /// <summary>The pinned roots are anchors, but their expiry is worth reporting.</summary>
    [Fact]
    public void EveryPinnedRootIsStillWithinItsOwnValidityWindow()
    {
        foreach (X509Certificate2 root in TestRoots.AppleRoots())
        {
            Assert.True(
                root.NotAfter.ToUniversalTime() > DateTime.UtcNow,
                $"{root.Subject} expired on {root.NotAfter:o} — cut a release with the new roots");
        }
    }
}
