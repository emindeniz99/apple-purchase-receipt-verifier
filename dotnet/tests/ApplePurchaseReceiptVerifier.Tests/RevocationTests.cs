using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The revocation settings (docs/design/revocation.md §4, §8, §9): what
/// <see cref="Config"/> keeps, what reaches the module's <c>init</c>, and the
/// state the verifier reports, which is the module's answer and nothing the
/// wrapper works out. The rules themselves are the shared cases'.
/// </summary>
public class RevocationTests
{
    private static readonly string[] AppleListUrls =
    {
        "http://crl.apple.com/root.crl", "http://crl.apple.com/applerootcag3.crl",
        "http://crl.apple.com/wwdrg5.crl", "http://crl.apple.com/wwdrg6.crl",
    };

    private static string InitJson(Config config) => Encoding.UTF8.GetString(VerifierImpl.ConfigJson(config));

    private static VerifierImpl Over(StubModule stub, Config? config = null) =>
        new(config ?? new Config(), new AprvRuntime(stub.ToWasm(), null));

    [Fact]
    public void TheDefaultsHaveNoRevocationSettingsAndSendNone()
    {
        Config defaults = new();
        Assert.Empty(defaults.RevocationLists);
        Assert.Empty(defaults.RevocationIssuers);
        Assert.Empty(defaults.Distrust);
        Assert.Equal("{}", InitJson(defaults));
        Assert.Equal("{}", InitJson(new Config(revocationLists: new List<byte[]>(), distrust: new List<RevokedCertificate>())));
    }

    /// <summary>
    /// The settings reach <c>init</c> as §8 names them: lists and issuers as
    /// base64 bytes, issuers exactly as roots are passed, and distrust entries
    /// as <c>{"issuer","serial"}</c> with the strings as given, unchecked here:
    /// the module judges them.
    /// </summary>
    [Fact]
    public void TheSettingsReachInitAsTheWireNamesThem()
    {
        X509Certificate2 issuer = TestRoots.FixtureCertificate("revocation-intermediate");
        Config config = new(
            revocationLists: new[] { new byte[] { 0xFB, 0xFF }, new byte[] { 2 } },
            revocationIssuers: new[] { issuer },
            distrust: new[] { new RevokedCertificate("Ab", "0x1"), new RevokedCertificate(string.Empty, "zz") });
        Assert.Equal(
            "{\"revocation_lists\":[\"+/8=\",\"Ag==\"],\"revocation_issuers\":[\"" + Convert.ToBase64String(issuer.RawData) + "\"],"
            + "\"distrust\":[{\"issuer\":\"Ab\",\"serial\":\"0x1\"},{\"issuer\":\"\",\"serial\":\"zz\"}]}",
            InitJson(config));
    }

    /// <summary>
    /// A config keeps its own copies of the lists and issuers, and hands out
    /// fresh ones: nothing the caller does to what it passed in or got back
    /// reaches a verifier built from it.
    /// </summary>
    [Fact]
    public void TheConfigKeepsItsOwnCopies()
    {
        byte[] list = { 1, 2, 3 };
        X509Certificate2 issuer = TestRoots.FixtureCertificate("revocation-intermediate");
        Config config = new(revocationLists: new[] { list }, revocationIssuers: new[] { issuer });
        string before = InitJson(config);
        list[0] = 9;
        issuer.Dispose();
        config.RevocationLists[0][1] = 9;
        Assert.Equal(before, InitJson(config));
        Assert.Equal(new byte[] { 1, 2, 3 }, config.RevocationLists[0]);
        Assert.NotEmpty(Assert.Single(config.RevocationIssuers).RawData);
        IList<byte[]> lists = Assert.IsAssignableFrom<IList<byte[]>>(config.RevocationLists);
        Assert.True(lists.IsReadOnly);
        IList<RevokedCertificate> entries = Assert.IsAssignableFrom<IList<RevokedCertificate>>(
            new Config(distrust: new[] { new RevokedCertificate("a", "b") }).Distrust);
        Assert.True(entries.IsReadOnly);
    }

    [Fact]
    public void ANullInASettingIsAnArgumentError()
    {
        Assert.Throws<ArgumentException>("revocationLists", () => new Config(revocationLists: new byte[][] { null! }));
        Assert.Throws<ArgumentException>("revocationIssuers", () => new Config(revocationIssuers: new X509Certificate2[] { null! }));
        Assert.Throws<ArgumentException>("distrust", () => new Config(distrust: new RevokedCertificate[] { null! }));
        Assert.Throws<ArgumentNullException>("issuer", () => new RevokedCertificate(null!, "01"));
        Assert.Throws<ArgumentNullException>("serial", () => new RevokedCertificate("a", null!));
        RevokedCertificate entry = new("ab", "01");
        Assert.Equal("ab", entry.Issuer);
        Assert.Equal("01", entry.Serial);
        Assert.Equal("ab:01", entry.ToString());
    }

    /// <summary>
    /// The verifier reports what its first instance's <c>init</c> answered,
    /// read once: the stub states two URLs and an instant, and the verifier
    /// says the same, with the URLs unmodifiable.
    /// </summary>
    [Fact]
    public void TheVerifierReportsTheStateInitAnswered()
    {
        StubModule stub = new()
        {
            InitAnswer = "{\"ok\":true,\"max_input_bytes\":3145729,"
                + "\"revocation_urls\":[\"http://crl.example.test/a.crl\",\"https://crl.example.test/a.crl\"],"
                + "\"revocation_valid_until_ms\":1795046400000}",
        };
        VerifierImpl verifier = Over(stub);
        Assert.Equal(new[] { "http://crl.example.test/a.crl", "https://crl.example.test/a.crl" }, verifier.RevocationUrls);
        Assert.Equal(1795046400000L, verifier.RevocationValidUntilMs);
        Assert.True(Assert.IsAssignableFrom<IList<string>>(verifier.RevocationUrls).IsReadOnly);
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("x").Failure?.Reason);
        Assert.Equal(2, verifier.RevocationUrls.Count);

        VerifierImpl none = Over(new StubModule());
        Assert.Empty(none.RevocationUrls);
        Assert.Null(none.RevocationValidUntilMs);
    }

    /// <summary>
    /// An accepting answer without the revocation state comes from a module
    /// older than revocation: create fails with the
    /// <see cref="InvalidOperationException"/> the README promises for a module
    /// of another version. A refusal is the caller's configuration, an
    /// <see cref="ArgumentException"/> carrying the module's message.
    /// </summary>
    [Fact]
    public void CreateFailsOnAnOlderModuleOrARefusedConfiguration()
    {
        InvalidOperationException old = Assert.ThrowsAny<InvalidOperationException>(
            () => Over(new StubModule { InitAnswer = "{\"ok\":true,\"max_input_bytes\":3145729}" }));
        Assert.Contains("revocation_urls", old.Message, StringComparison.Ordinal);

        StubModule refusing = new() { InitAnswer = "{\"ok\":false,\"message\":\"distrust[0]: not an issuer id\"}" };
        ArgumentException refused = Assert.Throws<ArgumentException>(() => Over(refusing));
        Assert.Contains("distrust[0]: not an issuer id", refused.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The real module's state for the two kinds of roots (§7): Apple's four
    /// list URLs and no list held with Apple's roots, nothing with the
    /// caller's own; and a distrust entry it cannot read refused at create.
    /// </summary>
    [Fact]
    public void TheModuleStatesTheRevocationStateOfTheRoots()
    {
        IVerifier apple = Verifier.Create(new Config());
        Assert.Equal(AppleListUrls, apple.RevocationUrls);
        Assert.Null(apple.RevocationValidUntilMs);

        IVerifier own = TestRoots.FixtureVerifier("receipt-root");
        Assert.Empty(own.RevocationUrls);
        Assert.Null(own.RevocationValidUntilMs);

        Assert.Throws<ArgumentException>(
            () => Verifier.Create(new Config(distrust: new[] { new RevokedCertificate("not an issuer id", "01") })));
    }
}
