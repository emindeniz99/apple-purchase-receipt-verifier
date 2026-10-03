using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Trust anchors from the <c>cases.json</c> fixture registry, and verifiers
/// pinned to them. Everything a test verifies is a registered fixture: the
/// wrapper mints no certificates of its own, because it verifies nothing.
/// </summary>
internal static class TestRoots
{
    /// <summary>2024-08-06T12:00:00Z, the instant the shared fixtures are signed at.</summary>
    internal const long SignedAtMs = 1722945600000L;

    private static readonly Lazy<List<string>> RootIds = new(() =>
    {
        List<string> ids = new();
        foreach (string id in Fixtures070.Ids)
        {
            if (!id.EndsWith("root", StringComparison.Ordinal) && id != "apple-test-ca")
            {
                continue;
            }

            using X509Certificate2? certificate = Certificates.TryLoad(Fixtures070.Bytes(id));
            if (certificate is not null)
            {
                ids.Add(id);
            }
        }

        return ids;
    });

    /// <summary>
    /// Every trust anchor the fixture registry holds: the ids ending in
    /// <c>root</c> that are certificates (one receipt fixture's name ends in
    /// <c>issued-by-root</c> too).
    /// </summary>
    internal static IReadOnlyList<string> RootFixtureIds => RootIds.Value;

    /// <summary>
    /// Apple's three published roots, read from the repository's <c>certs/</c>
    /// for the tests that pass them explicitly. The library carries no copy:
    /// its defaults are the roots compiled into the module.
    /// </summary>
    internal static IReadOnlyList<X509Certificate2> AppleRoots()
    {
        List<X509Certificate2> roots = new();
        foreach (string name in AppleRootFiles)
        {
            roots.Add(Certificates.TryLoad(File.ReadAllBytes(Path.Combine(CertsDirectory(), name)))
                ?? throw new InvalidOperationException($"harness error: certs/{name} is not a certificate"));
        }

        return roots;
    }

    /// <summary>The file names in <c>certs/</c>, in a fixed order.</summary>
    internal static readonly string[] AppleRootFiles =
    {
        "AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer",
    };

    /// <summary>The repository's <c>certs/</c> directory, found by walking up from the test binary.</summary>
    internal static string CertsDirectory()
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

    /// <summary>A certificate from the fixture registry.</summary>
    internal static X509Certificate2 FixtureCertificate(string id) =>
        Certificates.TryLoad(Fixtures070.Bytes(id))
        ?? throw new InvalidOperationException($"harness error: fixture \"{id}\" is not a certificate");

    /// <summary>A verifier that trusts exactly <paramref name="roots"/>, with the clock pinned when <paramref name="nowMs"/> is given.</summary>
    internal static IVerifier Verifier(IEnumerable<X509Certificate2> roots, long? nowMs = null)
    {
        Func<long>? clock = null;
        if (nowMs is long now)
        {
            clock = () => now;
        }

        return ApplePurchaseReceiptVerifier.Verifier.Create(new Config(roots, clock));
    }

    /// <summary>A verifier that trusts exactly the fixture root <paramref name="rootFixtureId"/>.</summary>
    internal static IVerifier FixtureVerifier(string rootFixtureId, long? nowMs = null) =>
        Verifier(new[] { FixtureCertificate(rootFixtureId) }, nowMs);

    /// <summary>A config that trusts exactly the fixture root <paramref name="rootFixtureId"/>, with <paramref name="clock"/> when given.</summary>
    internal static Config FixtureConfig(string rootFixtureId, Func<long>? clock = null) =>
        new(new[] { FixtureCertificate(rootFixtureId) }, clock);

    /// <summary>Every receipt the fixture registry holds, as <c>verifyReceipt</c> takes it (<see cref="Fixtures070.ForReceipt"/>).</summary>
    internal static IEnumerable<string> ReceiptFixtureIds()
    {
        foreach (string id in Fixtures070.Ids)
        {
            if ((id.Contains("receipt", StringComparison.Ordinal) || id == "legacy-purchase-info")
                && !RootIds.Value.Contains(id)
                && !id.StartsWith("public-receipts-", StringComparison.Ordinal))
            {
                yield return id;
            }
        }
    }
}
