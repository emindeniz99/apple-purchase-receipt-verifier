using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What the injected clock drives (the endpoint's request_date), and what it
/// must never be able to reach. The JWS and receipt verifiers take no clock,
/// and no payload is rejected for its age (PLAN.md D5).
/// </summary>
public class ClockTests
{
    // The shared fixture is signed at 2024-08-06T12:00:00Z.
    private static readonly DateTimeOffset SignedAt = new(2024, 8, 6, 12, 0, 0, TimeSpan.Zero);

    private static IReadOnlyList<X509Certificate2> JwsRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) };

    /// <summary>Freshness is the caller's decision: a 2024 payload still verifies.</summary>
    [Fact]
    public void APayloadIsNeverRejectedForItsAge()
    {
        using JwsVerifier verifier = new(JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            SignedAt.ToUnixTimeMilliseconds(),
            verifier.VerifyTransaction(Fixtures.Text("transaction")).SignedDate);
    }

    [Fact]
    public void TheJwsVerifierTakesNoClock()
    {
        foreach (System.Reflection.ConstructorInfo constructor in typeof(JwsVerifier).GetConstructors())
        {
            Assert.DoesNotContain(constructor.GetParameters(), p => p.ParameterType == typeof(IClock));
            Assert.DoesNotContain(constructor.GetParameters(), p => p.ParameterType == typeof(TimeSpan?));
        }
    }

    /// <summary>
    /// A payload stating no signing time is judged at the system clock, where
    /// this chain (valid until 2050) is live.
    /// </summary>
    [Fact]
    public void APayloadWithoutASignedDateVerifies()
    {
        using JwsVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("divergence-jws-root")) },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox });
        Assert.Null(verifier.VerifyTransaction(Fixtures.Text("transaction-no-signed-date")).SignedDate);
    }

    [Fact]
    public void APayloadSignedAfterItsChainExpiredIsRejected()
    {
        // expired-cert-fresh is signed after its chain expired.
        using JwsVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-expired-root")) },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyTransaction(Fixtures.Text("expired-cert-fresh"))).Reason);
    }

    [Fact]
    public void TheEndpointStampsRequestDateFromTheInjectedClock()
    {
        DateTimeOffset now = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using VerifyReceiptEndpoint endpoint = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) },
            AppleEnvironment.Sandbox,
            new FixedClock(now));

        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["receipt-data"] = Convert.ToBase64String(Fixtures.Bytes("receipt")),
        };
        IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceiptResult(body).ToResponse();
        IReadOnlyDictionary<string, object?> receipt =
            (IReadOnlyDictionary<string, object?>)response["receipt"]!;

        Assert.Equal("1735689600000", receipt["request_date_ms"]);
        Assert.Equal("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"]);
        Assert.Equal("2024-12-31 16:00:00 America/Los_Angeles", receipt["request_date_pst"]);
    }

    [Fact]
    public void TheDefaultClockIsTheSystemClock()
    {
        Assert.True(
            Math.Abs((SystemClock.Instance.UtcNow - DateTimeOffset.UtcNow).TotalSeconds) < 5);

        using VerifyReceiptEndpoint endpoint = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) },
            AppleEnvironment.Sandbox);
        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["receipt-data"] = Convert.ToBase64String(Fixtures.Bytes("receipt")),
        };
        IReadOnlyDictionary<string, object?> receipt =
            (IReadOnlyDictionary<string, object?>)endpoint.VerifyReceiptResult(body).ToResponse()["receipt"]!;
        long stamped = long.Parse((string)receipt["request_date_ms"]!, System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - stamped) < 60_000);
    }

    [Fact]
    public void AFixedClockNormalisesToUtc()
    {
        FixedClock clock = new(new DateTimeOffset(2025, 1, 1, 5, 0, 0, TimeSpan.FromHours(5)));
        Assert.Equal(TimeSpan.Zero, clock.UtcNow.Offset);
        Assert.Equal(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), clock.UtcNow);
    }

    /// <summary>
    /// The seam cannot be bypassed by accident: the library reads the system
    /// clock at exactly the two documented certificate-validity fallbacks, and
    /// nowhere else.
    /// </summary>
    [Fact]
    public void TheSystemClockIsReadAtExactlyTheDocumentedSites()
    {
        List<string> hits = new();
        string sourceRoot = SourceRoot();
        foreach (string file in Directory.GetFiles(sourceRoot, "*.cs", SearchOption.AllDirectories))
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string code = lines[i].Trim();
                if (code.StartsWith("//", StringComparison.Ordinal)
                    || code.StartsWith("*", StringComparison.Ordinal))
                {
                    // Comments explain why the fallback reads real time; only
                    // executable lines count.
                    continue;
                }

                if (lines[i].Contains("DateTime.UtcNow", StringComparison.Ordinal)
                    || lines[i].Contains("DateTime.Now", StringComparison.Ordinal)
                    || lines[i].Contains("DateTimeOffset.Now", StringComparison.Ordinal)
                    || lines[i].Contains("DateTimeOffset.UtcNow", StringComparison.Ordinal))
                {
                    hits.Add(Path.GetFileName(file) + ":" + (i + 1) + " " + lines[i].Trim());
                }
            }
        }

        // IClock.cs (SystemClock itself), JwsVerifier.cs (the no-signedDate
        // fallback) and ReceiptVerifier.cs (the no-attribute-12 fallback).
        Assert.Equal(3, hits.Count);
        Assert.Contains(hits, h => h.StartsWith("IClock.cs:", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("JwsVerifier.cs:", StringComparison.Ordinal));
        Assert.Contains(hits, h => h.StartsWith("ReceiptVerifier.cs:", StringComparison.Ordinal));
    }

    private static string SourceRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(
                directory.FullName, "dotnet", "src", "ApplePurchaseReceiptVerifier");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate the library sources");
    }
}
