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
/// What the injected clock drives, and — more importantly — what it must never
/// be able to reach.
/// </summary>
public class ClockTests
{
    // The shared fixture is signed at 2024-08-06T12:00:00Z.
    private static readonly DateTimeOffset SignedAt = new(2024, 8, 6, 12, 0, 0, TimeSpan.Zero);

    private static IReadOnlyList<X509Certificate2> JwsRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) };

    private static JwsVerifier Verifier(TimeSpan? maxAge, IClock? clock) =>
        new(JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox }, null, maxAge, clock);

    [Fact]
    public void APayloadExactlyAtTheMaxSignedAgeIsAccepted()
    {
        using JwsVerifier verifier = Verifier(
            TimeSpan.FromSeconds(60), new FixedClock(SignedAt.AddSeconds(60)));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(Fixtures.Text("transaction")).BundleId);
    }

    [Fact]
    public void APayloadOneSecondPastTheMaxSignedAgeIsRejected()
    {
        using JwsVerifier verifier = Verifier(
            TimeSpan.FromSeconds(60), new FixedClock(SignedAt.AddSeconds(61)));
        Assert.Equal(
            VerificationReason.StalePayload,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyTransaction(Fixtures.Text("transaction"))).Reason);
    }

    /// <summary>A payload signed in the future has a negative age, not a stale one.</summary>
    [Fact]
    public void APayloadSignedAfterTheClockIsNotStale()
    {
        using JwsVerifier verifier = Verifier(
            TimeSpan.FromSeconds(60), new FixedClock(SignedAt.AddHours(-5)));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(Fixtures.Text("transaction")).BundleId);
    }

    /// <summary>A payload stating no signing time has no age to be stale by.</summary>
    [Fact]
    public void APayloadWithoutASignedDateIsNeverStale()
    {
        using JwsVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("divergence-jws-root")) },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox },
            null,
            TimeSpan.FromSeconds(60),
            new FixedClock(new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.Null(verifier.VerifyTransaction(Fixtures.Text("transaction-no-signed-date")).SignedDate);
    }

    /// <summary>
    /// The rule the whole clock design exists for: an injected clock cannot
    /// move a certificate-validity verdict in either direction.
    /// </summary>
    [Fact]
    public void AnInjectedClockCannotExpireAValidChain()
    {
        using JwsVerifier verifier = Verifier(
            null, new FixedClock(new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(Fixtures.Text("transaction")).BundleId);
    }

    [Fact]
    public void AnInjectedClockCannotAuthenticateAnExpiredChain()
    {
        // expired-cert-fresh is signed after its chain expired. A clock planted
        // inside the expired window must not rescue it.
        using JwsVerifier verifier = new(
            new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-expired-root")) },
            "com.example.app",
            new[] { AppleEnvironment.Sandbox },
            null,
            null,
            new FixedClock(new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero)));
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
        IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceipt(body);
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
            (IReadOnlyDictionary<string, object?>)endpoint.VerifyReceipt(body)["receipt"]!;
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
