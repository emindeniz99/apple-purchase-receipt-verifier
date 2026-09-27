using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What the config clock drives, and what it must never be able to reach.
/// The clock answers "what time is it now?" and is read in two places only:
/// the chain instant when the input states no signing date, and the
/// endpoint's <c>request_date</c> (design, Setup). No payload is rejected
/// for its age.
/// </summary>
public class ClockTests
{
    /// <summary>2099-01-01T00:00:00Z, far past every chain the fixtures carry.</summary>
    private const long Year2099Ms = 4070908800000L;

    /// <summary>
    /// Freshness is the caller's decision: a payload that states its signing
    /// date is judged at that date, so a clock far past the chain's end does
    /// not reject it.
    /// </summary>
    [Fact]
    public void AStatedSigningDateIsNeverOverriddenByTheClock()
    {
        CountingClock clock = new(Year2099Ms);
        IVerifier verifier = Verifier.Create(TestPki.FixtureConfig("jws-root", clock.Read));
        Assert.True(verifier.VerifySignedData(Fixtures070.ForSignedData("transaction")).Verified);

        IVerifier receipts = Verifier.Create(TestPki.FixtureConfig("receipt-root", clock.Read));
        Assert.True(receipts.VerifyReceipt(Fixtures070.ForReceipt("receipt")).Verified);

        Assert.Equal(0, clock.Reads);
    }

    /// <summary>The clock stands in for a missing date, and is read once for it.</summary>
    [Fact]
    public void TheClockIsReadOnlyWhenTheInputStatesNoDate()
    {
        CountingClock clock = new(TestPki.SignedAtMs);
        IVerifier verifier = Verifier.Create(TestPki.FixtureConfig("divergence-jws-root", clock.Read));
        Assert.True(verifier.VerifySignedData(Fixtures070.ForSignedData("transaction-no-signed-date")).Verified);
        Assert.Equal(1, clock.Reads);

        CountingClock receiptClock = new(TestPki.SignedAtMs);
        IVerifier receipts = Verifier.Create(TestPki.FixtureConfig("divergence-receipt-root", receiptClock.Read));
        Assert.True(receipts.VerifyReceipt(Fixtures070.ForReceipt("receipt-no-creation-date")).Verified);
        Assert.Equal(1, receiptClock.Reads);
    }

    /// <summary>Input that fails its own checks never reaches the clock.</summary>
    [Fact]
    public void MalformedInputNeverReadsTheClock()
    {
        CountingClock clock = new(TestPki.SignedAtMs);
        IVerifier verifier = Verifier.Create(TestPki.FixtureConfig("receipt-root", clock.Read));
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("not base64").Failure?.Reason);
        Assert.Equal(VerificationReason.Malformed, verifier.VerifySignedData("a.b").Failure?.Reason);
        Assert.Equal(0, clock.Reads);
    }

    /// <summary>
    /// A request carries exactly one request date: the endpoint reads the
    /// clock once per call, and a dateless receipt is judged at that same
    /// reading rather than at a second one.
    /// </summary>
    [Fact]
    public void TheEndpointReadsTheClockOncePerRequest()
    {
        CountingClock clock = new(TestPki.SignedAtMs);
        IVerifier verifier = Verifier.Create(TestPki.FixtureConfig("divergence-receipt-root", clock.Read));
        string body = "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt-no-creation-date") + "\"}";

        string answer = verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body);
        Assert.StartsWith("{\"status\":0,", answer, StringComparison.Ordinal);
        Assert.Contains("\"request_date_ms\":\"1722945600000\"", answer, StringComparison.Ordinal);
        Assert.Equal(1, clock.Reads);
    }

    [Fact]
    public void TheDefaultClockIsTheSystemClock()
    {
        IVerifier verifier = Verifier.Create(
            Config.CreateBuilder().Roots(new[] { TestPki.FixtureCertificate("receipt-root") }).Build());
        string answer = verifier.VerifyReceiptEndpoint(
            AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt") + "\"}");

        OrderedMap receipt = (OrderedMap)Json.ParseObject(answer)["receipt"]!;
        long stamped = long.Parse((string)receipt["request_date_ms"]!, System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - stamped) < 60_000);
    }

    /// <summary>
    /// A clock that throws is the host's fault, not the input's: it is an
    /// internal error with the clock's exception as the cause, never
    /// MALFORMED (which would blame the input) and never a throw. The Java
    /// reference's <c>CallClock</c> pins the same.
    /// </summary>
    [Fact]
    public void AFailingClockIsAnInternalErrorNotABlameOnTheInput()
    {
        InvalidOperationException broken = new("broken clock");
        long Throwing() => throw broken;

        IVerifier jws = Verifier.Create(TestPki.FixtureConfig("divergence-jws-root", Throwing));
        Failure jwsFailure = jws.VerifySignedData(Fixtures070.ForSignedData("transaction-no-signed-date")).Failure!;
        Assert.Equal(VerificationReason.InternalError, jwsFailure.Reason);
        Assert.Same(broken, jwsFailure.Cause);

        IVerifier receipts = Verifier.Create(TestPki.FixtureConfig("divergence-receipt-root", Throwing));
        Failure receiptFailure = receipts.VerifyReceipt(Fixtures070.ForReceipt("receipt-no-creation-date")).Failure!;
        Assert.Equal(VerificationReason.InternalError, receiptFailure.Reason);
        Assert.Same(broken, receiptFailure.Cause);

        Assert.Equal(
            "{\"status\":21009}",
            receipts.VerifyReceiptEndpoint(
                AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt") + "\"}"));
    }

    /// <summary>
    /// The seam cannot be bypassed by accident: the library reads the system
    /// clock at exactly one site, the default clock in <c>Config</c>, and
    /// everything else goes through the config clock.
    /// </summary>
    [Fact]
    public void TheSystemClockIsReadAtExactlyOneSite()
    {
        List<string> hits = new();
        foreach (string file in Directory.GetFiles(SourceRoot(), "*.cs", SearchOption.AllDirectories))
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string code = lines[i].Trim();
                if (code.StartsWith("//", StringComparison.Ordinal)
                    || code.StartsWith("*", StringComparison.Ordinal))
                {
                    continue;
                }

                if (lines[i].Contains("DateTime.UtcNow", StringComparison.Ordinal)
                    || lines[i].Contains("DateTime.Now", StringComparison.Ordinal)
                    || lines[i].Contains("DateTimeOffset.Now", StringComparison.Ordinal)
                    || lines[i].Contains("DateTimeOffset.UtcNow", StringComparison.Ordinal)
                    || lines[i].Contains("Environment.TickCount", StringComparison.Ordinal)
                    || lines[i].Contains("Stopwatch", StringComparison.Ordinal))
                {
                    hits.Add(Path.GetFileName(file) + ":" + (i + 1) + " " + code);
                }
            }
        }

        string hit = Assert.Single(hits);
        Assert.StartsWith("Config.cs:", hit, StringComparison.Ordinal);
    }

    private static string SourceRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "dotnet", "src", "ApplePurchaseReceiptVerifier");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate the library sources");
    }

    /// <summary>A test-side clock that counts its reads; the library itself has no such hook.</summary>
    private sealed class CountingClock
    {
        private readonly long _now;
        private int _reads;

        internal CountingClock(long now) => _now = now;

        internal int Reads => Volatile.Read(ref _reads);

        internal long Read()
        {
            Interlocked.Increment(ref _reads);
            return _now;
        }
    }
}
