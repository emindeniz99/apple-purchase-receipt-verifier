using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// What the config clock drives, and what it must never be able to reach.
/// The wrapper reads it once per call, before it looks at the input, and
/// hands the value to the module as <c>now-ms</c>; the module decides what to
/// use it for (the chain instant when the input states no signing date, and
/// <c>request_date</c> in the endpoint response). The wrapper rejects
/// nothing for a payload's age.
/// </summary>
public class ClockTests
{
    private const long Now = 1735689600000L;

    /// <summary>One read per call, for every entry point, whatever the input and however it ends.</summary>
    [Fact]
    public void TheClockIsReadOnceForEveryCall()
    {
        CountingClock clock = new(Now);
        IVerifier verifier = Verifier.Create(TestRoots.FixtureConfig("receipt-root", clock.Read));

        verifier.VerifyReceipt(Fixtures070.ForReceipt("receipt"));
        Assert.Equal(1, clock.Reads);
        verifier.VerifyReceipt("not base64");
        Assert.Equal(2, clock.Reads);
        verifier.VerifyReceipt(null!);
        Assert.Equal(3, clock.Reads);
        verifier.VerifySignedData("a.b");
        Assert.Equal(4, clock.Reads);
        verifier.VerifySignedData(string.Empty);
        Assert.Equal(5, clock.Reads);
        verifier.VerifyReceiptEndpoint(
            AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt") + "\"}");
        Assert.Equal(6, clock.Reads);
        verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, "not json");
        Assert.Equal(7, clock.Reads);
    }

    /// <summary>The value the clock answered is the <c>now-ms</c> the module gets, for every operation (a stub module records it).</summary>
    [Fact]
    public void EveryOperationPassesTheClockToTheModule()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        VerifierImpl verifier = new(new Config(clock: () => Now), runtime);

        verifier.VerifyReceipt("x");
        Assert.Equal(Now, LastNow(verifier));
        long later = Now + 1;
        VerifierImpl second = new(new Config(clock: () => later), runtime);
        second.VerifySignedData("x");
        Assert.Equal(later, LastNow(second));
        long third = Now + 2;
        VerifierImpl endpoint = new(new Config(clock: () => third), runtime);
        endpoint.VerifyReceiptEndpoint(AppleEnvironment.Production, "x");
        Assert.Equal(third, LastNow(endpoint));
    }

    [Fact]
    public void TheDefaultClockIsTheSystemClock()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        VerifierImpl verifier = new(new Config(), runtime);
        verifier.VerifyReceipt("x");
        Assert.True(Math.Abs(LastNow(verifier) - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) < 60_000);
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

        IVerifier verifier = Verifier.Create(TestRoots.FixtureConfig("receipt-root", Throwing));

        Failure receiptFailure = verifier.VerifyReceipt(Fixtures070.ForReceipt("receipt")).Failure!;
        Assert.Equal(VerificationReason.InternalError, receiptFailure.Reason);
        Assert.Same(broken, receiptFailure.Cause);

        Failure jwsFailure = verifier.VerifySignedData(Fixtures070.ForSignedData("transaction")).Failure!;
        Assert.Equal(VerificationReason.InternalError, jwsFailure.Reason);
        Assert.Same(broken, jwsFailure.Cause);

        Failure malformed = verifier.VerifyReceipt("not base64").Failure!;
        Assert.Equal(VerificationReason.InternalError, malformed.Reason);

        Assert.Equal(
            "{\"status\":21009}",
            verifier.VerifyReceiptEndpoint(
                AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + Fixtures070.ForReceipt("receipt") + "\"}"));
    }

    /// <summary>A negative time cannot be a u64 <c>now-ms</c>; it is the host's fault too.</summary>
    [Fact]
    public void ANegativeClockIsAnInternalError()
    {
        IVerifier verifier = Verifier.Create(TestRoots.FixtureConfig("receipt-root", () => -1));
        Failure failure = verifier.VerifyReceipt("x").Failure!;
        Assert.Equal(VerificationReason.InternalError, failure.Reason);
        Assert.NotNull(failure.Cause);
        Assert.Equal("{\"status\":21009}", verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{}"));
    }

    private static long LastNow(VerifierImpl verifier)
    {
        AprvInstance instance = verifier.Pool.Rent();
        try
        {
            return ReadNowMs(instance, 0);
        }
        finally
        {
            verifier.Pool.Return(instance);
        }
    }

    private static long ReadNowMs(AprvInstance instance, long fallback)
    {
        Wasmtime.Function? lastNow = instance.Raw.GetFunction("last_now");
        return lastNow is null ? fallback : (long)lastNow.Invoke()!;
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
        foreach (string file in SourceTree.LibraryFiles())
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
