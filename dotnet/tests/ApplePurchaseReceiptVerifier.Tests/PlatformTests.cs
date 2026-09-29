using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Groups the tests that read or write process-wide state — the managed live
/// set, the default thread culture — so they do not run beside another
/// collection. xunit's default is one collection per class, all of them in
/// parallel, and <see cref="PlatformTests.RepeatedVerificationDoesNotGrowUnboundedly"/>
/// measures the whole heap, not just its own objects.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessWideCollection
{
    internal const string Name = "process-wide";
}

/// <summary>
/// The parts of this port that no cross-language vector can reach: thread
/// safety, retention, and the conformance harness's own resolver.
/// </summary>
[Collection(ProcessWideCollection.Name)]
public class PlatformTests
{
    // --- thread safety and retention -----------------------------------------

    /// <summary>
    /// The design's promise: one verifier is immutable and thread-safe. Four
    /// threads share one verifier, each takes an instance of its own from the
    /// pool, and every call gives what a single thread gives: the same result
    /// for a receipt, a JWS and the endpoint.
    /// </summary>
    [Fact]
    public void OneVerifierServesFourThreads()
    {
        IVerifier receipts = TestRoots.FixtureVerifier("receipt-root", TestRoots.SignedAtMs);
        IVerifier jws = TestRoots.FixtureVerifier("jws-root", TestRoots.SignedAtMs);
        string receipt = Fixtures070.ForReceipt("receipt");
        string transaction = Fixtures070.ForSignedData("transaction");
        string body = "{\"receipt-data\":\"" + receipt + "\"}";

        string Round()
        {
            VerificationResult<ReceiptPayload> r = receipts.VerifyReceipt(receipt);
            VerificationResult<JsonPayload> j = jws.VerifySignedData(transaction);
            return (r.Verified ? r.Payload.ToJson() : r.Failure.ToString()) + "|"
                + (j.Verified ? j.Payload.Json : j.Failure.ToString()) + "|"
                + receipts.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body);
        }

        string expected = Round();
        ConcurrentBag<string> failures = new();
        Task[] threads = new Task[4];
        for (int t = 0; t < threads.Length; t++)
        {
            threads[t] = Task.Factory.StartNew(
                () =>
                {
                    for (int i = 0; i < 50; i++)
                    {
                        try
                        {
                            Assert.Equal(expected, Round());
                        }
                        catch (Exception e)
                        {
                            failures.Add(e.ToString());
                        }
                    }
                },
                TaskCreationOptions.LongRunning);
        }

        Task.WaitAll(threads);
        Assert.Empty(failures);
    }

    /// <summary>
    /// Two calls that overlap never share an instance: each gets its own from
    /// the pool, and both come back, up to what the pool keeps.
    /// </summary>
    [Fact]
    public void ConcurrentCallsNeverShareAnInstance()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        InstancePool pool = new(runtime, System.Text.Encoding.UTF8.GetBytes("{}"));
        AprvInstance first = pool.Rent();
        AprvInstance second = pool.Rent();
        Assert.NotSame(first, second);
        pool.Return(first);
        pool.Return(second);
        AprvInstance again = pool.Rent();
        Assert.True(ReferenceEquals(again, first) || ReferenceEquals(again, second));
        pool.Return(again);
    }

    /// <summary>The verifications of a small measured round.</summary>
    private const int SmallRound = 500;

    /// <summary>The verifications of a large measured round.</summary>
    private const int LargeRound = 2000;

    /// <summary>
    /// Measured rounds of each size. The growth of a size is the smallest of
    /// its rounds: retention grows the live set in every round, a background
    /// allocation lands in one.
    /// </summary>
    private const int LiveSetRounds = 3;

    /// <summary>
    /// What one verification may leave behind, in bytes. A single retained
    /// <c>X509Certificate2</c> is ~1.5 kB of <c>RawData</c> alone (a measured
    /// leak of one per call read 1,730 B/call), so this is well under one
    /// leaked object per call. Linux measures 0 B/call, net of the controls.
    /// </summary>
    private const int LiveSetBudgetPerVerification = 256;

    /// <summary>The last object <see cref="Churn"/> made, so the allocations are not optimised away.</summary>
    private static object? _churned;

    /// <summary>
    /// Repeated verification must not grow unboundedly: each call moves bytes
    /// through unmanaged memory and reads a payload back, and a leak there is
    /// invisible until a server falls over. A module answering a full payload
    /// isolates the wrapper's own retention from the real module's.
    /// </summary>
    /// <remarks>
    /// <para>What is judged is the marginal live-set growth per verification: the
    /// growth of a round of <see cref="LargeRound"/> minus that of a round of
    /// <see cref="SmallRound"/>, over the difference in calls. A cost that does
    /// not depend on the number of calls (jitting, a runtime's own caches, a
    /// heap that commits a region while it is measured) is in both and cancels;
    /// retention grows with the calls and does not.</para>
    /// <para>A control is measured the same way and taken out: it allocates as
    /// many bytes per iteration as a verification does and keeps none, so a
    /// collector that reports some share of what a loop allocated as live (a
    /// platform's accounting, not a leak) shows that share there too. Only what
    /// the wrapper keeps beyond it counts against the budget. A second control,
    /// which does nothing for as long as a verification takes, is measured only
    /// when the test fails and is reported, not subtracted: growth there would
    /// be something else in the process whose live set grows with time (a test
    /// host's own reporting, a runtime thread), and would justify a change to
    /// this verdict on the evidence of a run.</para>
    /// <para>The bound is a budget per verification rather than a flat ceiling,
    /// so it scales with the round and fails on retention that is real but
    /// small. It can be that tight only because this class runs in a collection
    /// of its own (<see cref="ProcessWideCollection"/>):
    /// <see cref="GC.GetTotalMemory"/> reports the whole process's live set, so
    /// a sibling collection allocating on another thread lands in the delta.
    /// When it fails, the message carries every figure, the platform and a
    /// breakdown of where the growth is: the native call alone, the reading of
    /// the answer alone, the result objects, and the state of the pooled
    /// instance.</para>
    /// </remarks>
    [Fact]
    public void RepeatedVerificationDoesNotGrowUnboundedly()
    {
        AprvRuntime runtime = new(
            new StubModule { ReceiptAnswer = SyntheticAnswers.Verified(SyntheticAnswers.Receipt()) }.ToWasm(), null);
        VerifierImpl verifier = new(Config.Defaults(), runtime);
        string receipt = "x";

        // Warm up: first-call statics and JIT are a one-off cost, not
        // per-call retention. The allocation per call sizes the control.
        for (int i = 0; i < 50; i++)
        {
            Assert.True(verifier.VerifyReceipt(receipt).Verified);
        }

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            verifier.VerifyReceipt(receipt);
        }

        int allocatedPerCall = (int)((GC.GetAllocatedBytesForCurrentThread() - allocatedBefore) / 100);

        Measured wrapper = Marginal(() => verifier.VerifyReceipt(receipt));
        Measured alloc = Marginal(() => Churn(allocatedPerCall));

        // A control that reads below zero is noise, not credit to the wrapper.
        double share = wrapper.BytesPerCall - Math.Max(alloc.BytesPerCall, 0);
        if (share < LiveSetBudgetPerVerification)
        {
            return;
        }

        Measured idle = MarginalIdle(wrapper.MicrosPerCall);

        Assert.Fail(
            $"each verification left {wrapper.BytesPerCall:F1} B on the live set ({wrapper.MicrosPerCall:F0} us each) against "
            + $"{alloc.BytesPerCall:F1} B for a control that allocates the same {allocatedPerCall} B and keeps none and "
            + $"{idle.BytesPerCall:F1} B for one that idles as long (reported, not subtracted), so {share:F1} B are the wrapper's; the budget is "
            + $"{LiveSetBudgetPerVerification} B ({System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}, "
            + $"{System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier}). Where it is: {Breakdown(verifier, receipt)}");
    }

    /// <summary>A live-set growth per call and the wall time a call took.</summary>
    private readonly record struct Measured(double BytesPerCall, double MicrosPerCall);

    /// <summary>Bytes of live set per call from round to round: (large round - small round) / (large - small calls).</summary>
    private static Measured Marginal(Action call)
    {
        System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
        long small = SmallestGrowth(call, SmallRound, out int smallCalls);
        long large = SmallestGrowth(call, LargeRound, out int largeCalls);
        double micros = clock.Elapsed.TotalMilliseconds * 1000.0 / (smallCalls + largeCalls);
        return new Measured((large - small) / (double)(LargeRound - SmallRound), micros);
    }

    /// <summary>The same rounds with no calls, each lasting as long as the calls would.</summary>
    private static Measured MarginalIdle(double microsPerCall)
    {
        void Wait(int calls) => System.Threading.Thread.Sleep(TimeSpan.FromMilliseconds(microsPerCall * calls / 1000.0));
        long small = SmallestIdleGrowth(Wait, SmallRound);
        long large = SmallestIdleGrowth(Wait, LargeRound);
        return new Measured((large - small) / (double)(LargeRound - SmallRound), 0);
    }

    private static long SmallestGrowth(Action call, int calls, out int total)
    {
        total = calls * LiveSetRounds;
        return SmallestIdleGrowth(n =>
        {
            for (int i = 0; i < n; i++)
            {
                call();
            }
        }, calls);
    }

    private static long SmallestIdleGrowth(Action<int> round, int calls)
    {
        long smallest = long.MaxValue;
        long before = LiveSet();
        for (int r = 0; r < LiveSetRounds; r++)
        {
            round(calls);
            long after = LiveSet();
            smallest = Math.Min(smallest, after - before);
            before = after;
        }

        return smallest;
    }

    /// <summary>Allocates about <paramref name="bytes"/> in small objects and keeps none.</summary>
    private static void Churn(int bytes)
    {
        for (int allocated = 0; allocated < bytes; allocated += 128)
        {
            _churned = new byte[100];
        }

        _churned = null;
    }

    /// <summary>
    /// Where a growth is, for the failure message: the native call alone, the
    /// reading of a fixed answer alone, how many result objects outlive their
    /// collection, whether the pool hands the same instance back and what its
    /// store keeps.
    /// </summary>
    private static string Breakdown(VerifierImpl verifier, string receipt)
    {
        AprvInstance instance = verifier.Pool.Rent();
        string answerText;
        long linearMemory;
        string caches;
        byte[] input = System.Text.Encoding.UTF8.GetBytes(receipt);
        string answer = instance.VerifyReceipt(1_700_000_000_000L, input);
        Measured nativeOnly = Marginal(() => instance.VerifyReceipt(1_700_000_000_000L, input));
        Measured readOnly = Marginal(() => ModuleAnswers.ReadReceipt(answer));

        object? store = typeof(AprvInstance).GetField("_store", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(instance);
        caches = string.Join(
            ", ",
            new[] { "_externFunctionCache", "_externMemoryCache", "_externGlobalCache" }.Select(name =>
                name + "=" + ((store?.GetType().GetField(name, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(store)
                    as System.Collections.ICollection)?.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?")));

        linearMemory = instance.MemoryBytes;
        answerText = $"native call alone {nativeOnly.BytesPerCall:F1} B, reading the answer alone {readOnly.BytesPerCall:F1} B";

        verifier.Pool.Return(instance);
        (int results, int alive) = ResultsAfterCollection(verifier, receipt);
        AprvInstance again = verifier.Pool.Rent();
        bool same = ReferenceEquals(instance, again);
        verifier.Pool.Return(again);

        return $"{answerText}, {alive} of {results} dropped results still alive after two collections, "
            + $"the pool hands back the same instance: {same}, linear memory {linearMemory} B, store caches {caches}, "
            + $"process working set {Environment.WorkingSet} B";
    }

    /// <summary>Verifies <c>200</c> times, drops the results, and counts those a collection did not free.</summary>
    private static (int Created, int Alive) ResultsAfterCollection(VerifierImpl verifier, string receipt)
    {
        WeakReference[] weak = MakeWeak(verifier, receipt, 200);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return (weak.Length, weak.Count(w => w.IsAlive));
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static WeakReference[] MakeWeak(VerifierImpl verifier, string receipt, int count)
    {
        WeakReference[] weak = new WeakReference[count];
        for (int i = 0; i < count; i++)
        {
            weak[i] = new WeakReference(verifier.VerifyReceipt(receipt));
        }

        return weak;
    }

    /// <summary>The managed live set, with everything collectable collected.</summary>
    private static long LiveSet()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return GC.GetTotalMemory(true);
    }

    // --- the harness itself --------------------------------------------------

    /// <summary>
    /// The conformance adapter's field-path resolver has to be right, or the
    /// whole suite goes green against nothing. These are its own tests.
    /// </summary>
    [Fact]
    public void TheFieldPathResolverSelectsWhatTheGrammarSays()
    {
        object? model = Json.Parse(
            "{\"receipt\":{\"in_app\":[{\"product_id\":\"com.example.app.vip\",\"quantity\":\"1\"},"
            + "{\"product_id\":\"com.example.app.coins100\",\"quantity\":\"2\"}]},"
            + "\"unknown_attributes\":{\"9999\":[\"AQID\"]},\"a/b\":{\"c~d\":7}}");

        Assert.Equal(2L, JsonPointer070.Length(model, "/receipt/in_app"));
        Assert.Equal("1", JsonPointer070.Resolve(model, "/receipt/in_app/[product_id=com.example.app.vip]/quantity"));
        Assert.Equal("2", JsonPointer070.Resolve(model, "/receipt/in_app/1/quantity"));
        Assert.Equal("AQID", JsonPointer070.Resolve(model, "/unknown_attributes/9999/0"));
        Assert.Equal(1L, JsonPointer070.Length(model, "/unknown_attributes/9999"));
        Assert.Equal(7L, JsonPointer070.Resolve(model, "/a~1b/c~0d"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/absent"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/absent/deeper"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/in_app/5"));
    }

    [Fact]
    public void TheFieldPathResolverFailsWhenASelectorIsNotUnique()
    {
        object? model = Json.Parse("{\"list\":[{\"id\":\"a\"},{\"id\":\"a\"}]}");

        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "/list/[id=a]"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "/list/[id=missing]"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "list"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Length(model, "/list/0"));
    }
}
