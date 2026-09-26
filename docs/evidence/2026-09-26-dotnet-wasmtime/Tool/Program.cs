// Spike only (2026-09-26). The harness for aprv.wasm on wasmtime-dotnet:
//   Tool tests calls-cases.jsonl                        the 33 ABI tests + the facade's contract
//   Tool calls calls.jsonl                              corpus rows in the Node runner's exact format
//   Tool startup calls-cases.jsonl                      runtime (compile), first/second instance, first/second call
//   Tool bench calls-cases.jsonl id warm n              one thread, one instance
//   Tool threads calls-cases.jsonl id threads warm n    one instance per thread
//   Tool isolation calls-cases.jsonl                    independent instances; traps under concurrency
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using Aprv.Wasm;
using Wasmtime;

static class Program
{
    const string G5 = "receipt/verify-genuine-sandbox-g5-against-apple-roots";
    const string JWS = "transaction/verify-shared-sandbox";
    static readonly byte[] Ok = Encoding.UTF8.GetBytes("{\"verified\":true");

    static List<JsonElement> Load(string path) =>
        File.ReadLines(path).Where(l => l.Trim().Length > 0).Select(l => JsonDocument.Parse(l).RootElement).ToList();

    static (int op, byte[] input) CallOf(List<JsonElement> calls, string id)
    {
        var c = calls.First(x => x.GetProperty("id").GetString() == id);
        return (c.GetProperty("op").GetInt32(), Convert.FromBase64String(c.GetProperty("input").GetString()!));
    }

    static bool Verified(byte[] b) => b.AsSpan().StartsWith(Ok);

    /// <summary>A JSON string literal, escaped the way JSON.stringify escapes.</summary>
    static string Quote(string s)
    {
        var b = new StringBuilder(s.Length + 2).Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                case '\b': b.Append("\\b"); break;
                case '\f': b.Append("\\f"); break;
                default:
                    if (c < 0x20) b.Append("\\u").Append(((int)c).ToString("x4")); else b.Append(c);
                    break;
            }
        }
        return b.Append('"').ToString();
    }

    static int Main(string[] args)
    {
        var calls = Load(args[1]);
        switch (args[0])
        {
            case "tests": return AbiTests.Run(calls);
            case "calls": RunCalls(calls); return 0;
            case "startup": Startup(calls); return 0;
            case "bench": Bench(calls, args[2], int.Parse(args[3]), int.Parse(args[4])); return 0;
            case "threads": Threads(calls, args[2], int.Parse(args[3]), int.Parse(args[4]), int.Parse(args[5])); return 0;
            case "isolation": Isolation(calls); return 0;
            default: throw new ArgumentException(args[0]);
        }
    }

    static void RunCalls(List<JsonElement> calls)
    {
        var inst = new AprvInstance();
        int rows = 0, traps = 0;
        using var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false), 1 << 20);
        foreach (var c in calls)
        {
            rows++;
            var id = Quote(c.GetProperty("id").GetString()!);
            if (!c.TryGetProperty("op", out var op))
            {
                stdout.Write($"{{\"id\":{id},\"map\":{Quote(c.GetProperty("map").GetString()!)}}}\n");
                continue;
            }
            try
            {
                var outb = inst.Invoke(op.GetInt32(), Convert.FromBase64String(c.GetProperty("input").GetString()!));
                stdout.Write($"{{\"id\":{id},\"out\":{Quote(Encoding.UTF8.GetString(outb))}}}\n");
            }
            catch (Exception e) when (e is WasmtimeException || e is WasmTrapException || e is AbiMismatchException)
            {
                traps++;
                inst.Dispose();
                inst = new AprvInstance();
                stdout.Write($"{{\"id\":{id},\"trap\":{Quote(e.Message)}}}\n");
            }
        }
        stdout.Flush();
        Console.Error.WriteLine($"{{\"host\":\"dotnet-wasmtime\",\"dotnet\":\"{Environment.Version}\",\"rows\":{rows},\"traps\":{traps}}}");
    }

    static void Startup(List<JsonElement> calls)
    {
        byte[] wasm;
        using (var s = typeof(AprvRuntime).Assembly.GetManifestResourceStream("aprv.wasm")!)
        using (var ms = new MemoryStream()) { s.CopyTo(ms); wasm = ms.ToArray(); }
        var sw = Stopwatch.StartNew();
        var rt = new AprvRuntime(wasm);
        double t1 = sw.Elapsed.TotalMilliseconds;
        var a = new AprvInstance(rt);
        double t2 = sw.Elapsed.TotalMilliseconds;
        new AprvInstance(rt).Dispose();
        double t3 = sw.Elapsed.TotalMilliseconds;
        var (op, g5) = CallOf(calls, G5);
        double t4 = sw.Elapsed.TotalMilliseconds;
        if (!Verified(a.Invoke(op, g5))) throw new Exception("not verified");
        double t5 = sw.Elapsed.TotalMilliseconds;
        if (!Verified(a.Invoke(op, g5))) throw new Exception("not verified");
        double t6 = sw.Elapsed.TotalMilliseconds;
        string R(double x) => Math.Round(x, 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
        Console.WriteLine($"{{\"compile_module_ms\":{R(t1)},\"first_instance_ms\":{R(t2 - t1)},\"second_instance_ms\":{R(t3 - t2)},\"first_call_ms\":{R(t5 - t4)},\"second_call_ms\":{R(t6 - t5)}}}");
    }

    static void Bench(List<JsonElement> calls, string id, int warm, int n)
    {
        var (op, input) = CallOf(calls, id);
        var v = new AprvInstance();
        for (int i = 0; i < warm; i++) if (!Verified(v.Invoke(op, input))) throw new Exception("not verified");
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < n; i++) if (!Verified(v.Invoke(op, input))) throw new Exception("not verified");
        double us = sw.Elapsed.TotalMilliseconds * 1000 / n;
        Console.WriteLine($"{{\"id\":{Quote(id)},\"op\":{op},\"dotnet\":\"{Environment.Version}\",\"warm\":{warm},\"n\":{n},\"mean_us\":{Math.Round(us)},\"per_s\":{Math.Round(1e6 / us, 1)}}}");
    }

    static void Threads(List<JsonElement> calls, string id, int threads, int warm, int n)
    {
        var (op, input) = CallOf(calls, id);
        using var ready = new CountdownEvent(threads);
        using var go = new ManualResetEventSlim(false);
        long bad = 0;
        var ts = Enumerable.Range(0, threads).Select(_ => new Thread(() =>
        {
            var v = new AprvInstance();
            for (int i = 0; i < warm; i++) v.Invoke(op, input);
            ready.Signal();
            go.Wait();
            for (int i = 0; i < n; i++) if (!Verified(v.Invoke(op, input))) Interlocked.Increment(ref bad);
        })).ToList();
        ts.ForEach(t => t.Start());
        ready.Wait();
        var sw = Stopwatch.StartNew();
        go.Set();
        ts.ForEach(t => t.Join());
        double s = sw.Elapsed.TotalSeconds;
        Console.WriteLine($"{{\"id\":{Quote(id)},\"op\":{op},\"dotnet\":\"{Environment.Version}\",\"threads\":{threads},\"warm_each\":{warm},\"n_each\":{n},\"seconds\":{Math.Round(s, 2)},\"total_per_s\":{Math.Round(threads * n / s, 1)},\"not_verified\":{bad}}}");
    }

    static void Isolation(List<JsonElement> calls)
    {
        var (op, g5) = CallOf(calls, G5);
        var a = new Verifier();
        var b = new Verifier();
        var reference = a.Call(op, g5);
        try { a.Call(99, Array.Empty<byte>()); } catch (WasmTrapException) { }
        bool sameB = b.Call(op, g5).SequenceEqual(reference), sameA = a.Call(op, g5).SequenceEqual(reference);
        Console.WriteLine($"{{\"test\":\"independent instances: a trap in A leaves B untouched; A restarts fresh\",\"b_unchanged\":{(sameB ? "true" : "false")},\"a_after_trap\":{(sameA ? "true" : "false")},\"a_traps\":{a.Traps},\"b_traps\":{b.Traps},\"pass\":{(sameB && sameA && a.Traps == 1 && b.Traps == 0 ? "true" : "false")}}}");
        var good = new int[4];
        var traps = new int[4];
        long errors = 0;
        var ts = Enumerable.Range(0, 4).Select(k => new Thread(() =>
        {
            var v = new Verifier();
            for (int i = 0; i < 210; i++)
            {
                if (i % 7 == 6)
                {
                    try { v.Call(99, Array.Empty<byte>()); Interlocked.Increment(ref errors); } catch (WasmTrapException) { }
                }
                else if (v.Call(op, g5).SequenceEqual(reference)) good[k]++;
                else Interlocked.Increment(ref errors);
            }
            traps[k] = v.Traps;
        })).ToList();
        ts.ForEach(t => t.Start());
        ts.ForEach(t => t.Join());
        bool pass = errors == 0 && good.All(g => g == 180) && traps.All(t => t == 30);
        Console.WriteLine($"{{\"test\":\"4 threads, one Verifier each, a trap every 7th call\",\"good_calls\":[{string.Join(",", good)}],\"traps\":[{string.Join(",", traps)}],\"errors\":{errors},\"pass\":{(pass ? "true" : "false")}}}");
    }
}
