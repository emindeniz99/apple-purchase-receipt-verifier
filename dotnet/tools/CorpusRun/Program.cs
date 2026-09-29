// Drives the host layer over aprv.wasm with the shared corpora, and measures it.
//
//   CorpusRun calls CALLS.jsonl [MODULE.wasm]   one row per call, on stdout
//   CorpusRun probe FN CONFIG NOW ENV BASE64    one call, the module's answer on stdout
//   CorpusRun startup                           compile, first instance, later instances, first call
//   CorpusRun speed FN CALLS.jsonl ID SECONDS THREADS...   calls per second per thread count
//   CorpusRun memory N                          resident and virtual size with N live instances
//
// `calls` takes the canonical-ABI calls files (docs/evidence/
// 2026-09-29-canonical-abi-final/py/calls_bytes.py makes them) and writes rows in
// the Node runner's format ({"id","out"}, {"id","trap"}, {"id","map"}), so
// classify.py can hold them against ABI v1's Node rows. One instance serves
// each distinct init configuration and is thrown away after a trap, as the
// library's pool does; every call goes through the same AprvInstance the
// verifier uses.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using ApplePurchaseReceiptVerifier.Internal;
using Wasmtime;

namespace ApplePurchaseReceiptVerifier.CorpusRun
{
    internal static class Program
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Error.WriteLine("usage: CorpusRun calls|probe|startup|speed ...");
                return 2;
            }

            switch (args[0])
            {
                case "calls":
                    return Calls(args[1], args.Length > 2 ? args[2] : null);
                case "probe":
                    return Probe(args);
                case "startup":
                    return Startup();
                case "speed":
                    return Speed(args);
                case "memory":
                    return Memory(int.Parse(args[1], CultureInfo.InvariantCulture));
                default:
                    Console.Error.WriteLine("unknown mode " + args[0]);
                    return 2;
            }
        }

        private static AprvRuntime Runtime(string? modulePath) =>
            modulePath is null ? AprvRuntime.Shared : new AprvRuntime(File.ReadAllBytes(modulePath), null);

        private static string Quote(string text) => Json.Write(text);

        private static int Calls(string calls, string? modulePath)
        {
            AprvRuntime runtime = Runtime(modulePath);
            Dictionary<string, AprvInstance> instances = new Dictionary<string, AprvInstance>(StringComparer.Ordinal);
            long rows = 0, traps = 0, created = 0;
            using (StreamWriter output = new StreamWriter(Console.OpenStandardOutput(), Utf8, 1 << 20))
            {
                output.NewLine = "\n";
                foreach (string line in File.ReadLines(calls, Utf8))
                {
                    if (line.Trim().Length == 0)
                    {
                        continue;
                    }

                    OrderedMap row = Json.ParseObject(line);
                    string id = Quote((string)row["id"]!);
                    rows++;
                    if (row.ContainsKey("map"))
                    {
                        output.WriteLine("{\"id\":" + id + ",\"map\":" + Quote((string)row["map"]!) + "}");
                        continue;
                    }

                    string config = (string)row["config"]!;
                    string? answer = null;
                    if (!instances.TryGetValue(config, out AprvInstance? instance))
                    {
                        instance = new AprvInstance(runtime);
                        created++;
                        string ok = instance.Init(Utf8.GetBytes(config));
                        if (ok == "{\"ok\":true}")
                        {
                            instances[config] = instance;
                        }
                        else
                        {
                            answer = ok;
                            instance.Dispose();
                        }
                    }

                    long now = row["now"] is null ? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() : (long)row["now"]!;
                    byte[] input = Convert.FromBase64String((string)row["b64"]!);
                    try
                    {
                        if (answer is null)
                        {
                            switch ((string)row["fn"]!)
                            {
                                case "verify-receipt":
                                    answer = instance.VerifyReceipt(now, input);
                                    break;
                                case "verify-signed-data":
                                    answer = instance.VerifySignedData(now, input);
                                    break;
                                default:
                                    answer = instance.VerifyReceiptEndpoint((int)(long)row["env"]!, now, input);
                                    break;
                            }
                        }

                        output.WriteLine("{\"id\":" + id + ",\"out\":" + Quote(answer) + "}");
                    }
                    catch (Exception e) when (e is WasmtimeException || e is InvalidOperationException)
                    {
                        traps++;
                        if (instances.Remove(config))
                        {
                            instance.Dispose();
                        }

                        output.WriteLine("{\"id\":" + id + ",\"trap\":" + Quote(e.Message) + "}");
                    }
                }
            }

            Console.Error.WriteLine(
                "{\"host\":\"Wasmtime .NET 48.0.2\",\"dotnet\":" + Quote(Environment.Version.ToString())
                + ",\"rows\":" + rows.ToString(CultureInfo.InvariantCulture)
                + ",\"traps\":" + traps.ToString(CultureInfo.InvariantCulture)
                + ",\"instances\":" + created.ToString(CultureInfo.InvariantCulture) + "}");
            return 0;
        }

        private static int Probe(string[] args)
        {
            string fn = args[1];
            byte[] config = Utf8.GetBytes(args[2] == "-" ? string.Empty : args[2]);
            long now = args[3] == "-" ? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() : long.Parse(args[3], CultureInfo.InvariantCulture);
            int env = int.Parse(args[4], CultureInfo.InvariantCulture);
            byte[] input = Convert.FromBase64String(args[5]);
            AprvInstance instance = new AprvInstance(AprvRuntime.Shared);
            Console.Error.WriteLine("init: " + instance.Init(config));
            Console.WriteLine(fn switch
            {
                "verify-receipt" => instance.VerifyReceipt(now, input),
                "verify-signed-data" => instance.VerifySignedData(now, input),
                _ => instance.VerifyReceiptEndpoint(env, now, input),
            });
            return 0;
        }

        private static (byte[] Input, byte[] Config, string Fn, long Now) Find(string calls, string id)
        {
            foreach (string line in File.ReadLines(calls, Utf8))
            {
                if (line.Contains("\"" + id + "\"", StringComparison.Ordinal))
                {
                    OrderedMap row = Json.ParseObject(line);
                    return (
                        Convert.FromBase64String((string)row["b64"]!),
                        Utf8.GetBytes((string)row["config"]!),
                        (string)row["fn"]!,
                        row["now"] is null ? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() : (long)row["now"]!);
                }
            }

            throw new InvalidOperationException("no row " + id);
        }

        private static string Call(AprvInstance instance, string fn, long now, byte[] input) => fn switch
        {
            "verify-receipt" => instance.VerifyReceipt(now, input),
            "verify-signed-data" => instance.VerifySignedData(now, input),
            _ => throw new InvalidOperationException("speed measures receipts and JWSs"),
        };

        private static int Startup()
        {
            Stopwatch clock = Stopwatch.StartNew();
            AprvRuntime runtime = AprvRuntime.Shared;
            double compile = clock.Elapsed.TotalMilliseconds;
            clock.Restart();
            AprvInstance first = new AprvInstance(runtime);
            first.Init(Utf8.GetBytes("{}"));
            double firstInstance = clock.Elapsed.TotalMilliseconds;
            clock.Restart();
            List<double> later = new List<double>();
            for (int i = 0; i < 20; i++)
            {
                clock.Restart();
                AprvInstance next = new AprvInstance(runtime);
                next.Init(Utf8.GetBytes("{}"));
                later.Add(clock.Elapsed.TotalMilliseconds);
                next.Dispose();
            }

            later.Sort();
            Console.WriteLine(
                string.Format(
                    CultureInfo.InvariantCulture,
                    "compile_ms={0:F1} first_instance_with_init_ms={1:F1} later_instance_with_init_ms_median={2:F2} later_min={3:F2} later_max={4:F2} linear_memory_after_init_bytes={5}",
                    compile, firstInstance, later[later.Count / 2], later[0], later[later.Count - 1], first.MemoryBytes));
            first.Dispose();
            return 0;
        }

        private static int Memory(int count)
        {
            Process self = Process.GetCurrentProcess();
            AprvRuntime runtime = AprvRuntime.Shared;
            self.Refresh();
            Console.WriteLine(
                string.Format(CultureInfo.InvariantCulture, "after compile: resident {0:F0} MiB, virtual {1:F0} MiB", self.WorkingSet64 / 1048576.0, self.VirtualMemorySize64 / 1048576.0));
            List<AprvInstance> live = new List<AprvInstance>();
            for (int i = 1; i <= count; i++)
            {
                AprvInstance instance = new AprvInstance(runtime);
                instance.Init(Utf8.GetBytes("{}"));
                live.Add(instance);
                if (i == 1 || i == count || i % 8 == 0)
                {
                    self.Refresh();
                    Console.WriteLine(
                        string.Format(CultureInfo.InvariantCulture, "{0} instance(s): resident {1:F0} MiB, virtual {2:F0} MiB", i, self.WorkingSet64 / 1048576.0, self.VirtualMemorySize64 / 1048576.0));
                }
            }

            GC.KeepAlive(live);
            return 0;
        }

        private static int Speed(string[] args)
        {
            string fn = args[1];
            (byte[] input, byte[] config, _, long now) = Find(args[2], args[3]);
            double seconds = double.Parse(args[4], CultureInfo.InvariantCulture);
            AprvRuntime runtime = AprvRuntime.Shared;
            foreach (string t in args[5..])
            {
                int threads = int.Parse(t, CultureInfo.InvariantCulture);
                long[] counts = new long[threads];
                Thread[] pool = new Thread[threads];
                using ManualResetEventSlim go = new ManualResetEventSlim(false);
                long deadline = 0;
                for (int i = 0; i < threads; i++)
                {
                    int index = i;
                    pool[i] = new Thread(() =>
                    {
                        AprvInstance instance = new AprvInstance(runtime);
                        instance.Init(config);
                        for (int w = 0; w < 30; w++)
                        {
                            Call(instance, fn, now, input);
                        }

                        go.Wait();
                        long n = 0;
                        while (Stopwatch.GetTimestamp() < Interlocked.Read(ref deadline))
                        {
                            Call(instance, fn, now, input);
                            n++;
                        }

                        counts[index] = n;
                        instance.Dispose();
                    });
                    pool[i].Start();
                }

                Thread.Sleep(2000);
                long begin = Stopwatch.GetTimestamp();
                Interlocked.Exchange(ref deadline, begin + (long)(seconds * Stopwatch.Frequency));
                go.Set();
                foreach (Thread thread in pool)
                {
                    thread.Join();
                }

                long total = 0;
                foreach (long c in counts)
                {
                    total += c;
                }

                Console.WriteLine(
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "{0} {1}: {2} thread(s): {3:F1} per second ({4} calls in {5:F1} s)",
                        fn, args[3], threads, total / seconds, total, seconds));
            }

            return 0;
        }
    }
}
