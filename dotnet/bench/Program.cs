// The cross-port benchmark: the same operations on the same two genuine
// sandbox receipts in every port, named after the Java JMH benchmarks in
// java-bench/ (BENCHMARKS.md at the repository root has the table).
//
//   dotnet run -c Release --project dotnet/bench > dotnet-bench.json
//
// Plain System.Diagnostics.Stopwatch, no benchmark dependency. Each benchmark
// warms up for one second, then takes ten samples of at least 100 ms each;
// the JSON on stdout carries the median, minimum and maximum microseconds per
// operation over those samples.
//
//   dotnet run -c Release --project dotnet/bench -- --worst-case
//
// times, the same way, every shared case in fixtures/cases.json that carries
// a maxMillis budget: the hostile inputs (oversized untrusted keys,
// certificate meshes, encoding oddities inside certificates) the shared suite
// bounds in time. Each call is run once first and must give the answer the
// case expects. The README's worst-case CPU figure comes from this mode.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ApplePurchaseReceiptVerifier;

namespace ApplePurchaseReceiptVerifier.Bench
{
    internal static class Program
    {
        private const double WarmupMs = 1000;
        private const int Samples = 10;
        private const double MinSampleMs = 100;

        // File under fixtures/public-receipts, and the bundle id, in-app count
        // and digest fixtures/cases.json pins for it.
        private static readonly (string Name, string BundleId, int InAppCount, string Sha256)[] Fixtures =
        {
            ("receipt-sandbox-g5", "dev.bonzer.weeka.app", 2,
                "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0"),
            ("receipt-sandbox-legacy", "com.nutcall.alert", 187,
                "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8"),
        };

        // Keeps each result reachable so no call can be optimized away.
        private static object? s_sink;

        private static readonly long NowMillis =
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();

        private static void Main(string[] args)
        {
            bool worstCase = args.Contains("--worst-case");
            List<Result> results = worstCase ? WorstCase() : CrossPort();
            Check(s_sink is not null, "sink");
            WriteReport(results, worstCase ? "worst-case" : "cross-port");
        }

        private static List<Result> CrossPort()
        {
            Config config = new Config(clock: () => NowMillis);
            IVerifier verifier = Verifier.Create(config);
            List<Result> results = new List<Result>();
            foreach ((string name, string bundleId, int inAppCount, string sha256) in Fixtures)
            {
                byte[] der = Convert.FromBase64String(
                    File.ReadAllText(Path.Combine(FixturesDirectory(), "public-receipts", name + ".b64")));
                Check(Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant() == sha256, name + " digest");
                string base64 = Convert.ToBase64String(der);
                string requestJson = JsonSerializer.Serialize(new Dictionary<string, object?> { ["receipt-data"] = base64 });
                byte[] tampered = Tamper(der);

                object RejectTampered()
                {
                    VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(Convert.ToBase64String(tampered));
                    return result.Failure ?? (object)result;
                }

                // Every call once, with the answer the conformance suite
                // expects, so no benchmark can time a fast failure by accident.
                VerificationResult<ReceiptPayload> verified = verifier.VerifyReceipt(base64);
                Check(
                    verified.Verified && verified.Payload!.BundleId == bundleId && verified.Payload!.InApp.Count == inAppCount,
                    "receipt");
                string endpointResponse = verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, requestJson);
                using (JsonDocument ok = JsonDocument.Parse(endpointResponse))
                {
                    Check(ok.RootElement.GetProperty("status").GetInt32() == 0
                        && ok.RootElement.GetProperty("receipt").GetProperty("in_app").GetArrayLength() == inAppCount,
                        "endpointJson");
                }
                Check(
                    RejectTampered() is Failure { Reason: VerificationReason.InvalidSignature },
                    "rejectTamperedSignature");

                results.Add(Measure("verifyReceipt", name, () => verifier.VerifyReceipt(base64)));
                results.Add(Measure("endpointJson", name, () => verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, requestJson)));
                results.Add(Measure("rejectTamperedSignature", name, RejectTampered));
            }
            return results;
        }

        private static List<Result> WorstCase()
        {
            string fixtures = FixturesDirectory();
            using JsonDocument file = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(fixtures, "cases.json")));
            JsonElement registry = file.RootElement.GetProperty("fixtures");

            // A registered fixture's logical bytes, per its codec (the same
            // rules the conformance adapter in tests/ applies).
            byte[] FixtureBytes(string id)
            {
                JsonElement entry = registry.GetProperty(id);
                byte[] raw = File.ReadAllBytes(Path.Combine(fixtures, entry.GetProperty("path").GetString()!));
                return entry.GetProperty("codec").GetString() switch
                {
                    "raw" or "text" => raw,
                    "base64" => Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(raw)),
                    "utf8" => System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(raw).Trim()),
                    var codec => throw new InvalidOperationException("fixture " + id + " has codec " + codec),
                };
            }

            List<Result> results = new List<Result>();
            foreach (JsonElement kase in file.RootElement.GetProperty("cases").EnumerateArray())
            {
                if (!kase.TryGetProperty("maxMillis", out _))
                {
                    continue;
                }
                string id = kase.GetProperty("id").GetString()!;
                string operation = kase.GetProperty("operation").GetString()!;
                JsonElement trusted = kase.GetProperty("config").GetProperty("trustedRoots");
                List<X509Certificate2>? roots = null;
                if (trusted.GetProperty("source").GetString() == "fixtures")
                {
                    roots = trusted.GetProperty("fixtures").EnumerateArray()
                        .Select(root => X509CertificateLoader.LoadCertificate(FixtureBytes(root.GetString()!)))
                        .ToList();
                }

                IVerifier verifier = Verifier.Create(new Config(roots, () => NowMillis));
                string fixture = kase.GetProperty("input").GetProperty("fixture").GetString()!;
                byte[] bytes = FixtureBytes(fixture);
                string codec = registry.GetProperty(fixture).GetProperty("codec").GetString()!;
                Func<Failure?> op = operation switch
                {
                    "verifyReceipt" when codec is "raw" or "base64" => Receipt(verifier, Convert.ToBase64String(bytes)),
                    "verifyReceipt" => Receipt(verifier, System.Text.Encoding.UTF8.GetString(bytes)),
                    "verifySignedData" => SignedData(verifier, System.Text.Encoding.UTF8.GetString(bytes)),
                    _ => throw new InvalidOperationException(id + ": no adapter for operation " + operation),
                };

                // The answer the case expects, before anything is timed.
                Failure? failure = op();
                string outcome = failure is null ? "ok" : VerificationReasonCodes.ToCode(failure.Reason);
                JsonElement expected = kase.GetProperty("expected");
                if (expected.TryGetProperty("oneOf", out JsonElement oneOf))
                {
                    Check(oneOf.EnumerateArray().Any(o => o.GetString() == outcome), id + " answered " + outcome);
                }
                else
                {
                    string want = expected.GetProperty("status").GetString() == "ok"
                        ? "ok"
                        : expected.GetProperty("reason").GetString()!;
                    Check(outcome == want, id + " answered " + outcome);
                }
                results.Add(Measure(operation, id, () => op() ?? (object)outcome));
            }
            return results;
        }

        private static Func<Failure?> Receipt(IVerifier verifier, string base64) =>
            () => verifier.VerifyReceipt(base64).Failure;

        private static Func<Failure?> SignedData(IVerifier verifier, string jws) =>
            () => verifier.VerifySignedData(jws).Failure;

        private static Result Measure(string benchmark, string fixture, Func<object> op)
        {
            long start = Stopwatch.GetTimestamp();
            long warmupOps = 0;
            while (Stopwatch.GetElapsedTime(start).TotalMilliseconds < WarmupMs)
            {
                s_sink = op();
                warmupOps++;
            }
            double perOpMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds / warmupOps;
            long ops = Math.Max(1, (long)Math.Ceiling(MinSampleMs / perOpMs));
            double[] samples = new double[Samples];
            for (int s = 0; s < Samples; s++)
            {
                long t = Stopwatch.GetTimestamp();
                for (long i = 0; i < ops; i++)
                {
                    s_sink = op();
                }
                samples[s] = Stopwatch.GetElapsedTime(t).TotalMicroseconds / ops;
            }
            Array.Sort(samples);
            double median = (samples[(Samples / 2) - 1] + samples[Samples / 2]) / 2;
            Console.Error.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "{0,24} {1,-24} {2,12:F1} us/op", benchmark, fixture, median));
            return new Result(benchmark, fixture, median, samples[0], samples[Samples - 1], ops);
        }

        private static void WriteReport(List<Result> results, string mode)
        {
            using Stream stdout = Console.OpenStandardOutput();
            using (Utf8JsonWriter json = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true }))
            {
                json.WriteStartObject();
                json.WriteString("port", "dotnet");
                json.WriteString("tool", "bench/Program.cs " + mode + " (System.Diagnostics.Stopwatch)");
                json.WriteString("runtime", RuntimeInformation.FrameworkDescription);
                json.WriteStartObject("settings");
                json.WriteNumber("warmup_s", WarmupMs / 1000);
                json.WriteNumber("samples", Samples);
                json.WriteNumber("min_sample_s", MinSampleMs / 1000);
                json.WriteEndObject();
                json.WriteStartArray("results");
                foreach (Result r in results)
                {
                    json.WriteStartObject();
                    json.WriteString("benchmark", r.Benchmark);
                    json.WriteString("fixture", r.Fixture);
                    json.WriteNumber("us_per_op_median", r.Median);
                    json.WriteNumber("us_per_op_min", r.Min);
                    json.WriteNumber("us_per_op_max", r.Max);
                    json.WriteNumber("ops_per_sample", r.OpsPerSample);
                    json.WriteEndObject();
                }
                json.WriteEndArray();
                json.WriteEndObject();
            }
            stdout.WriteByte((byte)'\n');
        }

        /// <summary>
        /// Flips one bit in the middle of the SignerInfo signature, the byte
        /// java-bench's flipSignatureByte flips. In both fixtures the
        /// signature is a 256-byte OCTET STRING that ends the DER (openssl
        /// asn1parse shows it), so its middle byte is 128 from the end; setup
        /// proves the flip landed there by requiring INVALID_SIGNATURE.
        /// </summary>
        private static byte[] Tamper(byte[] der)
        {
            byte[] tampered = (byte[])der.Clone();
            tampered[tampered.Length - 128] ^= 0x01;
            return tampered;
        }

        private static void Check(bool condition, string what)
        {
            if (!condition)
            {
                throw new InvalidOperationException("setup check failed: " + what);
            }
        }

        /// <summary>Walks up from the binary to the repository's fixtures/.</summary>
        private static string FixturesDirectory()
        {
            DirectoryInfo? directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null)
            {
                string candidate = Path.Combine(directory.FullName, "fixtures");
                if (File.Exists(Path.Combine(candidate, "cases.json")))
                {
                    return candidate;
                }
                directory = directory.Parent;
            }
            throw new DirectoryNotFoundException("no fixtures/cases.json above " + AppContext.BaseDirectory);
        }

        private readonly record struct Result(
            string Benchmark, string Fixture, double Median, double Min, double Max, long OpsPerSample);
    }
}
