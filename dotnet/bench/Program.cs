// The cross-port benchmark: the same six operations on the same two genuine
// sandbox receipts in every port, named after the Java JMH benchmarks in
// java-bench/ (BENCHMARKS.md at the repository root has the table).
//
//   dotnet run -c Release --project dotnet/bench > dotnet-bench.json
//
// Plain System.Diagnostics.Stopwatch, no benchmark dependency. Each benchmark
// warms up for one second, then takes ten samples of at least 100 ms each;
// the JSON on stdout carries the median, minimum and maximum microseconds per
// operation over those samples.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ApplePurchaseReceiptVerifier.Receipt;

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

        // The library's own receipt-data decoder is internal. Reflection
        // rather than an InternalsVisibleTo entry, as in fuzz/: the library
        // is what ships and this project must not change it. The delegate is
        // bound once, so each call costs a delegate invocation.
        private static readonly Func<string, byte[]> DecodeBase64 =
            (Func<string, byte[]>)typeof(ReceiptVerifier)
                .GetMethod("DecodeBase64", BindingFlags.Static | BindingFlags.NonPublic, null, new[] { typeof(string) }, null)!
                .CreateDelegate(typeof(Func<string, byte[]>));

        // Keeps each result reachable so no call can be optimized away.
        private static object? s_sink;

        private static void Main()
        {
            List<X509Certificate2> roots = AppleRootCertificates.ReceiptRoots().ToList();
            FixedClock clock = new FixedClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
            List<Result> results = new List<Result>();
            foreach ((string name, string bundleId, int inAppCount, string sha256) in Fixtures)
            {
                byte[] der = Convert.FromBase64String(
                    File.ReadAllText(Path.Combine(FixturesDirectory(), "public-receipts", name + ".b64")));
                Check(Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant() == sha256, name + " digest");
                string base64 = Convert.ToBase64String(der);
                Dictionary<string, object?> request = new Dictionary<string, object?> { ["receipt-data"] = base64 };
                string requestJson = JsonSerializer.Serialize(request);
                byte[] tampered = Tamper(der);
                using ReceiptVerifier verifier = new ReceiptVerifier(roots, bundleId);
                using VerifyReceiptEndpoint sandbox = new VerifyReceiptEndpoint(roots, AppleEnvironment.Sandbox, clock);
                using VerifyReceiptEndpoint production = new VerifyReceiptEndpoint(roots, AppleEnvironment.Production, clock);

                object RejectTampered()
                {
                    try
                    {
                        return ReceiptVerifier.VerifyReceiptCore(tampered, roots);
                    }
                    catch (VerificationException e)
                    {
                        return e;
                    }
                }

                // Every call once, with the answer the conformance suite
                // expects, so no benchmark can time a fast failure by accident.
                Check(DecodeBase64(base64).AsSpan().SequenceEqual(der), "decodeBase64");
                foreach (AppReceipt receipt in new[] { ReceiptVerifier.VerifyReceiptCore(der, roots), verifier.Verify(base64) })
                {
                    Check(receipt.BundleId == bundleId && receipt.InAppPurchases.Count == inAppCount, "receipt");
                }
                using (JsonDocument ok = JsonDocument.Parse(sandbox.VerifyReceiptJson(requestJson)))
                {
                    Check(ok.RootElement.GetProperty("status").GetInt32() == 0
                        && ok.RootElement.GetProperty("receipt").GetProperty("in_app").GetArrayLength() == inAppCount,
                        "endpointJson");
                }
                using (JsonDocument retry = JsonDocument.Parse(
                    production.VerifyReceiptResult(request).ToJson(AppleEnvironment.Sandbox)))
                {
                    Check(retry.RootElement.GetProperty("status").GetInt32() == 0
                        && retry.RootElement.GetProperty("environment").GetString() == "Sandbox",
                        "retryViaResult");
                }
                Check(RejectTampered() is VerificationException { Reason: VerificationReason.InvalidSignature },
                    "rejectTamperedSignature");

                results.Add(Measure("decodeBase64", name, () => DecodeBase64(base64)));
                results.Add(Measure("core", name, () => ReceiptVerifier.VerifyReceiptCore(der, roots)));
                results.Add(Measure("verifierBase64", name, () => verifier.Verify(base64)));
                results.Add(Measure("endpointJson", name, () => sandbox.VerifyReceiptJson(requestJson)));
                results.Add(Measure("retryViaResult", name,
                    () => production.VerifyReceiptResult(request).ToJson(AppleEnvironment.Sandbox)));
                results.Add(Measure("rejectTamperedSignature", name, RejectTampered));
            }
            Check(s_sink is not null, "sink");
            WriteReport(results);
        }

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

        private static void WriteReport(List<Result> results)
        {
            using Stream stdout = Console.OpenStandardOutput();
            using (Utf8JsonWriter json = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true }))
            {
                json.WriteStartObject();
                json.WriteString("port", "dotnet");
                json.WriteString("tool", "bench/Program.cs (System.Diagnostics.Stopwatch)");
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
