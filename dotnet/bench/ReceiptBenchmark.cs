using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ApplePurchaseReceiptVerifier.Receipt;
using BenchmarkDotNet.Attributes;

namespace ApplePurchaseReceiptVerifier.Bench
{
    /// <summary>
    /// The cross-port benchmark: the same six operations on the same two
    /// genuine sandbox receipts in every port, named after the Java JMH
    /// benchmarks in java-bench/ (BENCHMARKS.md at the repository root has
    /// the table).
    /// </summary>
    /// <remarks>
    /// The job mirrors java-bench's JMH settings: two processes, five warmup
    /// and five measured iterations each. Every input is prepared in
    /// <see cref="Setup"/>, which also runs each call once and fails unless
    /// it gives the answer the conformance suite expects, so no benchmark
    /// can time a fast failure by accident.
    /// </remarks>
    [MemoryDiagnoser]
    [SimpleJob(launchCount: 2, warmupCount: 5, iterationCount: 5)]
    public class ReceiptBenchmark
    {
        // The library's own receipt-data decoder is internal. Reflection
        // rather than an InternalsVisibleTo entry, as in fuzz/: the library
        // is what ships and this project must not change it. The delegate
        // is bound once, so each call costs a delegate invocation.
        private static readonly Func<string, byte[]> DecodeBase64Core =
            (Func<string, byte[]>)typeof(ReceiptVerifier)
                .GetMethod("DecodeBase64", BindingFlags.Static | BindingFlags.NonPublic, null, new[] { typeof(string) }, null)!
                .CreateDelegate(typeof(Func<string, byte[]>));

        private List<X509Certificate2> _roots = new List<X509Certificate2>();
        private byte[] _der = Array.Empty<byte>();
        private byte[] _tampered = Array.Empty<byte>();
        private string _base64 = string.Empty;
        private string _requestJson = string.Empty;
        private Dictionary<string, object?> _request = new Dictionary<string, object?>();
        private ReceiptVerifier? _verifier;
        private VerifyReceiptEndpoint? _sandbox;
        private VerifyReceiptEndpoint? _production;

        /// <summary>File under fixtures/public-receipts.</summary>
        [Params("receipt-sandbox-g5", "receipt-sandbox-legacy")]
        public string Fixture { get; set; } = string.Empty;

        /// <summary>Prepares and checks every input.</summary>
        [GlobalSetup]
        public void Setup()
        {
            // The bundle id, in-app count and digest fixtures/cases.json pins.
            (string bundleId, int inAppCount, string sha256) = Fixture switch
            {
                "receipt-sandbox-g5" => ("dev.bonzer.weeka.app", 2,
                    "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0"),
                "receipt-sandbox-legacy" => ("com.nutcall.alert", 187,
                    "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8"),
                _ => throw new InvalidOperationException("unknown fixture " + Fixture),
            };
            string text = File.ReadAllText(Path.Combine(FixturesDirectory(), "public-receipts", Fixture + ".b64"));
            _der = Convert.FromBase64String(text);
            Check(Convert.ToHexString(SHA256.HashData(_der)).ToLowerInvariant() == sha256, "digest");
            _base64 = Convert.ToBase64String(_der);
            _request = new Dictionary<string, object?> { ["receipt-data"] = _base64 };
            _requestJson = JsonSerializer.Serialize(_request);
            _tampered = Tamper(_der);
            _roots = AppleRootCertificates.ReceiptRoots().ToList();
            _verifier = new ReceiptVerifier(_roots, bundleId);
            FixedClock clock = new FixedClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
            _sandbox = new VerifyReceiptEndpoint(_roots, AppleEnvironment.Sandbox, clock);
            _production = new VerifyReceiptEndpoint(_roots, AppleEnvironment.Production, clock);

            Check(DecodeBase64Core(_base64).AsSpan().SequenceEqual(_der), "decodeBase64");
            foreach (AppReceipt receipt in new[] { Core(), VerifierBase64() })
            {
                Check(receipt.BundleId == bundleId && receipt.InAppPurchases.Count == inAppCount, "receipt");
            }
            using (JsonDocument ok = JsonDocument.Parse(EndpointJson()))
            {
                Check(ok.RootElement.GetProperty("status").GetInt32() == 0
                    && ok.RootElement.GetProperty("receipt").GetProperty("in_app").GetArrayLength() == inAppCount,
                    "endpointJson");
            }
            using (JsonDocument retry = JsonDocument.Parse(RetryViaResult()))
            {
                Check(retry.RootElement.GetProperty("status").GetInt32() == 0
                    && retry.RootElement.GetProperty("environment").GetString() == "Sandbox",
                    "retryViaResult");
            }
            Check(RejectTamperedSignature() is VerificationException { Reason: VerificationReason.InvalidSignature },
                "rejectTamperedSignature");
        }

        /// <summary>Releases the verifier and endpoints.</summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            _verifier?.Dispose();
            _sandbox?.Dispose();
            _production?.Dispose();
        }

        /// <summary>The library's receipt-data decoder on canonical base64.</summary>
        [Benchmark]
        public byte[] DecodeBase64() => DecodeBase64Core(_base64);

        /// <summary><c>VerifyReceiptCore</c> on pre-decoded DER.</summary>
        [Benchmark]
        public AppReceipt Core() => ReceiptVerifier.VerifyReceiptCore(_der, _roots);

        /// <summary>A verifier built in setup, on the base64 string.</summary>
        [Benchmark]
        public AppReceipt VerifierBase64() => _verifier!.Verify(_base64);

        /// <summary>The Sandbox endpoint, JSON request in, JSON response out.</summary>
        [Benchmark]
        public string EndpointJson() => _sandbox!.VerifyReceiptJson(_requestJson);

        /// <summary>The 21007 retry: a Production result rendered for Sandbox.</summary>
        [Benchmark]
        public string RetryViaResult() => _production!.VerifyReceiptResult(_request).ToJson(AppleEnvironment.Sandbox);

        /// <summary><c>VerifyReceiptCore</c> on a receipt with one signature bit flipped.</summary>
        [Benchmark]
        public object RejectTamperedSignature()
        {
            try
            {
                return ReceiptVerifier.VerifyReceiptCore(_tampered, _roots);
            }
            catch (VerificationException e)
            {
                return e;
            }
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
    }
}
