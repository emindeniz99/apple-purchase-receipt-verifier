using System;
using System.Collections.Generic;
using ApplePurchaseReceiptVerifier.Fuzz.Targets;
using SharpFuzz;

namespace ApplePurchaseReceiptVerifier.Fuzz
{
    /// <summary>
    /// One executable, five targets, selected by <c>APRV_FUZZ_TARGET</c>.
    /// </summary>
    /// <remarks>
    /// <para>The target is an environment variable and not libfuzzer-dotnet's
    /// <c>--target_arg</c> on purpose. <c>--target_arg</c> arrives as this
    /// process's first command-line argument, and that argument slot is what
    /// <c>Fuzzer.LibFuzzer.Run</c> reads a single input file from when the
    /// process runs on its own. Keeping the slot free is what makes replaying a
    /// crasher the obvious command it should be:</para>
    /// <code>
    /// APRV_FUZZ_TARGET=receipt ./ApplePurchaseReceiptVerifier.Fuzz artifacts/receipt/crash-2f1c…
    /// </code>
    /// <para><strong>Every target builds its anchors and verifiers on its first
    /// execution, never here.</strong> SharpFuzz's instrumentation makes the
    /// library's methods write edge counters through a shared-memory pointer
    /// that <c>Fuzzer.LibFuzzer.Run</c> installs; calling instrumented code
    /// before that — an eager <c>AppleRootCertificates.ReceiptRoots()</c> in
    /// <c>Main</c> did exactly this — dereferences a pointer that does not
    /// exist yet and kills the process with an
    /// <c>AccessViolationException</c> that looks like a library crash and is
    /// not one. The setup still happens once, just one execution later.</para>
    /// </remarks>
    internal static class Program
    {
        private static ReceiptDer? _receipt;
        private static ReceiptBase64? _receiptBase64;
        private static Targets.Jws? _jws;
        private static EndpointJson? _endpoint;

        private static int Main()
        {
            string name = Environment.GetEnvironmentVariable("APRV_FUZZ_TARGET") ?? string.Empty;

            Dictionary<string, ReadOnlySpanAction> targets = new Dictionary<string, ReadOnlySpanAction>(
                StringComparer.Ordinal)
            {
                ["json"] = JsonReader.Run,
                ["receipt"] = data => (_receipt ??= new ReceiptDer()).Run(data),
                ["receipt-base64"] = data => (_receiptBase64 ??= new ReceiptBase64()).Run(data),
                ["jws"] = data => (_jws ??= new Targets.Jws()).Run(data),
                ["endpoint-json"] = data => (_endpoint ??= new EndpointJson()).Run(data),
            };

            if (!targets.TryGetValue(name, out ReadOnlySpanAction? action))
            {
                Console.Error.WriteLine(
                    "set APRV_FUZZ_TARGET to one of: " + string.Join(", ", targets.Keys));
                return 2;
            }

            Fuzzer.LibFuzzer.Run(action);
            return 0;
        }
    }
}
