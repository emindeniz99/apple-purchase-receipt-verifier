using BenchmarkDotNet.Running;

namespace ApplePurchaseReceiptVerifier.Bench
{
    internal static class Program
    {
        /// <summary>
        /// Runs <see cref="ReceiptBenchmark"/>; BenchmarkDotNet's own
        /// command-line options pass through (for example
        /// <c>--exporters json</c> or <c>--filter *Core*</c>).
        /// </summary>
        private static void Main(string[] args) => BenchmarkRunner.Run<ReceiptBenchmark>(args: args);
    }
}
