using System;
using System.Reflection;

namespace ApplePurchaseReceiptVerifier.Fuzz
{
    /// <summary>
    /// Reflected access to the two internal parsers a fuzz target reaches
    /// directly: the hand-written JSON reader and the CMS pre-scan.
    /// </summary>
    /// <remarks>
    /// <para>Reflection rather than an <c>InternalsVisibleTo</c> entry: the
    /// library assembly is what ships, and this project exists to test it, not
    /// to change it. The delegates are bound once at startup, so the reflection
    /// costs nothing per execution and — because it is the library's own IL
    /// that runs — SharpFuzz's instrumentation of that assembly still reports
    /// the coverage.</para>
    /// <para>The internal exception types are compared by full name for the
    /// same reason: their identity is the invariant, and naming them in source
    /// would require making them public.</para>
    /// </remarks>
    internal static class Internals
    {
        private const string JsonExceptionName = "ApplePurchaseReceiptVerifier.Internal.JsonException";

        private static readonly Assembly Library = typeof(VerificationException).Assembly;

        private static readonly Func<string, int, object?> JsonParseCore =
            Bind<Func<string, int, object?>>("Internal.Json", "Parse");

        private static readonly Func<object?, string> JsonWriteCore =
            Bind<Func<object?, string>>("Internal.Json", "Write");

        private static readonly Func<byte[], int, int> CmsPreScanCore =
            Bind<Func<byte[], int, int>>("Internal.CmsPreScan", "Scan");

        /// <summary>The default maximum JSON length the library compiles in.</summary>
        internal const int JsonMaxLength = 16 * 1024 * 1024;

        /// <summary>The certificate bound the receipt path enforces.</summary>
        internal const int MaxEmbeddedCertificates = 10;

        /// <summary><c>Json.Parse</c>.</summary>
        internal static object? JsonParse(string text) => JsonParseCore(text, JsonMaxLength);

        /// <summary><c>Json.Write</c>.</summary>
        internal static string JsonWrite(object? value) => JsonWriteCore(value);

        /// <summary><c>CmsPreScan.Scan</c>.</summary>
        internal static int CmsPreScan(byte[] der, int limit) => CmsPreScanCore(der, limit);

        /// <summary>True when the exception is the reader's own typed failure.</summary>
        internal static bool IsJsonException(Exception e) =>
            string.Equals(e.GetType().FullName, JsonExceptionName, StringComparison.Ordinal);

        private static TDelegate Bind<TDelegate>(string type, string method)
            where TDelegate : Delegate
        {
            Type owner = Library.GetType("ApplePurchaseReceiptVerifier." + type, throwOnError: true)!;
            MethodInfo target = owner.GetMethod(method, BindingFlags.Static | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException($"{type}.{method} is not where this expects it");
            return (TDelegate)target.CreateDelegate(typeof(TDelegate));
        }
    }
}
