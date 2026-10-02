using System;
using System.Reflection;
using System.Text.Json;

namespace ApplePurchaseReceiptVerifier.Fuzz
{
    /// <summary>
    /// Reflected access to the internal JSON writer and reader a fuzz target
    /// reaches directly (<c>Internal.Json</c>).
    /// </summary>
    /// <remarks>
    /// <para>Reflection rather than an <c>InternalsVisibleTo</c> entry: the
    /// library assembly is what ships, and this project exists to test it, not
    /// to change it. The delegates are bound once at startup, so the reflection
    /// costs nothing per execution and — because it is the library's own IL
    /// that runs — SharpFuzz's instrumentation of that assembly still reports
    /// the coverage.</para>
    /// </remarks>
    internal static class Internals
    {
        private static readonly Assembly Library = typeof(IVerifier).Assembly;

        private static readonly Func<string, JsonDocument> JsonParseCore =
            Bind<Func<string, JsonDocument>>("Internal.Json", "Parse");

        private static readonly Func<Action<Utf8JsonWriter>, string> JsonWriteCore =
            Bind<Func<Action<Utf8JsonWriter>, string>>("Internal.Json", "Write");

        /// <summary>The certificate bound the receipt path enforces (<c>Internal.Cms.MaxEmbeddedCertificates</c>).</summary>
        internal const int MaxEmbeddedCertificates = 10;

        /// <summary><c>Json.Parse</c>: the options the module's answers are read with.</summary>
        internal static JsonDocument JsonParse(string text) => JsonParseCore(text);

        /// <summary><c>Json.Write</c>: the options <c>ReceiptPayload.ToJson</c> is written with.</summary>
        internal static string JsonWrite(Action<Utf8JsonWriter> write) => JsonWriteCore(write);

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
