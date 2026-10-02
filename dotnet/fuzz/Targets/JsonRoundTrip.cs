using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The JSON writer's escaping (<c>Internal/Json.cs</c>), the one piece of
    /// JSON code the package still carries: a <c>JavaScriptEncoder</c> over
    /// char pointers that keeps <c>ReceiptPayload.ToJson</c>'s bytes what
    /// they were before <c>System.Text.Json</c>.
    /// </summary>
    /// <remarks>
    /// <para>The input is a string: the bytes as UTF-8 when they are valid
    /// UTF-8, so the JSON seeds bring quotes, backslashes and controls, and
    /// otherwise the bytes as UTF-16 code units, which is how the fuzzer
    /// reaches lone surrogates. Two invariants:</para>
    /// <list type="number">
    ///   <item><c>Json.Write</c> writes any string without throwing;</item>
    ///   <item><c>Json.Parse</c> reads what it wrote back to the same string,
    ///   with each lone surrogate replaced by U+FFFD, the one character the
    ///   writer cannot carry. A wrong escape, a missed control or a split
    ///   surrogate pair fails here.</item>
    /// </list>
    /// </remarks>
    internal static class JsonRoundTrip
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private static readonly UTF8Encoding LenientUtf8 = new UTF8Encoding(false, false);

        internal static void Run(ReadOnlySpan<byte> data)
        {
            string text;
            try
            {
                text = StrictUtf8.GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                text = new string(MemoryMarshal.Cast<byte, char>(data.Slice(0, data.Length & ~1)));
            }

            string written;
            try
            {
                written = Internals.JsonWrite(json => json.WriteStringValue(text));
            }
            catch (Exception e)
            {
                throw new InvariantException($"Json.Write threw {e.GetType().FullName}: {e.Message}");
            }

            string? reread;
            try
            {
                using (JsonDocument document = Internals.JsonParse(written))
                {
                    reread = document.RootElement.GetString();
                }
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"Json.Parse refused what Json.Write emitted ({e.GetType().FullName}: {e.Message})");
            }

            // UTF8Encoding's replacement fallback turns each lone surrogate
            // into U+FFFD and leaves everything else as it is.
            string expected = LenientUtf8.GetString(LenientUtf8.GetBytes(text));
            Invariant.Require(
                string.Equals(expected, reread, StringComparison.Ordinal),
                "the writer and the reader disagree on a string");
        }
    }
}
