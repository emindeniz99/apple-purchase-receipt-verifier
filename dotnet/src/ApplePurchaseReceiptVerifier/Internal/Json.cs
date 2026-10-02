using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The options this package reads and writes JSON with, over
    /// <c>System.Text.Json</c>: <see cref="JsonDocument"/> to read the module's
    /// answers and <see cref="Utf8JsonWriter"/> to write
    /// <see cref="ReceiptPayload.ToJson"/>. No reflection serializer, so the
    /// code survives trimming and IL2CPP stripping.
    /// </summary>
    /// <remarks>
    /// <c>System.Text.Json</c> is in the box from net8.0; the netstandard2.0
    /// asset takes it as a package (the owner's decision of 2026-10-02; see
    /// docs/rust-core/DECISIONS.md R41).
    /// </remarks>
    internal static class Json
    {
        /// <summary>
        /// How many arrays and objects may be open at once when reading. The
        /// deepest answer the module gives is six levels (the answer, its
        /// receipt payload, <c>in_app</c>, a purchase, its
        /// <c>unknown_attributes</c>, one type's values). A verified JWS
        /// payload, which the core accepts at any depth (DECISIONS.md R40),
        /// arrives in the answer as a JSON string, so its nesting never meets
        /// this bound. Set rather than left at <c>JsonDocument</c>'s default
        /// of 64 so the number is visible and has room; an answer deeper than
        /// six levels is refused by its shape anyway.
        /// </summary>
        internal const int MaxDepth = 128;

        private static readonly JsonDocumentOptions ReadOptions = new JsonDocumentOptions { MaxDepth = MaxDepth };

        private static readonly JsonWriterOptions WriteOptions = new JsonWriterOptions { Encoder = MinimalEscaping.Instance };

        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

        /// <summary>Parses one JSON document; trailing content, comments and trailing commas are errors.</summary>
        /// <exception cref="JsonException">The text is not one JSON document within <see cref="MaxDepth"/>.</exception>
        internal static JsonDocument Parse(string json) => JsonDocument.Parse(json, ReadOptions);

        /// <summary>Runs <paramref name="write"/> over a writer and returns what it wrote.</summary>
        internal static string Write(Action<Utf8JsonWriter> write)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(stream, WriteOptions))
                {
                    write(writer);
                }

                return Utf8.GetString(stream.GetBuffer(), 0, checked((int)stream.Length));
            }
        }

        /// <summary>Writes the member <paramref name="name"/> as <paramref name="value"/>, or <c>null</c>.</summary>
        internal static void WriteNumberOrNull(Utf8JsonWriter writer, string name, long? value)
        {
            if (value is long number)
            {
                writer.WriteNumber(name, number);
            }
            else
            {
                writer.WriteNull(name);
            }
        }

        /// <summary>Writes the member <paramref name="name"/> as <paramref name="value"/>, or <c>null</c>.</summary>
        internal static void WriteBooleanOrNull(Utf8JsonWriter writer, string name, bool? value)
        {
            if (value is bool flag)
            {
                writer.WriteBoolean(name, flag);
            }
            else
            {
                writer.WriteNull(name);
            }
        }

        /// <summary>
        /// Escapes what RFC 8259 requires and nothing else: the quotation
        /// mark, the reverse solidus and the controls below U+0020 (as
        /// <c>\b</c>, <c>\f</c>, <c>\n</c>, <c>\r</c>, <c>\t</c>, or
        /// <c>\u00xx</c> in lower case). Every other character, non-ASCII and
        /// outside the BMP included, is written as itself.
        /// </summary>
        /// <remarks>
        /// <para>This is the escaping <see cref="ReceiptPayload.ToJson"/> had
        /// before 0.8 wrote it with <c>System.Text.Json</c>, kept so its
        /// output stays byte for byte what it was. The encoders the library
        /// ships do not give it: even <c>UnsafeRelaxedJsonEscaping</c> writes
        /// its hex in upper case and escapes U+007F to U+009F, U+2028 and
        /// U+2029, U+FEFF, private-use, unassigned and noncharacter code
        /// points, and every character outside the BMP.</para>
        /// <para>A lone surrogate cannot be written as UTF-8 at all, and
        /// <c>Utf8JsonWriter</c> throws on one it is not told to escape. It is
        /// reported here, and the base encoder replaces it with U+FFFD. Only a
        /// payload built by hand can hold one: the module's strings are
        /// Rust strings.</para>
        /// </remarks>
        private sealed class MinimalEscaping : JavaScriptEncoder
        {
            internal static readonly MinimalEscaping Instance = new MinimalEscaping();

            /// <summary><c>\u001f</c> is the longest escape.</summary>
            public override int MaxOutputCharactersPerInputCharacter => 6;

            public override bool WillEncode(int unicodeScalar) =>
                unicodeScalar < 0x20 || unicodeScalar == '"' || unicodeScalar == '\\';

            public override unsafe int FindFirstCharacterToEncode(char* text, int textLength)
            {
                for (int i = 0; i < textLength; i++)
                {
                    char c = text[i];
                    if (c < 0x20 || c == '"' || c == '\\')
                    {
                        return i;
                    }

                    if (char.IsHighSurrogate(c) && i + 1 < textLength && char.IsLowSurrogate(text[i + 1]))
                    {
                        i++;
                    }
                    else if (char.IsSurrogate(c))
                    {
                        return i;
                    }
                }

                return -1;
            }

            public override unsafe bool TryEncodeUnicodeScalar(
                int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
            {
                string text = unicodeScalar switch
                {
                    '"' => "\\\"",
                    '\\' => "\\\\",
                    '\b' => "\\b",
                    '\f' => "\\f",
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    < 0x20 => "\\u" + unicodeScalar.ToString("x4", CultureInfo.InvariantCulture),
                    _ => char.ConvertFromUtf32(unicodeScalar),
                };

                if (text.Length > bufferLength)
                {
                    numberOfCharactersWritten = 0;
                    return false;
                }

                for (int i = 0; i < text.Length; i++)
                {
                    buffer[i] = text[i];
                }

                numberOfCharactersWritten = text.Length;
                return true;
            }
        }
    }
}
