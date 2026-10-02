using System;
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

        /// <summary>
        /// The library's relaxed encoder: text is written as itself except for
        /// the quotation mark, the reverse solidus, the controls, and the
        /// characters the encoder still escapes (among them U+007F to U+009F,
        /// U+2028 and U+2029, private-use and unassigned code points, and every
        /// character outside the BMP, as a surrogate pair). A lone surrogate,
        /// which has no UTF-8 form, is written as <c>\uFFFD</c>. Before 0.8
        /// <see cref="ReceiptPayload.ToJson"/> escaped only the quotation mark,
        /// the reverse solidus and the controls; the text may differ from
        /// then, the value does not (the owner's decision of 2026-10-02, Q20).
        /// </summary>
        private static readonly JsonWriterOptions WriteOptions = new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

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
    }
}
