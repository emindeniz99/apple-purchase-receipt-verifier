namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Measures a <see cref="string"/> in UTF-8 bytes without encoding it. The
    /// input limits are Apple's, and Apple counts the bytes on the wire: a .NET
    /// string holds UTF-16 code units, so <see cref="string.Length"/>
    /// under-counts any character above U+007F.
    /// </summary>
    /// <remarks>
    /// <para>Two shortcuts decide almost every call without looking at a
    /// character. Every UTF-16 unit costs at least one byte, so more units than
    /// the limit is over it. Every unit costs at most three bytes (a surrogate
    /// pair is two units and four bytes), so three times the units within the
    /// limit is within it. Only a string between those two bounds is walked,
    /// and the walk stops as soon as the count passes the limit, which
    /// <c>Encoding.UTF8.GetByteCount</c> cannot do.</para>
    /// <para>A lone surrogate counts as three bytes, the same as
    /// <c>Encoding.UTF8</c>, which replaces it with U+FFFD. It cannot arrive
    /// from the wire, where a decoder already turned invalid bytes into
    /// U+FFFD. The shared conformance vectors carry none.</para>
    /// </remarks>
    internal static class Utf8Length
    {
        /// <summary>Whether <paramref name="text"/> takes more than <paramref name="limit"/> bytes as UTF-8.</summary>
        internal static bool Exceeds(string text, int limit)
        {
            int units = text.Length;
            if (units > limit)
            {
                return true;
            }

            if (units * 3L <= limit)
            {
                return false;
            }

            long bytes = 0;
            for (int i = 0; i < units; i++)
            {
                char c = text[i];
                if (c < 0x80)
                {
                    bytes += 1;
                }
                else if (c < 0x800)
                {
                    bytes += 2;
                }
                else if (char.IsHighSurrogate(c) && i + 1 < units && char.IsLowSurrogate(text[i + 1]))
                {
                    bytes += 4;
                    i++;
                }
                else
                {
                    bytes += 3;
                }

                if (bytes > limit)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
