using System.Formats.Asn1;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Bounds how deeply a BER/DER document nests constructed values (the
    /// design's Bounds table, "ASN.1 nesting depth", 32), applied to two
    /// documents parsed on their own: the CMS envelope from its ContentInfo,
    /// and the signed content from its attribute SET. The outermost
    /// constructed value counts as depth 1.
    /// </summary>
    internal static class Asn1Depth
    {
        internal const int MaxDepth = 32;

        /// <summary>Whether <paramref name="data"/>, read as one BER value, nests deeper than <paramref name="maxDepth"/>.</summary>
        /// <remarks>
        /// A document this cannot read at all (malformed length, trailing
        /// bytes inside a container) is reported as "not exceeding" — some
        /// other, more specific check owns that verdict; this function's only
        /// job is the depth bound.
        /// </remarks>
        internal static bool Exceeds(byte[] data, int maxDepth)
        {
            try
            {
                // The value in `data` is itself depth 1 ("the outermost one as
                // 1"), so counting starts at 0 for the pass that reads its own
                // tag/length and recurses into its content at depth 1.
                AsnReader reader = new AsnReader(data, AsnEncodingRules.BER);
                return !Walk(reader, 0, maxDepth);
            }
            catch (System.Exception)
            {
                return false;
            }
        }

        /// <summary>Walks one level, returning <see langword="false"/> the moment <paramref name="depth"/> exceeds <paramref name="maxDepth"/>.</summary>
        private static bool Walk(AsnReader reader, int depth, int maxDepth)
        {
            if (depth > maxDepth)
            {
                return false;
            }

            while (reader.HasData)
            {
                Asn1Tag tag = reader.PeekTag();

                // AsnReader.ReadSequence(Asn1Tag) insists a Universal-class
                // expected tag be the "correct" one for the read it performs
                // (16 for ReadSequence, 17 for ReadSetOf) — a plain
                // IsConstructed branch throws on every SET (CMS is full of
                // them: digestAlgorithms, certificates, signerInfos).
                // Context-specific and other non-universal constructed tags
                // (an EXPLICIT [n]) have no such restriction.
                if (tag.TagClass == TagClass.Universal && tag.IsConstructed && tag.TagValue == 16)
                {
                    if (!Walk(reader.ReadSequence(), depth + 1, maxDepth))
                    {
                        return false;
                    }
                }
                else if (tag.TagClass == TagClass.Universal && tag.IsConstructed && tag.TagValue == 17)
                {
                    if (!Walk(reader.ReadSetOf(skipSortOrderValidation: true), depth + 1, maxDepth))
                    {
                        return false;
                    }
                }
                else if (tag.TagClass != TagClass.Universal && tag.IsConstructed)
                {
                    if (!Walk(reader.ReadSequence(tag), depth + 1, maxDepth))
                    {
                        return false;
                    }
                }
                else
                {
                    reader.ReadEncodedValue();
                }
            }

            return true;
        }
    }
}
