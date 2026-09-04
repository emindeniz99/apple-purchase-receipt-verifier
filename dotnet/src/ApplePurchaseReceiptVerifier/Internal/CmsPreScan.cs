using System;
using System.Formats.Asn1;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// A structural pass over the CMS blob, run before <c>SignedCms</c> sees
    /// anything: it rejects trailing bytes and counts the embedded
    /// certificates without decoding any of them.
    /// </summary>
    /// <remarks>
    /// <para>The obvious port of the bound — <c>if (cms.Certificates.Count &gt;
    /// 10)</c> — <em>is</em> the attack. <c>SignedCms.Decode</c> is lazy;
    /// touching <c>Certificates</c> is what materialises every embedded
    /// certificate. Measured on a synthetic flood built from
    /// <c>generated/receipt.der</c>: 6 000 certificates cost 1 045 ms on that
    /// property and 35 µs here, and the property also allocates 6 000
    /// handle-holding <c>X509Certificate2</c> objects for a receipt nothing
    /// has verified yet.</para>
    /// <para>Trailing bytes matter because <c>SignedCms</c> silently accepts
    /// them: <c>receipt.der</c> plus a megabyte of zeros decodes fine, which
    /// would let one blob carry two different meanings.</para>
    /// </remarks>
    internal static class CmsPreScan
    {
        private const string SignedDataOid = "1.2.840.113549.1.7.2";

        /// <summary>
        /// Verifies that <paramref name="der"/> is exactly one BER value and
        /// returns how many certificates the SignedData embeds, stopping as
        /// soon as the count exceeds <paramref name="limit"/>.
        /// </summary>
        /// <exception cref="VerificationException">
        /// The blob is not a single well-formed CMS SignedData value, or it
        /// carries trailing bytes.
        /// </exception>
        internal static int Scan(byte[] der, int limit)
        {
            if (der is null || der.Length == 0)
            {
                throw Malformed("receipt is empty");
            }

            try
            {
                AsnDecoder.ReadEncodedValue(der, AsnEncodingRules.BER, out _, out _, out int consumed);
                if (consumed != der.Length)
                {
                    throw Malformed("receipt has trailing bytes after the CMS blob");
                }

                AsnReader outer = new AsnReader(der, AsnEncodingRules.BER);
                AsnReader contentInfo = outer.ReadSequence();
                if (!string.Equals(contentInfo.ReadObjectIdentifier(), SignedDataOid, StringComparison.Ordinal))
                {
                    throw Malformed("not a CMS SignedData blob");
                }

                Asn1Tag explicitContent = new Asn1Tag(TagClass.ContextSpecific, 0, true);
                AsnReader signedData = contentInfo.ReadSequence(explicitContent).ReadSequence();
                signedData.ReadEncodedValue();          // version
                signedData.ReadEncodedValue();          // digestAlgorithms
                signedData.ReadEncodedValue();          // encapContentInfo

                if (!signedData.HasData || signedData.PeekTag() != explicitContent)
                {
                    return 0;
                }

                AsnReader certificates = signedData.ReadSetOf(skipSortOrderValidation: true, explicitContent);
                int count = 0;
                while (certificates.HasData)
                {
                    certificates.ReadEncodedValue();
                    count++;
                    if (count > limit)
                    {
                        return count;
                    }
                }

                return count;
            }
            catch (AsnContentException e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "not a parseable CMS blob", e);
            }
        }

        private static VerificationException Malformed(string detail)
        {
            return new VerificationException(VerificationReason.InvalidReceiptFormat, detail);
        }
    }
}
