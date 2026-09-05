using System;
using System.Collections.Generic;
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

        /// <summary>
        /// The raw DER of the certificate the first SignerInfo <em>names</em> —
        /// its <c>issuerAndSerialNumber</c> matched against the certificate
        /// bag — or <see langword="null"/> when this pass cannot name one.
        /// Call it after <see cref="Scan"/>, whose structural verdict it does
        /// not repeat.
        /// </summary>
        /// <remarks>
        /// <para>It exists so the signer can be judged BEFORE the platform CMS
        /// decoder sees the blob. Materialising the bag is a platform call —
        /// on macOS it is Security.framework's certificate parser — and that
        /// parser refuses a certificate claiming an unknown X.509 version or
        /// carrying an extension value that does not decode. The receipt then
        /// comes out as INVALID_RECEIPT_FORMAT, a verdict about the blob,
        /// where every other host reaches the verdict about the certificate.
        /// Reading the bag here, with the same hand-written bounded walk as
        /// <see cref="Scan"/> and never through <c>X509Certificate2</c>, is
        /// what makes that verdict the same on every operating system.</para>
        /// <para>Returning <see langword="null"/> is not a verdict. A blob
        /// whose signer this cannot name — one identified by
        /// <c>subjectKeyIdentifier</c>, or a bag over the certificate bound —
        /// is left to the decoder and to the checks after it, exactly as
        /// before.</para>
        /// </remarks>
        internal static byte[]? FindSignerCertificate(byte[] der, int limit)
        {
            if (der is null || der.Length == 0)
            {
                return null;
            }

            Asn1Tag explicitContent = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            try
            {
                AsnReader contentInfo = new AsnReader(der, AsnEncodingRules.BER).ReadSequence();
                contentInfo.ReadObjectIdentifier();
                AsnReader signedData = contentInfo.ReadSequence(explicitContent).ReadSequence();
                signedData.ReadEncodedValue();      // version
                signedData.ReadEncodedValue();      // digestAlgorithms
                signedData.ReadEncodedValue();      // encapContentInfo

                if (!signedData.HasData || signedData.PeekTag() != explicitContent)
                {
                    return null;
                }

                List<byte[]> bag = new List<byte[]>();
                AsnReader certificates = signedData.ReadSetOf(skipSortOrderValidation: true, explicitContent);
                while (certificates.HasData)
                {
                    if (bag.Count == limit)
                    {
                        // Over the bound Scan counts. Its INVALID_CHAIN verdict
                        // owns that input, so nothing is decoded here.
                        return null;
                    }

                    bag.Add(certificates.ReadEncodedValue().ToArray());
                }

                Asn1Tag revocationInfo = new Asn1Tag(TagClass.ContextSpecific, 1, true);
                if (signedData.HasData && signedData.PeekTag() == revocationInfo)
                {
                    signedData.ReadEncodedValue();  // crls
                }

                if (!signedData.HasData)
                {
                    return null;
                }

                AsnReader signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
                if (!signerInfos.HasData)
                {
                    return null;
                }

                AsnReader signerInfo = signerInfos.ReadSequence();
                signerInfo.ReadEncodedValue();      // version
                if (!signerInfo.HasData || signerInfo.PeekTag() != Asn1Tag.Sequence)
                {
                    // SignerIdentifier ::= issuerAndSerialNumber | [0] subjectKeyIdentifier
                    return null;
                }

                AsnReader issuerAndSerial = signerInfo.ReadSequence();
                ReadOnlyMemory<byte> issuer = issuerAndSerial.ReadEncodedValue();
                ReadOnlyMemory<byte> serialNumber = issuerAndSerial.ReadEncodedValue();

                foreach (byte[] candidate in bag)
                {
                    if (Names(candidate, issuer.Span, serialNumber.Span))
                    {
                        return candidate;
                    }
                }

                return null;
            }
            catch (AsnContentException)
            {
                return null;
            }
        }

        /// <summary>
        /// Whether <paramref name="certificate"/> is the one an
        /// <c>issuerAndSerialNumber</c> names. Only the two fields that answer
        /// that are read, so a certificate this cannot otherwise parse is
        /// still recognised as the named one and still gets judged.
        /// </summary>
        private static bool Names(
            byte[] certificate, ReadOnlySpan<byte> issuer, ReadOnlySpan<byte> serialNumber)
        {
            try
            {
                AsnReader tbs = new AsnReader(certificate, AsnEncodingRules.DER)
                    .ReadSequence()
                    .ReadSequence();
                if (tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                {
                    tbs.ReadEncodedValue();         // version
                }

                ReadOnlyMemory<byte> candidateSerial = tbs.ReadEncodedValue();
                tbs.ReadEncodedValue();             // signature
                ReadOnlyMemory<byte> candidateIssuer = tbs.ReadEncodedValue();
                return ByteOps.SequenceEqual(candidateSerial.Span, serialNumber)
                    && ByteOps.SequenceEqual(candidateIssuer.Span, issuer);
            }
            catch (AsnContentException)
            {
                return false;
            }
        }

        private static VerificationException Malformed(string detail)
        {
            return new VerificationException(VerificationReason.InvalidReceiptFormat, detail);
        }
    }
}
