using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>One CMS/PKCS#7 SignerInfo's structural fields, undecoded beyond ASN.1 structure.</summary>
    internal sealed class CmsSignerInfo
    {
        /// <summary>The <c>issuerAndSerialNumber.issuer</c> field, tag and length included; <see langword="null"/> for the <c>subjectKeyIdentifier</c> form, which this library cannot name a certificate from.</summary>
        internal byte[]? IssuerRaw { get; set; }

        /// <summary>The <c>issuerAndSerialNumber.serialNumber</c> field, tag and length included.</summary>
        internal byte[]? SerialRaw { get; set; }

        internal string DigestAlgorithmOid { get; set; } = string.Empty;

        /// <summary>
        /// The original <c>[0] IMPLICIT SET OF Attribute</c> TLV bytes (tag
        /// <c>0xA0</c>), or <see langword="null"/> when signedAttrs is absent.
        /// </summary>
        internal byte[]? SignedAttrsRaw { get; set; }

        internal string SignatureAlgorithmOid { get; set; } = string.Empty;

        internal byte[]? SignatureAlgorithmParams { get; set; }

        internal byte[] Signature { get; set; } = Array.Empty<byte>();
    }

    /// <summary>The structural pieces of a CMS SignedData this library needs.</summary>
    internal sealed class CmsParsed
    {
        internal string ContentTypeOid { get; set; } = string.Empty;

        /// <summary>The <c>encapContentInfo.eContent</c> OCTET STRING's value bytes.</summary>
        internal byte[] Content { get; set; } = Array.Empty<byte>();

        /// <summary>Raw DER/BER of each embedded certificate, bag order, undecoded.</summary>
        internal List<byte[]> CertificateEntries { get; } = new List<byte[]>();

        internal List<CmsSignerInfo> SignerInfos { get; } = new List<CmsSignerInfo>();
    }

    /// <summary>What a SignerInfo's signedAttrs say about the content, once extracted.</summary>
    internal sealed class SignedAttributesInfo
    {
        internal string? ContentTypeOid { get; set; }

        internal bool DuplicateContentType { get; set; }

        internal byte[]? MessageDigest { get; set; }

        internal bool DuplicateMessageDigest { get; set; }

        /// <summary>
        /// The bytes the signature actually covers: the original signedAttrs
        /// content re-tagged from <c>[0] IMPLICIT</c> to a universal
        /// <c>SET OF</c> (RFC 5652 §5.4) — same length and content bytes, only
        /// the leading tag octet changes.
        /// </summary>
        internal byte[] SignedBytes { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// A structural, hand-rolled CMS/PKCS#7 SignedData reader — deliberately
    /// not <c>System.Security.Cryptography.Pkcs.SignedCms</c>, which checks
    /// every signer by default and offers no seam for the several-embedded-
    /// certificates-name-one-signer bag-order rule the design requires.
    /// </summary>
    internal static class Cms
    {
        private const string SignedDataOid = "1.2.840.113549.1.7.2";
        private const string ContentTypeAttrOid = "1.2.840.113549.1.9.3";
        private const string MessageDigestAttrOid = "1.2.840.113549.1.9.4";

        internal const int MaxEmbeddedCertificates = 10;
        internal const int MaxSignerInfos = 4;

        private static readonly Asn1Tag ExplicitContext0 = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        private static readonly Asn1Tag ExplicitContext1 = new Asn1Tag(TagClass.ContextSpecific, 1, true);

        /// <summary>Parses a ContentInfo/SignedData blob. Every failure is a <see cref="VerificationReason.Malformed"/> <see cref="VerificationException"/>.</summary>
        internal static CmsParsed Parse(byte[] der)
        {
            if (der is null || der.Length == 0)
            {
                throw Malformed("receipt is empty");
            }

            if (Asn1Depth.Exceeds(der, Asn1Depth.MaxDepth))
            {
                throw Malformed("CMS envelope nests deeper than the maximum depth");
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
                if (outer.HasData
                    || !string.Equals(contentInfo.ReadObjectIdentifier(), SignedDataOid, StringComparison.Ordinal)
                    || !contentInfo.HasData
                    || contentInfo.PeekTag() != ExplicitContext0)
                {
                    throw Malformed("not a CMS SignedData blob");
                }

                AsnReader signedData = contentInfo.ReadSequence(ExplicitContext0).ReadSequence();
                signedData.ReadEncodedValue();          // version
                signedData.ReadEncodedValue();          // digestAlgorithms

                AsnReader encapContentInfo = signedData.ReadSequence();
                string contentTypeOid = encapContentInfo.ReadObjectIdentifier();
                byte[]? content = null;
                if (encapContentInfo.HasData && encapContentInfo.PeekTag() == ExplicitContext0)
                {
                    AsnReader eContentWrap = encapContentInfo.ReadSequence(ExplicitContext0);
                    content = eContentWrap.ReadOctetString();
                }

                if (content is null)
                {
                    throw Malformed("no encapsulated payload");
                }

                List<byte[]> certificateEntries = new List<byte[]>();
                if (signedData.HasData && signedData.PeekTag() == ExplicitContext0)
                {
                    AsnReader certificates = signedData.ReadSetOf(skipSortOrderValidation: true, ExplicitContext0);
                    while (certificates.HasData)
                    {
                        if (certificateEntries.Count == MaxEmbeddedCertificates)
                        {
                            throw Malformed(
                                "receipt embeds more than "
                                + MaxEmbeddedCertificates.ToString(CultureInfo.InvariantCulture) + " certificates");
                        }

                        certificateEntries.Add(certificates.ReadEncodedValue().ToArray());
                    }
                }

                if (signedData.HasData && signedData.PeekTag() == ExplicitContext1)
                {
                    signedData.ReadEncodedValue();      // crls, ignored
                }

                if (!signedData.HasData)
                {
                    throw Malformed("no signer info");
                }

                AsnReader signerInfoSet = signedData.ReadSetOf(skipSortOrderValidation: true);
                List<CmsSignerInfo> signerInfos = new List<CmsSignerInfo>();
                while (signerInfoSet.HasData)
                {
                    if (signerInfos.Count == MaxSignerInfos)
                    {
                        throw Malformed(
                            "receipt carries more than "
                            + MaxSignerInfos.ToString(CultureInfo.InvariantCulture) + " SignerInfos");
                    }

                    signerInfos.Add(ReadSignerInfo(signerInfoSet.ReadSequence()));
                }

                if (signerInfos.Count == 0)
                {
                    throw Malformed("no signer info");
                }

                CmsParsed parsed = new CmsParsed { ContentTypeOid = contentTypeOid, Content = content };
                parsed.CertificateEntries.AddRange(certificateEntries);
                parsed.SignerInfos.AddRange(signerInfos);
                return parsed;
            }
            catch (AsnContentException e)
            {
                throw Malformed("not a parseable CMS blob", e);
            }
        }

        private static CmsSignerInfo ReadSignerInfo(AsnReader signerInfo)
        {
            signerInfo.ReadEncodedValue();              // version

            byte[]? issuerRaw = null;
            byte[]? serialRaw = null;
            if (signerInfo.HasData && signerInfo.PeekTag() == Asn1Tag.Sequence)
            {
                AsnReader sid = signerInfo.ReadSequence();
                issuerRaw = sid.ReadEncodedValue().ToArray();
                serialRaw = sid.ReadEncodedValue().ToArray();
            }
            else
            {
                signerInfo.ReadEncodedValue();          // [0] subjectKeyIdentifier form
            }

            AsnReader digestAlgorithm = signerInfo.ReadSequence();
            string digestOid = digestAlgorithm.ReadObjectIdentifier();

            byte[]? signedAttrsRaw = null;
            if (signerInfo.HasData && signerInfo.PeekTag() == ExplicitContext0)
            {
                signedAttrsRaw = signerInfo.PeekEncodedValue().ToArray();
                signerInfo.ReadEncodedValue();
            }

            AsnReader signatureAlgorithm = signerInfo.ReadSequence();
            string signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();
            byte[]? signatureAlgorithmParams =
                signatureAlgorithm.HasData ? signatureAlgorithm.ReadEncodedValue().ToArray() : null;

            byte[] signature = signerInfo.ReadOctetString();

            // unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL — ignored:
            // nothing this library reads is carried there.

            return new CmsSignerInfo
            {
                IssuerRaw = issuerRaw,
                SerialRaw = serialRaw,
                DigestAlgorithmOid = digestOid,
                SignedAttrsRaw = signedAttrsRaw,
                SignatureAlgorithmOid = signatureAlgorithmOid,
                SignatureAlgorithmParams = signatureAlgorithmParams,
                Signature = signature,
            };
        }

        /// <summary>
        /// Validates that <paramref name="signedAttrsRaw"/> is a well-formed
        /// <c>SET OF Attribute</c> — every entry a SEQUENCE of an OID and a
        /// non-empty SET of values, nothing left over. Called for every
        /// SignerInfo before any key is used, so a malformed signedAttrs is
        /// MALFORMED regardless of signer order.
        /// </summary>
        internal static void RequireAttributeSetSyntax(byte[] signedAttrsRaw)
        {
            try
            {
                ReadAttributes(signedAttrsRaw);
            }
            catch (AsnContentException e)
            {
                throw Malformed("signedAttrs is not a well-formed attribute set", e);
            }
        }

        /// <summary>
        /// Reads the <c>contentType</c> and <c>messageDigest</c> attributes out
        /// of an already syntax-checked signedAttrs, and the bytes the
        /// signature covers.
        /// </summary>
        internal static SignedAttributesInfo ExtractSignedAttributes(byte[] signedAttrsRaw)
        {
            List<(string Oid, byte[] ValuesRaw)> attributes;
            try
            {
                attributes = ReadAttributes(signedAttrsRaw);
            }
            catch (AsnContentException e)
            {
                throw Malformed("signedAttrs is not a well-formed attribute set", e);
            }

            SignedAttributesInfo info = new SignedAttributesInfo();
            int contentTypeCount = 0;
            int messageDigestCount = 0;
            foreach ((string oid, byte[] valuesRaw) in attributes)
            {
                if (string.Equals(oid, ContentTypeAttrOid, StringComparison.Ordinal))
                {
                    contentTypeCount++;
                    if (contentTypeCount == 1)
                    {
                        info.ContentTypeOid = TryReadFirstOid(valuesRaw);
                    }
                }
                else if (string.Equals(oid, MessageDigestAttrOid, StringComparison.Ordinal))
                {
                    messageDigestCount++;
                    if (messageDigestCount == 1)
                    {
                        info.MessageDigest = TryReadFirstOctetString(valuesRaw);
                    }
                }
            }

            info.DuplicateContentType = contentTypeCount > 1;
            info.DuplicateMessageDigest = messageDigestCount > 1;

            byte[] retagged = (byte[])signedAttrsRaw.Clone();
            retagged[0] = 0x31; // universal SET OF, constructed — was [0] IMPLICIT (0xA0).
            info.SignedBytes = retagged;
            return info;
        }

        private static List<(string Oid, byte[] ValuesRaw)> ReadAttributes(byte[] signedAttrsRaw)
        {
            List<(string, byte[])> result = new List<(string, byte[])>();
            AsnReader outer = new AsnReader(signedAttrsRaw, AsnEncodingRules.BER);
            AsnReader set = outer.ReadSequence(ExplicitContext0);
            if (outer.HasData)
            {
                throw new AsnContentException("trailing data after signedAttrs");
            }

            while (set.HasData)
            {
                AsnReader attribute = set.ReadSequence();
                string oid = attribute.ReadObjectIdentifier();
                if (!attribute.HasData || attribute.PeekTag() != Asn1Tag.SetOf)
                {
                    throw new AsnContentException("attribute has no values SET");
                }

                byte[] valuesRaw = attribute.ReadEncodedValue().ToArray();
                if (attribute.HasData)
                {
                    throw new AsnContentException("attribute has trailing data");
                }

                AsnReader values = new AsnReader(valuesRaw, AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
                if (!values.HasData)
                {
                    throw new AsnContentException("attribute values SET is empty");
                }

                result.Add((oid, valuesRaw));
            }

            return result;
        }

        private static string? TryReadFirstOid(byte[] valuesRaw)
        {
            try
            {
                AsnReader values = new AsnReader(valuesRaw, AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
                return values.HasData ? values.ReadObjectIdentifier() : null;
            }
            catch (AsnContentException)
            {
                return null;
            }
        }

        private static byte[]? TryReadFirstOctetString(byte[] valuesRaw)
        {
            try
            {
                AsnReader values = new AsnReader(valuesRaw, AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
                return values.HasData ? values.ReadOctetString() : null;
            }
            catch (AsnContentException)
            {
                return null;
            }
        }

        private static VerificationException Malformed(string detail, Exception? cause = null) =>
            new VerificationException(VerificationReason.Malformed, detail, cause);
    }
}
