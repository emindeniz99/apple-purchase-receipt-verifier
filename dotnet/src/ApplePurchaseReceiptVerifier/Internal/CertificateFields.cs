using System;
using System.Collections.Generic;
using System.Formats.Asn1;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The structural pieces of an X.509 certificate this library needs and
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/>
    /// does not expose portably: the exact <c>tbsCertificate</c> bytes the
    /// signature covers, the signature algorithm OID, the signature bits, the
    /// raw extension values, and the <c>CA</c> flag.
    /// </summary>
    /// <remarks>
    /// Read from the DER the caller handed us, not from a re-encoding: the
    /// bytes verified must be the bytes parsed. Extensions are read here rather
    /// than through <c>X509Certificate2.Extensions</c> because that property's
    /// behaviour on a malformed extension varies by platform, and this path
    /// takes attacker-controlled DER.
    /// </remarks>
    internal sealed class CertificateFields
    {
        private const string BasicConstraintsOid = "2.5.29.19";

        private CertificateFields(
            byte[] tbsCertificate,
            string signatureAlgorithmOid,
            string tbsSignatureAlgorithmOid,
            byte[] signature,
            IReadOnlyDictionary<string, byte[]> extensions,
            bool hasDuplicateExtension)
        {
            TbsCertificate = tbsCertificate;
            SignatureAlgorithmOid = signatureAlgorithmOid;
            TbsSignatureAlgorithmOid = tbsSignatureAlgorithmOid;
            Signature = signature;
            Extensions = extensions;
            HasDuplicateExtension = hasDuplicateExtension;
        }

        /// <summary>The exact encoded <c>tbsCertificate</c> the signature is over.</summary>
        internal byte[] TbsCertificate { get; }

        /// <summary>The outer <c>signatureAlgorithm</c> OID.</summary>
        internal string SignatureAlgorithmOid { get; }

        /// <summary>The <c>signature</c> AlgorithmIdentifier OID from inside the TBS.</summary>
        internal string TbsSignatureAlgorithmOid { get; }

        /// <summary>The raw signature bits.</summary>
        internal byte[] Signature { get; }

        /// <summary>Extension OID to raw <c>extnValue</c> octets. Duplicates keep the first.</summary>
        internal IReadOnlyDictionary<string, byte[]> Extensions { get; }

        /// <summary>
        /// Whether the certificate carries the same extension OID more than
        /// once, which RFC 5280 4.2 forbids. Recorded rather than acted on
        /// here: <see cref="Extensions"/> keeps the first copy, so every
        /// reader of this type would otherwise be answering from a copy it
        /// picked. The JWS path refuses such a certificate outright.
        /// </summary>
        internal bool HasDuplicateExtension { get; }

        /// <summary>Parses <paramref name="raw"/>, or returns <see langword="null"/> if it will not parse.</summary>
        internal static CertificateFields? TryParse(byte[] raw)
        {
            if (raw is null || raw.Length == 0)
            {
                return null;
            }

            try
            {
                AsnReader outer = new AsnReader(raw, AsnEncodingRules.DER);
                AsnReader certificate = outer.ReadSequence();
                if (outer.HasData)
                {
                    return null;
                }

                byte[] tbs = certificate.PeekEncodedValue().ToArray();
                AsnReader tbsReader = certificate.ReadSequence();
                string outerOid = ReadAlgorithmIdentifierOid(certificate);
                byte[] signature = certificate.ReadBitString(out int unusedBits);
                if (unusedBits != 0 || certificate.HasData)
                {
                    return null;
                }

                // TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1,
                //   serialNumber, signature, issuer, validity, subject,
                //   subjectPublicKeyInfo, [1] , [2] , [3] extensions }
                if (tbsReader.HasData && tbsReader.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                {
                    tbsReader.ReadEncodedValue();
                }

                tbsReader.ReadEncodedValue();                       // serialNumber
                string tbsOid = ReadAlgorithmIdentifierOid(tbsReader);
                tbsReader.ReadEncodedValue();                       // issuer
                tbsReader.ReadEncodedValue();                       // validity
                tbsReader.ReadEncodedValue();                       // subject
                tbsReader.ReadEncodedValue();                       // subjectPublicKeyInfo

                Dictionary<string, byte[]> extensions = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                bool duplicate = false;
                while (tbsReader.HasData)
                {
                    Asn1Tag tag = tbsReader.PeekTag();
                    if (tag.TagClass != TagClass.ContextSpecific)
                    {
                        return null;
                    }

                    if (tag.TagValue != 3)
                    {
                        tbsReader.ReadEncodedValue();               // issuer/subject unique id
                        continue;
                    }

                    duplicate |= ReadExtensions(tbsReader.ReadSequence(tag).ReadSequence(), extensions);
                }

                return new CertificateFields(tbs, outerOid, tbsOid, signature, extensions, duplicate);
            }
            catch (AsnContentException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <summary>The raw value of one extension, or <see langword="null"/> when absent.</summary>
        internal byte[]? Extension(string oid)
        {
            return Extensions.TryGetValue(oid, out byte[]? value) ? value : null;
        }

        /// <summary>Whether the certificate is marked as a CA by BasicConstraints.</summary>
        /// <remarks>A missing or unparseable extension is not a CA — fail closed.</remarks>
        internal bool IsCertificateAuthority()
        {
            byte[]? encoded = Extension(BasicConstraintsOid);
            if (encoded is null)
            {
                return false;
            }

            try
            {
                AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
                AsnReader constraints = reader.ReadSequence();
                if (reader.HasData)
                {
                    return false;
                }

                // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
                //                                 pathLenConstraint INTEGER OPTIONAL }
                return constraints.HasData
                    && constraints.PeekTag() == Asn1Tag.Boolean
                    && constraints.ReadBoolean();
            }
            catch (AsnContentException)
            {
                return false;
            }
        }

        /// <summary>Reads the extension list; returns whether an OID repeated.</summary>
        private static bool ReadExtensions(AsnReader sequence, Dictionary<string, byte[]> into)
        {
            bool duplicate = false;
            while (sequence.HasData)
            {
                AsnReader extension = sequence.ReadSequence();
                string oid = extension.ReadObjectIdentifier();
                if (extension.HasData && extension.PeekTag() == Asn1Tag.Boolean)
                {
                    extension.ReadBoolean();
                }

                byte[] value = extension.ReadOctetString();
                if (into.ContainsKey(oid))
                {
                    duplicate = true;
                    continue;
                }

                into.Add(oid, value);
            }

            return duplicate;
        }

        private static string ReadAlgorithmIdentifierOid(AsnReader reader)
        {
            AsnReader algorithm = reader.ReadSequence();
            return algorithm.ReadObjectIdentifier();
        }
    }
}
