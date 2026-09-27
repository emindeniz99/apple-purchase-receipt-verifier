using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Every signature scheme this library verifies under, with no allowlist
    /// beyond what the .NET crypto stack itself implements (#160, owner
    /// 2026-09-27): whatever <see cref="RSA"/> and
    /// <see cref="ECDsa"/> can check is accepted, on a certificate a pinned
    /// chain has already vouched for, or a CMS SignerInfo whose signer
    /// certificate has.
    /// </summary>
    /// <remarks>
    /// One .NET-specific gap: the BCL has no SHA-224 implementation at all (not
    /// even as a bare hash), so <c>sha224WithRSAEncryption</c>,
    /// <c>ecdsa-with-SHA224</c> and a SHA-224 CMS digest do not verify here —
    /// not a policy choice, a platform limitation, same as Q14's "whatever the
    /// port's library verifies".
    /// </remarks>
    internal static class SignatureAlgorithms
    {
        private const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
        private const string EcPublicKeyOid = "1.2.840.10045.2.1";
        private const string RsaPssOid = "1.2.840.113549.1.1.10";
        private const string Mgf1Oid = "1.2.840.113549.1.1.8";

        internal enum Kind
        {
            RsaPkcs1,
            RsaPss,
            Ecdsa,
        }

        internal readonly struct Scheme
        {
            internal Scheme(Kind kind, HashAlgorithmName hash)
            {
                Kind = kind;
                Hash = hash;
            }

            internal Kind Kind { get; }

            internal HashAlgorithmName Hash { get; }
        }

        /// <summary>A CMS/PKCS#7 digestAlgorithm or PSS hashAlgorithm OID to a hash this platform implements.</summary>
        internal static HashAlgorithmName? DigestOidToHash(string oid)
        {
            switch (oid)
            {
                case "1.3.14.3.2.26": return HashAlgorithmName.SHA1;
                case "2.16.840.1.101.3.4.2.1": return HashAlgorithmName.SHA256;
                case "2.16.840.1.101.3.4.2.2": return HashAlgorithmName.SHA384;
                case "2.16.840.1.101.3.4.2.3": return HashAlgorithmName.SHA512;
                case "1.2.840.113549.2.5": return HashAlgorithmName.MD5;
                default: return null;
            }
        }

        /// <summary>
        /// The scheme a certificate or SignerInfo <c>signatureAlgorithm</c>
        /// OID names, or <see langword="null"/> when the OID is unrecognised,
        /// or (for RSASSA-PSS) its parameters do not decode or name an
        /// unimplemented hash. <paramref name="parameters"/> is the raw
        /// AlgorithmIdentifier <c>parameters</c> field, needed only for PSS.
        /// </summary>
        internal static Scheme? Named(string oid, byte[]? parameters)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.4": return new Scheme(Kind.RsaPkcs1, HashAlgorithmName.MD5);
                case "1.2.840.113549.1.1.5": return new Scheme(Kind.RsaPkcs1, HashAlgorithmName.SHA1);
                case "1.2.840.113549.1.1.11": return new Scheme(Kind.RsaPkcs1, HashAlgorithmName.SHA256);
                case "1.2.840.113549.1.1.12": return new Scheme(Kind.RsaPkcs1, HashAlgorithmName.SHA384);
                case "1.2.840.113549.1.1.13": return new Scheme(Kind.RsaPkcs1, HashAlgorithmName.SHA512);
                case "1.2.840.10045.4.1": return new Scheme(Kind.Ecdsa, HashAlgorithmName.SHA1);
                case "1.2.840.10045.4.3.2": return new Scheme(Kind.Ecdsa, HashAlgorithmName.SHA256);
                case "1.2.840.10045.4.3.3": return new Scheme(Kind.Ecdsa, HashAlgorithmName.SHA384);
                case "1.2.840.10045.4.3.4": return new Scheme(Kind.Ecdsa, HashAlgorithmName.SHA512);
                case RsaPssOid: return ParsePss(parameters);
                default: return null;
            }
        }

        /// <summary>Whether <paramref name="oid"/> is the RSASSA-PSS algorithm OID.</summary>
        internal static bool IsRsaPss(string oid) => string.Equals(oid, RsaPssOid, StringComparison.Ordinal);

        /// <summary>
        /// A certificate signature: <paramref name="subject"/>'s
        /// <c>tbsCertificate</c> bytes and <c>signature</c> bits, checked under
        /// <paramref name="subject"/>'s own <c>signatureAlgorithm</c>, with
        /// <paramref name="issuer"/>'s public key. No allowlist and no
        /// requirement that the inner TBS <c>signature</c> AlgorithmIdentifier
        /// match the outer one (Q14, owner 2026-09-27): only the outer
        /// algorithm decides how the bytes are checked.
        /// </summary>
        internal static bool VerifyCertificateSignature(CertificateFields subject, X509Certificate2 issuer)
        {
            Scheme? scheme = Named(subject.SignatureAlgorithmOid, subject.SignatureAlgorithmParams);
            return scheme is Scheme s && Verify(s, issuer, subject.TbsCertificate, subject.Signature);
        }

        /// <summary>
        /// A CMS SignerInfo signature. <paramref name="signatureAlgorithmOid"/>
        /// and <paramref name="signatureAlgorithmParams"/> come from the
        /// SignerInfo's own <c>signatureAlgorithm</c>; when it names a hash
        /// (an explicit <c>sha256WithRSAEncryption</c>, an ECDSA OID, or PSS
        /// parameters) that hash must equal <paramref name="digestOid"/> or the
        /// signature is refused — a label that disagrees with what was hashed
        /// is not one signature under two names. <c>rsaEncryption</c>,
        /// <c>id-ecPublicKey</c> and any OID this cannot otherwise name take
        /// the digest and the signer's own key type.
        /// </summary>
        internal static bool VerifySignerSignature(
            X509Certificate2 signer,
            string? signerPublicKeyAlgorithmOid,
            string digestOid,
            string signatureAlgorithmOid,
            byte[]? signatureAlgorithmParams,
            byte[] signature,
            byte[] signedBytes)
        {
            HashAlgorithmName? digest = DigestOidToHash(digestOid);
            if (digest is null)
            {
                return false;
            }

            Scheme? named = Named(signatureAlgorithmOid, signatureAlgorithmParams);
            if (IsRsaPss(signatureAlgorithmOid) && named is null)
            {
                // PSS named itself but its parameters did not decode.
                return false;
            }

            if (named is Scheme namedScheme)
            {
                if (namedScheme.Hash != digest.Value)
                {
                    return false;
                }

                if (namedScheme.Kind == Kind.RsaPss)
                {
                    return Verify(namedScheme, signer, signedBytes, signature);
                }
            }

            Scheme scheme;
            if (string.Equals(signerPublicKeyAlgorithmOid, RsaEncryptionOid, StringComparison.Ordinal))
            {
                scheme = new Scheme(Kind.RsaPkcs1, digest.Value);
            }
            else if (string.Equals(signerPublicKeyAlgorithmOid, EcPublicKeyOid, StringComparison.Ordinal))
            {
                scheme = new Scheme(Kind.Ecdsa, digest.Value);
            }
            else
            {
                return false;
            }

            return Verify(scheme, signer, signedBytes, signature);
        }

        private static bool Verify(Scheme scheme, X509Certificate2 key, byte[] signedBytes, byte[] signature)
        {
            try
            {
                switch (scheme.Kind)
                {
                    case Kind.RsaPkcs1:
                        using (RSA? rsa = key.GetRSAPublicKey())
                        {
                            return rsa is not null
                                && rsa.VerifyData(signedBytes, signature, scheme.Hash, RSASignaturePadding.Pkcs1);
                        }

                    case Kind.RsaPss:
                        using (RSA? rsa = key.GetRSAPublicKey())
                        {
                            return rsa is not null
                                && rsa.VerifyData(signedBytes, signature, scheme.Hash, RSASignaturePadding.Pss);
                        }

                    case Kind.Ecdsa:
                        using (ECDsa? ec = key.GetECDsaPublicKey())
                        {
                            if (ec is null)
                            {
                                return false;
                            }

                            byte[]? p1363 = EcdsaSignatureFormat.DerToP1363(signature, (ec.KeySize + 7) / 8);
                            return p1363 is not null && ec.VerifyData(signedBytes, p1363, scheme.Hash);
                        }

                    default:
                        return false;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>
        /// RSASSA-PSS-params (RFC 4055 §3.1): the hash, MGF1 over that same
        /// hash (the only mask .NET implements), the salt length and the
        /// trailer field, each with its DEFAULT when absent. The salt length
        /// is parsed only to validate the encoding; .NET's PSS verifier always
        /// uses a salt as long as the digest, the near-universal convention, so
        /// a non-default salt length here fails to verify rather than being
        /// rejected up front.
        /// </summary>
        private static Scheme? ParsePss(byte[]? parameters)
        {
            if (parameters is null)
            {
                return new Scheme(Kind.RsaPss, HashAlgorithmName.SHA1);
            }

            try
            {
                AsnReader reader = new AsnReader(parameters, AsnEncodingRules.DER);
                AsnReader sequence = reader.ReadSequence();
                if (reader.HasData)
                {
                    return null;
                }

                HashAlgorithmName digest = HashAlgorithmName.SHA1;
                HashAlgorithmName maskDigest = HashAlgorithmName.SHA1;
                int lastTagValue = -1;
                while (sequence.HasData)
                {
                    Asn1Tag tag = sequence.PeekTag();
                    if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue <= lastTagValue)
                    {
                        return null;
                    }

                    lastTagValue = tag.TagValue;
                    switch (tag.TagValue)
                    {
                        case 0:
                            {
                                AsnReader field = sequence.ReadSequence(tag);
                                HashAlgorithmName? hash = ReadHashAlgorithm(field);
                                if (hash is null)
                                {
                                    return null;
                                }

                                digest = hash.Value;
                                break;
                            }

                        case 1:
                            {
                                AsnReader field = sequence.ReadSequence(tag);
                                AsnReader mgf = field.ReadSequence();
                                if (!string.Equals(mgf.ReadObjectIdentifier(), Mgf1Oid, StringComparison.Ordinal))
                                {
                                    return null;
                                }

                                AsnReader mgfHashField = mgf.ReadSequence();
                                HashAlgorithmName? mgfHash = ReadHashAlgorithm(mgfHashField, alreadyInsideSequence: true);
                                if (mgfHash is null || mgf.HasData || field.HasData)
                                {
                                    return null;
                                }

                                maskDigest = mgfHash.Value;
                                break;
                            }

                        case 2:
                            {
                                AsnReader field = sequence.ReadSequence(tag);
                                field.ReadInteger();
                                if (field.HasData)
                                {
                                    return null;
                                }

                                break;
                            }

                        case 3:
                            {
                                AsnReader field = sequence.ReadSequence(tag);
                                System.Numerics.BigInteger trailer = field.ReadInteger();
                                if (field.HasData || trailer != 1)
                                {
                                    return null;
                                }

                                break;
                            }

                        default:
                            return null;
                    }
                }

                return digest == maskDigest ? new Scheme(Kind.RsaPss, digest) : (Scheme?)null;
            }
            catch (AsnContentException)
            {
                return null;
            }
        }

        private static HashAlgorithmName? ReadHashAlgorithm(AsnReader field, bool alreadyInsideSequence = false)
        {
            AsnReader algorithm = alreadyInsideSequence ? field : field.ReadSequence();
            string oid = algorithm.ReadObjectIdentifier();
            return DigestOidToHash(oid);
        }
    }
}
