using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The pinned-anchor path walk. <c>X509Chain</c> is never constructed
    /// anywhere in this library.
    /// </summary>
    /// <remarks>
    /// <para>Reasons, in order of weight: <c>X509Chain</c>'s anchor-pinning
    /// properties (<c>CustomTrustStore</c>, <c>TrustMode</c>,
    /// <c>DisableCertificateDownloads</c>) are .NET 5+ only, so on the
    /// netstandard2.0 floor the only available behaviour is "trust the OS
    /// store"; its defaults are online revocation plus AIA fetching, which is
    /// both a network dependency and a privacy leak; and it fails
    /// <em>permissively</em> on a developer machine whose OS store already
    /// holds the Apple roots. Node and Swift hand-roll the same fixed walk,
    /// which is how the conformance vectors stay identical.</para>
    /// <para>Every entry point takes the validity instant as a required
    /// parameter. There is no overload defaulting to "now", so forgetting to
    /// pass the signing time does not compile.</para>
    /// </remarks>
    internal static class CertificateChain
    {
        /// <summary>Receipt chains embed their intermediates; this bounds the walk.</summary>
        private const int MaxPathLength = 6;

        /// <summary>
        /// Certificate signatureAlgorithm OIDs the walk will verify under.
        /// SHA-1 with RSA is on the list because Apple's own legacy receipt
        /// chain is SHA-1/RSA end to end — dropping it would drop legacy
        /// receipt support, not harden anything. <c>ecdsa-with-SHA1</c>
        /// (<c>1.2.840.10045.4.1</c>) is deliberately absent: no Apple chain
        /// has ever used it, so admitting a second collision-broken
        /// construction buys nothing and would accept certificates node and
        /// python reject.
        /// </summary>
        private static readonly Dictionary<string, SignatureAlgorithm> Algorithms =
            new Dictionary<string, SignatureAlgorithm>(StringComparer.Ordinal)
            {
                ["1.2.840.113549.1.1.5"] = new SignatureAlgorithm(HashAlgorithmName.SHA1, false),
                ["1.2.840.113549.1.1.11"] = new SignatureAlgorithm(HashAlgorithmName.SHA256, false),
                ["1.2.840.113549.1.1.12"] = new SignatureAlgorithm(HashAlgorithmName.SHA384, false),
                ["1.2.840.113549.1.1.13"] = new SignatureAlgorithm(HashAlgorithmName.SHA512, false),
                ["1.2.840.10045.4.3.2"] = new SignatureAlgorithm(HashAlgorithmName.SHA256, true),
                ["1.2.840.10045.4.3.3"] = new SignatureAlgorithm(HashAlgorithmName.SHA384, true),
                ["1.2.840.10045.4.3.4"] = new SignatureAlgorithm(HashAlgorithmName.SHA512, true),
            };

        /// <summary>
        /// The fixed JWS path: leaf → intermediate → a pinned anchor, judged at
        /// <paramref name="at"/>. <c>x5c[2]</c> is never consulted.
        /// </summary>
        internal static void ValidateJwsPair(
            X509Certificate2 leaf,
            X509Certificate2 intermediate,
            IReadOnlyList<X509Certificate2> anchors,
            DateTimeOffset at)
        {
            if (!IsValidAt(leaf, at) || !IsValidAt(intermediate, at))
            {
                throw Invalid("certificate is not valid at the payload's signing time");
            }

            CertificateFields? intermediateFields = CertificateFields.TryParse(intermediate.RawData);
            if (intermediateFields is null || !intermediateFields.IsCertificateAuthority())
            {
                throw Invalid("intermediate is not a CA");
            }

            if (!IssuedBy(leaf, intermediate))
            {
                throw Invalid("leaf is not issued by the intermediate");
            }

            foreach (X509Certificate2 anchor in anchors)
            {
                if (IssuedBy(intermediate, anchor))
                {
                    return;
                }
            }

            throw Invalid("intermediate is not issued by a pinned root");
        }

        /// <summary>
        /// Walks from <paramref name="target"/> through <paramref name="candidates"/>
        /// to a pinned anchor, judged at <paramref name="at"/>. Trust anchors
        /// are trusted by fiat — an anchor's own expiry is not checked, which
        /// is standard PKIX trust-anchor semantics and is what lets a
        /// historical receipt verify under a since-expired chain.
        /// </summary>
        internal static void BuildPath(
            X509Certificate2 target,
            IReadOnlyList<X509Certificate2> candidates,
            IReadOnlyList<X509Certificate2> anchors,
            DateTimeOffset at)
        {
            X509Certificate2 current = target;
            for (int depth = 0; depth < MaxPathLength; depth++)
            {
                if (!IsValidAt(current, at))
                {
                    throw Invalid("certificate is not valid at the receipt's signing time");
                }

                if (depth > 0)
                {
                    CertificateFields? fields = CertificateFields.TryParse(current.RawData);
                    if (fields is null || !fields.IsCertificateAuthority())
                    {
                        throw Invalid("intermediate is not a CA");
                    }
                }

                foreach (X509Certificate2 anchor in anchors)
                {
                    if (IssuedBy(current, anchor))
                    {
                        return;
                    }
                }

                X509Certificate2? issuer = null;
                foreach (X509Certificate2 candidate in candidates)
                {
                    if (!ReferenceEquals(candidate, current) && IssuedBy(current, candidate))
                    {
                        issuer = candidate;
                        break;
                    }
                }

                if (issuer is null)
                {
                    throw Invalid("chain does not reach a pinned root");
                }

                current = issuer;
            }

            throw Invalid("chain exceeds the maximum path length");
        }

        /// <summary>
        /// Whether <paramref name="issuer"/> issued <paramref name="subject"/>:
        /// byte-equal names plus a verified signature over the exact
        /// <c>tbsCertificate</c> bytes.
        /// </summary>
        /// <remarks>
        /// No library "verify" call is involved, and the algorithm OID goes
        /// through a closed allowlist — an unrecognised algorithm is a
        /// <em>failed</em> check, never a skipped one.
        /// </remarks>
        internal static bool IssuedBy(X509Certificate2 subject, X509Certificate2 issuer)
        {
            // Byte comparison, not string: X.500 string canonicalisation is a
            // whole family of bugs.
            if (!ByteOps.SequenceEqual(subject.IssuerName.RawData, issuer.SubjectName.RawData))
            {
                return false;
            }

            CertificateFields? fields = CertificateFields.TryParse(subject.RawData);
            if (fields is null
                || !string.Equals(fields.SignatureAlgorithmOid, fields.TbsSignatureAlgorithmOid, StringComparison.Ordinal)
                || !Algorithms.TryGetValue(fields.SignatureAlgorithmOid, out SignatureAlgorithm algorithm))
            {
                return false;
            }

            try
            {
                if (algorithm.IsEllipticCurve)
                {
                    using (ECDsa? key = issuer.GetECDsaPublicKey())
                    {
                        if (key is null)
                        {
                            return false;
                        }

                        byte[]? p1363 = EcdsaSignatureFormat.DerToP1363(fields.Signature, (key.KeySize + 7) / 8);
                        return p1363 is not null
                            && key.VerifyData(fields.TbsCertificate, p1363, algorithm.Hash);
                    }
                }

                using (RSA? key = issuer.GetRSAPublicKey())
                {
                    return key is not null
                        && key.VerifyData(fields.TbsCertificate, fields.Signature, algorithm.Hash, RSASignaturePadding.Pkcs1);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        private static bool IsValidAt(X509Certificate2 certificate, DateTimeOffset at)
        {
            DateTimeOffset notBefore = certificate.NotBefore.ToUniversalTime();
            DateTimeOffset notAfter = certificate.NotAfter.ToUniversalTime();
            return notBefore <= at && at <= notAfter;
        }

        private static VerificationException Invalid(string detail)
        {
            return new VerificationException(VerificationReason.InvalidChain, detail);
        }

        private readonly struct SignatureAlgorithm
        {
            internal SignatureAlgorithm(HashAlgorithmName hash, bool isEllipticCurve)
            {
                Hash = hash;
                IsEllipticCurve = isEllipticCurve;
            }

            internal HashAlgorithmName Hash { get; }

            internal bool IsEllipticCurve { get; }
        }
    }
}
