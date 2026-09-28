using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>A certificate paired with the raw fields read from its own DER.</summary>
    internal readonly struct LoadedCertificate
    {
        internal LoadedCertificate(X509Certificate2 certificate, CertificateFields fields)
        {
            Certificate = certificate;
            Fields = fields;
        }

        internal X509Certificate2 Certificate { get; }

        internal CertificateFields Fields { get; }
    }

    /// <summary>
    /// The pinned-anchor path walk, found top-down: a certificate's signature
    /// is checked with the key of a certificate already vouched for (an
    /// anchor, or something an anchor vouched for), never with the key of a
    /// certificate nobody has vouched for yet
    /// (#161).
    /// <c>X509Chain</c> is never constructed anywhere in this library.
    /// </summary>
    internal static class Chain
    {
        /// <summary>The longest path the builder will walk, anchor excluded.</summary>
        internal const int MaxPathLength = 6;

        /// <summary>
        /// The extensions a certificate on the path may mark critical: the
        /// ones a PKIX validator processes (RFC 5280 §6.1). Any other
        /// extension marked critical makes the certificate unusable, so the
        /// path fails, as a PKIX validator fails it. Rust's
        /// <c>rust/src/chain.rs</c> <c>PROCESSED_EXTENSIONS</c>, verbatim.
        /// </summary>
        private static readonly HashSet<string> ProcessedExtensions = new HashSet<string>(StringComparer.Ordinal)
        {
            "2.5.29.15", // keyUsage
            "2.5.29.32", // certificatePolicies
            "2.5.29.33", // policyMappings
            "2.5.29.54", // inhibitAnyPolicy
            "2.5.29.28", // issuingDistributionPoint
            "2.5.29.27", // deltaCRLIndicator
            "2.5.29.36", // policyConstraints
            "2.5.29.19", // basicConstraints
            "2.5.29.17", // subjectAltName
            "2.5.29.30", // nameConstraints
        };

        /// <summary>For the leaf only, also these. Rust's <c>PROCESSED_LEAF_EXTENSIONS</c>, verbatim.</summary>
        private static readonly HashSet<string> ProcessedLeafExtensions = new HashSet<string>(StringComparer.Ordinal)
        {
            "2.5.29.31", // cRLDistributionPoints
            "2.5.29.37", // extKeyUsage
        };

        /// <summary>Whether <paramref name="fields"/> marks critical an extension no step here processes.</summary>
        private static bool HasUnprocessedCriticalExtension(CertificateFields fields, bool leaf)
        {
            foreach (string oid in fields.CriticalExtensionOids())
            {
                if (ProcessedExtensions.Contains(oid))
                {
                    continue;
                }

                if (leaf && ProcessedLeafExtensions.Contains(oid))
                {
                    continue;
                }

                return true;
            }

            return false;
        }

        private const string KeyUsageOid = "2.5.29.15";

        /// <summary>
        /// Whether <paramref name="issuer"/>'s <c>keyUsage</c> extension, if it
        /// has one, permits <c>keyCertSign</c>. A missing extension imposes no
        /// restriction; one that is present but does not decode fails closed
        /// (a malformed <c>keyUsage</c> on an intermediate is
        /// <c>UNTRUSTED_CHAIN</c>, not "allowed").
        /// </summary>
        private static bool IssuerPermitsCertSign(X509Certificate2 issuer)
        {
            CertificateFields? fields = CertificateFields.TryParse(issuer.RawData);
            byte[]? keyUsage = fields?.Extension(KeyUsageOid);
            if (fields is null || keyUsage is null)
            {
                return fields is not null;
            }

            try
            {
                AsnReader reader = new AsnReader(keyUsage, AsnEncodingRules.DER);
                byte[] bits = reader.ReadBitString(out _);
                if (reader.HasData || bits.Length == 0)
                {
                    return false;
                }

                // keyCertSign is bit 5 (0-indexed, MSB-first) of the KeyUsage
                // BIT STRING: byte 0, mask 0x04.
                return (bits[0] & 0x04) != 0;
            }
            catch (AsnContentException)
            {
                return false;
            }
        }

        /// <summary>
        /// Whether <paramref name="certificate"/> is valid at <paramref name="atMs"/>,
        /// compared as epoch milliseconds rather than through
        /// <see cref="DateTimeOffset"/>: a JWS <c>signedDate</c> claim is
        /// attacker-supplied and may state an instant
        /// <see cref="DateTimeOffset"/> cannot represent (its year range is 1
        /// to 9999), and that must fail the validity check rather than throw.
        /// The certificate's own <see cref="X509Certificate2.NotBefore"/> and
        /// <see cref="X509Certificate2.NotAfter"/> are always in that range.
        /// </summary>
        private static bool IsValidAt(X509Certificate2 certificate, long atMs)
        {
            long notBeforeMs = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()).ToUnixTimeMilliseconds();
            long notAfterMs = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()).ToUnixTimeMilliseconds();
            return notBeforeMs <= atMs && atMs <= notAfterMs;
        }

        /// <summary>
        /// Whether <paramref name="issuer"/> issued <paramref name="subject"/>:
        /// byte-equal names, plus a verified signature over the exact
        /// <c>tbsCertificate</c> bytes under whatever algorithm
        /// <paramref name="subject"/> names (Q14: no allowlist).
        /// </summary>
        private static bool IssuedBy(LoadedCertificate subject, X509Certificate2 issuer)
        {
            return ByteOps.SequenceEqual(subject.Certificate.IssuerName.RawData, issuer.SubjectName.RawData)
                && IssuerPermitsCertSign(issuer)
                && SignatureAlgorithms.VerifyCertificateSignature(subject.Fields, issuer);
        }

        private static bool IssuedByAnyAnchor(LoadedCertificate certificate, IReadOnlyList<X509Certificate2> anchors)
        {
            foreach (X509Certificate2 anchor in anchors)
            {
                if (IssuedBy(certificate, anchor))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Validates the fixed JWS path leaf, intermediate, pinned anchor. The
        /// two signatures are checked from the anchor down first, so no key an
        /// anchor did not vouch for is ever used; then the intermediate's
        /// window, its CA flag and the leaf's window, at <paramref name="atMs"/>.
        /// </summary>
        internal static void ValidatePair(
            LoadedCertificate leaf,
            LoadedCertificate intermediate,
            IReadOnlyList<X509Certificate2> anchors,
            long atMs)
        {
            if (!IssuedByAnyAnchor(intermediate, anchors))
            {
                throw Untrusted("intermediate certificate is not signed by a pinned root");
            }

            // Vouched for, and its key is about to check the leaf: an
            // unbuildable key (an unassigned or unimplemented EC curve) is
            // the certificate's own defect, not a chain failure.
            RequireBuildablePublicKey(intermediate.Certificate, VerificationReason.InvalidCertificate, "intermediate certificate");
            if (!IssuedBy(leaf, intermediate.Certificate))
            {
                throw Untrusted("leaf certificate is not signed by the intermediate");
            }

            if (!IsValidAt(intermediate.Certificate, atMs))
            {
                throw OutsideValidity();
            }

            if (!intermediate.Fields.IsCertificateAuthority())
            {
                throw Untrusted("intermediate is not a CA");
            }

            if (HasUnprocessedCriticalExtension(intermediate.Fields, leaf: false))
            {
                throw UnprocessedCriticalExtension();
            }

            if (!IsValidAt(leaf.Certificate, atMs))
            {
                throw OutsideValidity();
            }

            if (HasUnprocessedCriticalExtension(leaf.Fields, leaf: true))
            {
                throw UnprocessedCriticalExtension();
            }
        }

        /// <summary>
        /// The embedded certificates whose signature verifies under a pinned
        /// anchor, or under a certificate already accepted this way, walking
        /// down from the anchors in at most <see cref="MaxPathLength"/>
        /// rounds. Only these are handed to <see cref="BuildAndValidatePath"/>.
        /// An embedded copy of an anchor is the anchor, and is accepted
        /// without a signature check.
        /// </summary>
        internal static List<LoadedCertificate> AuthenticatedTopDown(
            IReadOnlyList<LoadedCertificate> embedded, IReadOnlyList<X509Certificate2> anchors)
        {
            List<LoadedCertificate> accepted = new List<LoadedCertificate>();
            List<LoadedCertificate> pending = new List<LoadedCertificate>();
            foreach (LoadedCertificate certificate in embedded)
            {
                bool isAnchor = false;
                foreach (X509Certificate2 anchor in anchors)
                {
                    if (ByteOps.SequenceEqual(anchor.RawData, certificate.Certificate.RawData))
                    {
                        isAnchor = true;
                        break;
                    }
                }

                (isAnchor ? accepted : pending).Add(certificate);
            }

            List<X509Certificate2> issuers = new List<X509Certificate2>(anchors);
            foreach (LoadedCertificate a in accepted)
            {
                issuers.Add(a.Certificate);
            }

            for (int round = 0; round < MaxPathLength && pending.Count > 0; round++)
            {
                List<LoadedCertificate> acceptedThisRound = new List<LoadedCertificate>();
                List<LoadedCertificate> stillPending = new List<LoadedCertificate>();
                foreach (LoadedCertificate candidate in pending)
                {
                    bool ok = false;
                    foreach (X509Certificate2 issuer in issuers)
                    {
                        if (IssuedBy(candidate, issuer))
                        {
                            ok = true;
                            break;
                        }
                    }

                    (ok ? acceptedThisRound : stillPending).Add(candidate);
                }

                if (acceptedThisRound.Count == 0)
                {
                    break;
                }

                accepted.AddRange(acceptedThisRound);
                issuers = new List<X509Certificate2>();
                foreach (LoadedCertificate a in acceptedThisRound)
                {
                    issuers.Add(a.Certificate);
                }

                pending = stillPending;
            }

            return accepted;
        }

        /// <summary>
        /// Builds a path from <paramref name="target"/> through
        /// <paramref name="candidates"/> (the ones
        /// <see cref="AuthenticatedTopDown"/> accepted) to one of the pinned
        /// <paramref name="anchors"/>, the shape a legacy receipt uses; then
        /// checks every certificate on it is inside its validity window at
        /// <paramref name="atMs"/>. Returns the path, target first, anchor
        /// excluded.
        /// </summary>
        internal static List<LoadedCertificate> BuildAndValidatePath(
            LoadedCertificate target,
            IReadOnlyList<LoadedCertificate> candidates,
            IReadOnlyList<X509Certificate2> anchors,
            long atMs)
        {
            List<LoadedCertificate> path = new List<LoadedCertificate> { target };
            LoadedCertificate current = target;
            while (true)
            {
                if (path.Count > 1 && !current.Fields.IsCertificateAuthority())
                {
                    throw Untrusted("an intermediate is not a CA");
                }

                if (IssuedByAnyAnchor(current, anchors))
                {
                    break;
                }

                if (path.Count >= MaxPathLength)
                {
                    throw Untrusted("chain exceeds the maximum length");
                }

                LoadedCertificate? issuer = null;
                foreach (LoadedCertificate candidate in candidates)
                {
                    if (Contains(path, candidate))
                    {
                        continue;
                    }

                    if (IssuedBy(current, candidate.Certificate))
                    {
                        issuer = candidate;
                        break;
                    }
                }

                if (issuer is null)
                {
                    throw Untrusted("chain does not reach a pinned root");
                }

                path.Add(issuer.Value);
                current = issuer.Value;
            }

            foreach (LoadedCertificate c in path)
            {
                if (!IsValidAt(c.Certificate, atMs))
                {
                    throw OutsideValidity();
                }
            }

            for (int i = 0; i < path.Count; i++)
            {
                if (HasUnprocessedCriticalExtension(path[i].Fields, leaf: i == 0))
                {
                    throw UnprocessedCriticalExtension();
                }
            }

            return path;
        }

        private static bool Contains(List<LoadedCertificate> path, LoadedCertificate candidate)
        {
            foreach (LoadedCertificate p in path)
            {
                if (ReferenceEquals(p.Certificate, candidate.Certificate))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Four things a platform certificate decoder lets past that this
        /// library does not, checked while the verdict is still "this is not
        /// a usable certificate": an unknown X.509 version, a repeated
        /// extension (RFC 5280 §4.2 forbids it — every reader downstream
        /// takes the first copy, so without this check different readers
        /// could disagree about, say, the CA flag), and an extension whose
        /// value does not decode. Applied to a certificate about to have its
        /// own key checked or used: the receipt signer, and the JWS leaf and
        /// intermediate (and the third, dropped, <c>x5c</c> entry).
        /// </summary>
        internal static void RequireStructurallySound(LoadedCertificate certificate, VerificationReason reason, string what)
        {
            if (certificate.Fields.Version is < 1 or > 3)
            {
                throw new VerificationException(reason, what + " has an unknown X.509 version");
            }

            if (certificate.Fields.HasDuplicateExtension)
            {
                throw new VerificationException(reason, what + " carries a duplicate extension");
            }

            if (certificate.Fields.HasUndecodableExtension)
            {
                throw new VerificationException(reason, what + " has an extension that does not decode");
            }
        }

        /// <summary>
        /// A certificate whose key is about to check a signature this
        /// library trusts to it directly — the receipt signer, the JWS leaf —
        /// must have a key this platform can build at all: an unassigned or
        /// unimplemented EC curve, checked only once the certificate has
        /// already been vouched for and carries the right marker OID, is the
        /// certificate's own defect, <c>INVALID_CERTIFICATE</c>, never a
        /// signature or chain verdict. A certificate reached only as an
        /// <em>issuer</em> (the intermediate, checking the leaf) gets no such
        /// check: its key simply fails to verify anything, and the chain
        /// through it is <c>UNTRUSTED_CHAIN</c>.
        /// </summary>
        internal static void RequireBuildablePublicKey(X509Certificate2 certificate, VerificationReason reason, string what)
        {
            try
            {
                using (ECDsa? ec = certificate.GetECDsaPublicKey())
                {
                    if (ec is not null)
                    {
                        return;
                    }
                }

                using (RSA? rsa = certificate.GetRSAPublicKey())
                {
                    if (rsa is not null)
                    {
                        return;
                    }
                }
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // Not only CryptographicException: OpenSSL refuses an
                // undecodable key with one, but on macOS the key is built by
                // Apple's Security framework and the refusal escaped this
                // catch as some other type, reaching the caller's catch-all
                // as MALFORMED. Either way the certificate was vouched for and
                // its key cannot be built, so the verdict must not depend on
                // the platform.
                throw new VerificationException(reason, what + " has a key this library cannot build", e);
            }

            throw new VerificationException(reason, what + " has a key this library cannot build");
        }

        private static VerificationException Untrusted(string detail) =>
            new VerificationException(VerificationReason.UntrustedChain, detail);

        private static VerificationException OutsideValidity() =>
            new VerificationException(
                VerificationReason.InvalidCertificate,
                "certificate is outside its validity window at the chain instant");

        private static VerificationException UnprocessedCriticalExtension() =>
            Untrusted("a certificate on the path has an unsupported critical extension");
    }
}
