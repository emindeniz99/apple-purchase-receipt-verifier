using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// <c>verifyReceipt(base64)</c>: legacy PKCS#7 app receipts, verified
    /// offline against pinned Apple roots.
    /// </summary>
    /// <remarks>
    /// Checks, in order: strict base64, the CMS envelope, the chain to a
    /// pinned root walked top-down together with certificate validity at the
    /// receipt's creation date, Apple's marker OIDs on both the leaf and the
    /// WWDR intermediate, then the signature. Several SignerInfos: the receipt
    /// verifies when at least one verifies under a pinned chain; when none
    /// does, the first SignerInfo's failure is the verdict.
    /// </remarks>
    internal static class ReceiptVerifierCore
    {
        /// <summary>3 MiB, counted in UTF-8 bytes of the base64 string.</summary>
        internal const int MaxReceiptBytes = 3145728;

        private const string ReceiptSignerOid = "1.2.840.113635.100.6.11.1";
        private const string WwdrIntermediateOid = "1.2.840.113635.100.6.2.1";

        /// <summary>
        /// Decodes the base64 text a client sends as <c>receipt-data</c>:
        /// canonical standard base64 and nothing else, as Apple's verifyReceipt
        /// accepts it.
        /// </summary>
        internal static byte[] DecodeBase64(string? base64Receipt)
        {
            if (string.IsNullOrEmpty(base64Receipt))
            {
                throw Malformed("receipt is empty");
            }

            if (Utf8Length.Exceeds(base64Receipt!, MaxReceiptBytes))
            {
                throw new VerificationException(
                    VerificationReason.TooLarge,
                    "receipt exceeds the maximum accepted size of "
                    + MaxReceiptBytes.ToString(CultureInfo.InvariantCulture) + " bytes");
            }

            return CanonicalBase64.Decode(base64Receipt!)
                ?? throw Malformed("receipt is not canonical standard base64");
        }

        internal static ReceiptPayload Verify(string? base64, IReadOnlyList<X509Certificate2> anchors, Func<long> clock)
        {
            byte[] der = DecodeBase64(base64);
            byte[] content;
            try
            {
                content = VerifySignature(der, anchors, clock);
            }
            catch (VerificationException)
            {
                throw;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // Contains any unexpected error before the signature has
                // verified: everything up to here runs on input nobody has
                // vouched for, so it is MALFORMED, never INTERNAL_ERROR, which
                // would let anyone raise that alert at will.
                throw Malformed("unexpected error: " + e.GetType().Name, e);
            }

            try
            {
                return ReceiptAttributes.Parse(content);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // A trusted signer signed these bytes, so a payload this
                // library cannot read is the library's failure or a format
                // Apple added, not the client's.
                throw new VerificationException(
                    VerificationReason.UnreadablePayload, "signed receipt content could not be read", e);
            }
        }

        private static byte[] VerifySignature(byte[] der, IReadOnlyList<X509Certificate2> anchors, Func<long> clock)
        {
            CmsParsed cms = Cms.Parse(der);

            // Judged for every SignerInfo before any key is used, so a
            // malformed signedAttrs is MALFORMED regardless of signer order.
            foreach (CmsSignerInfo info in cms.SignerInfos)
            {
                if (info.SignedAttrsRaw is not null)
                {
                    Cms.RequireAttributeSetSyntax(info.SignedAttrsRaw);
                }
            }

            // Only the creation date is read before trust is established,
            // because chain validity is anchored at signing time.
            long? creationMs = ReceiptAttributes.ReadCreationDateMs(cms.Content);
            long at = creationMs ?? CallClock.Read(clock);

            EmbeddedCertificates embedded = DecodeEmbedded(cms.CertificateEntries);

            // Signer-independent, so walked once for all SignerInfos, and
            // only once one of them has named an embedded certificate that
            // decodes.
            List<LoadedCertificate>? authenticated = null;
            VerificationException? firstFailure = null;
            foreach (CmsSignerInfo info in cms.SignerInfos)
            {
                try
                {
                    List<LoadedCertificate> candidates = SignerCertificates(info, embedded);
                    authenticated ??= Chain.AuthenticatedTopDown(embedded.Decoded, anchors);

                    // The certificate bag is unsigned, so more than one
                    // embedded certificate can carry the signer's issuer and
                    // serial. Each match is tried in bag order: one passing is
                    // enough, and only when none does is the first match's
                    // failure the verdict.
                    VerificationException? firstMatchFailure = null;
                    foreach (LoadedCertificate signer in candidates)
                    {
                        try
                        {
                            VerifySigner(cms, info, signer, authenticated, anchors, at);
                            return cms.Content;
                        }
                        catch (VerificationException matchCause)
                        {
                            firstMatchFailure ??= matchCause;
                        }
                    }

                    throw firstMatchFailure ?? Malformed("signer certificate not embedded");
                }
                catch (VerificationException cause)
                {
                    // Every SignerInfo signs the same content, so another one
                    // passing proves the same bytes; only when none does is
                    // the first one's failure the verdict.
                    firstFailure ??= cause;
                }
            }

            throw firstFailure ?? Malformed("no signer info");
        }

        private readonly struct EmbeddedCertificates
        {
            internal EmbeddedCertificates(List<LoadedCertificate> decoded, List<byte[]> unreadable)
            {
                Decoded = decoded;
                Unreadable = unreadable;
            }

            internal List<LoadedCertificate> Decoded { get; }

            internal List<byte[]> Unreadable { get; }
        }

        private static EmbeddedCertificates DecodeEmbedded(List<byte[]> entries)
        {
            List<LoadedCertificate> decoded = new List<LoadedCertificate>();
            List<byte[]> unreadable = new List<byte[]>();
            foreach (byte[] raw in entries)
            {
                X509Certificate2? certificate = Certificates.TryLoad(raw);
                CertificateFields? fields = certificate is not null ? CertificateFields.TryParse(raw) : null;
                if (certificate is not null && fields is not null)
                {
                    decoded.Add(new LoadedCertificate(certificate, fields));
                }
                else
                {
                    unreadable.Add(raw);
                }
            }

            return new EmbeddedCertificates(decoded, unreadable);
        }

        /// <summary>
        /// Every embedded certificate carrying the issuer and serial
        /// <paramref name="info"/> names, in bag order and never empty, or the
        /// verdict for the bag. The signer's own entry not decoding is
        /// <c>INVALID_CERTIFICATE</c>; any other entry not decoding is
        /// <c>MALFORMED</c>, because the bag is unsigned. A broken signer
        /// outranks a broken stranger.
        /// </summary>
        private static List<LoadedCertificate> SignerCertificates(CmsSignerInfo info, EmbeddedCertificates embedded)
        {
            if (info.IssuerRaw is null || info.SerialRaw is null)
            {
                throw Malformed("signer certificate not embedded");
            }

            foreach (byte[] raw in embedded.Unreadable)
            {
                if (NamesTheSigner(raw, info))
                {
                    throw new VerificationException(
                        VerificationReason.InvalidCertificate, "receipt signer certificate does not decode");
                }
            }

            List<LoadedCertificate> matches = new List<LoadedCertificate>();
            foreach (LoadedCertificate certificate in embedded.Decoded)
            {
                if (ByteOps.SequenceEqual(certificate.Fields.SerialNumberRaw, info.SerialRaw)
                    && ByteOps.SequenceEqual(certificate.Fields.IssuerRaw, info.IssuerRaw))
                {
                    matches.Add(certificate);
                }
            }

            if (embedded.Unreadable.Count > 0)
            {
                // A signer this library condemns from its own bytes is as
                // broken as one the platform could not load, and outranks the
                // broken stranger the same way. Which of the two a given
                // signer is depends on the host's decoder (macOS refuses a
                // version-11 certificate that OpenSSL loads), so the verdict
                // must not.
                foreach (LoadedCertificate signer in matches)
                {
                    Chain.RequireStructurallySound(
                        signer, VerificationReason.InvalidCertificate, "the receipt signer certificate");
                }

                throw Malformed("an embedded certificate is not a valid certificate");
            }

            if (matches.Count == 0)
            {
                throw Malformed("signer certificate not embedded");
            }

            return matches;
        }

        /// <summary>
        /// Whether <paramref name="raw"/> carries the issuer Name and
        /// serialNumber <paramref name="info"/> names, read as generic ASN.1
        /// because the entry is one <see cref="CertificateFields"/> refused.
        /// </summary>
        private static bool NamesTheSigner(byte[] raw, CmsSignerInfo info)
        {
            try
            {
                AsnReader certificate = new AsnReader(raw, AsnEncodingRules.BER).ReadSequence();
                AsnReader tbs = certificate.ReadSequence();
                if (tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                {
                    tbs.ReadEncodedValue();     // version
                }

                byte[] serial = tbs.ReadEncodedValue().ToArray();
                tbs.ReadEncodedValue();         // signature
                byte[] issuer = tbs.ReadEncodedValue().ToArray();
                return ByteOps.SequenceEqual(serial, info.SerialRaw!) && ByteOps.SequenceEqual(issuer, info.IssuerRaw!);
            }
            catch (AsnContentException)
            {
                return false;
            }
        }

        private static void VerifySigner(
            CmsParsed cms,
            CmsSignerInfo info,
            LoadedCertificate signer,
            List<LoadedCertificate> authenticated,
            IReadOnlyList<X509Certificate2> anchors,
            long at)
        {
            Chain.RequireStructurallySound(signer, VerificationReason.InvalidCertificate, "the receipt signer certificate");
            List<LoadedCertificate> path = Chain.BuildAndValidatePath(signer, authenticated, anchors, at);

            // Checked after the chain, so a foreign chain still reports
            // UNTRUSTED_CHAIN rather than INVALID_CERTIFICATE_PURPOSE.
            if (signer.Fields.Extension(ReceiptSignerOid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose,
                    "the receipt signer certificate lacks Apple marker OID " + ReceiptSignerOid);
            }

            // The certificate after the signer on the path. A signer issued
            // straight by a root has no WWDR certificate to carry the marker.
            LoadedCertificate? intermediate = path.Count > 1 ? path[1] : (LoadedCertificate?)null;
            if (intermediate is null || intermediate.Value.Fields.Extension(WwdrIntermediateOid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose,
                    "the receipt intermediate certificate lacks Apple WWDR marker OID " + WwdrIntermediateOid);
            }

            // The signer's key is about to check the CMS signature; judged
            // only once the chain has vouched for it and its marker is right.
            Chain.RequireBuildablePublicKey(
                signer.Certificate, VerificationReason.InvalidCertificate, "the receipt signer certificate");

            VerifyCmsSignature(cms, info, signer);
        }

        /// <summary>
        /// No algorithm or key-type allowlist beyond what the .NET crypto
        /// stack implements: the signer is already pinned to an Apple root and
        /// carries Apple's receipt-signing marker.
        /// </summary>
        private static void VerifyCmsSignature(CmsParsed cms, CmsSignerInfo info, LoadedCertificate signer)
        {
            HashAlgorithmName? digest = SignatureAlgorithms.DigestOidToHash(info.DigestAlgorithmOid);
            byte[] signedBytes;
            if (info.SignedAttrsRaw is not null)
            {
                if (digest is null)
                {
                    throw new VerificationException(VerificationReason.InvalidSignature, "unsupported digest algorithm");
                }

                SignedAttributesInfo attrs = Cms.ExtractSignedAttributes(info.SignedAttrsRaw);

                // RFC 5652 §5.3: contentType and messageDigest are mandatory
                // whenever signedAttrs are present.
                if (attrs.ContentTypeOid is null)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "signedAttrs lack a contentType attribute");
                }

                if (attrs.MessageDigest is null)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "signedAttrs lack a messageDigest attribute");
                }

                // RFC 5652 §11: at most one instance of each attribute.
                if (attrs.DuplicateContentType || attrs.DuplicateMessageDigest)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature,
                        "signedAttrs carry a contentType or messageDigest attribute twice");
                }

                // RFC 5652 §11.1: the contentType attribute names the content
                // the signature covers.
                if (!string.Equals(attrs.ContentTypeOid, cms.ContentTypeOid, StringComparison.Ordinal))
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "contentType attribute differs from the eContentType");
                }

                byte[] contentDigest = Digest.Compute(digest.Value, cms.Content);
                if (!ByteOps.FixedTimeEquals(attrs.MessageDigest, contentDigest))
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "messageDigest attribute does not match content");
                }

                signedBytes = attrs.SignedBytes;
            }
            else
            {
                signedBytes = cms.Content;
            }

            bool valid = SignatureAlgorithms.VerifySignerSignature(
                signer.Certificate,
                signer.Fields.SubjectPublicKeyAlgorithmOid,
                info.DigestAlgorithmOid,
                info.SignatureAlgorithmOid,
                info.SignatureAlgorithmParams,
                info.Signature,
                signedBytes);
            if (!valid)
            {
                throw new VerificationException(
                    VerificationReason.InvalidSignature,
                    "the CMS signature does not match the signer certificate's key");
            }
        }

        private static VerificationException Malformed(string detail, Exception? cause = null) =>
            new VerificationException(VerificationReason.Malformed, detail, cause);
    }
}
