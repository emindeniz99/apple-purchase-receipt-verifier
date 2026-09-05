using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Receipt
{
    /// <summary>
    /// Verifies legacy PKCS#7 app receipts — the blob apps used to send to the
    /// deprecated <c>verifyReceipt</c> endpoint — completely offline, against
    /// pinned Apple roots.
    /// </summary>
    /// <remarks>
    /// <para>PLAN.md §2.2, the server-side port of Apple's "Validating receipts
    /// on the device" procedure. No OCSP, no CRL, no AIA fetch; the OS trust
    /// store is never consulted.</para>
    /// <para>There is deliberately <strong>no clock option</strong> on this
    /// class, and there must not be one. Receipt verification has no staleness
    /// rule, so the only thing a clock could reach is the "else current time"
    /// fallback for the chain-validity instant of a receipt carrying no
    /// creation date — a certificate-validity verdict. A caller injecting a
    /// clock must not thereby be able to accept a chain that is expired in real
    /// time, so that fallback reads the system clock and nothing else.</para>
    /// <para>Immutable and thread-safe once constructed.</para>
    /// </remarks>
    public sealed class ReceiptVerifier : IDisposable
    {
        /// <summary>
        /// Apple's marker OID on the receipt-signing leaf. The chain check
        /// alone is not enough: a developer "Apple Distribution" certificate
        /// chains through the same WWDR intermediate to the same pinned root,
        /// so without this purpose check any developer could sign a forged
        /// receipt (PLAN.md D13).
        /// </summary>
        internal const string ReceiptSignerOid = "1.2.840.113635.100.6.11.1";

        private const string Sha1Oid = "1.3.14.3.2.26";
        private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
        private const string RsaOid = "1.2.840.113549.1.1.1";

        /// <summary>
        /// The ceiling on the certificates a receipt may embed. Genuine
        /// receipts carry one to three; ten clears any chain Apple ships and
        /// still rejects a flood before a single certificate is decoded.
        /// </summary>
        internal const int MaximumEmbeddedCertificates = 10;

        private readonly List<X509Certificate2> _anchors;
        private readonly string _bundleId;
        private bool _disposed;

        /// <summary>Builds a verifier.</summary>
        /// <param name="trustedRoots">
        /// Pinned root CAs — in production
        /// <see cref="AppleRootCertificates.ReceiptRoots"/>. Copied, so the
        /// caller may dispose theirs.
        /// </param>
        /// <param name="bundleId">The bundle id the receipt must carry.</param>
        /// <exception cref="ArgumentException">
        /// The roots are empty or the bundle id is null or empty.
        /// </exception>
        public ReceiptVerifier(IEnumerable<X509Certificate2> trustedRoots, string bundleId)
        {
            if (string.IsNullOrEmpty(bundleId))
            {
                throw new ArgumentException("bundleId must not be empty", nameof(bundleId));
            }

            _anchors = Certificates.CopyAnchors(trustedRoots, nameof(trustedRoots));
            _bundleId = bundleId;
        }

        /// <summary>
        /// Verifies a DER receipt and enforces the configured bundle id.
        /// </summary>
        /// <param name="receiptDer">The PKCS#7 blob.</param>
        /// <param name="deviceGuid">
        /// When supplied, additionally enforces the device binding
        /// <c>SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) == attribute 5</c>.
        /// Optional because a server does not always hold the device's
        /// <c>identifierForVendor</c> bytes (PLAN.md D4); cross-device restore
        /// still works, since each device presents its own receipt.
        /// </param>
        /// <exception cref="VerificationException">The receipt did not verify.</exception>
        public AppReceipt Verify(byte[] receiptDer, byte[]? deviceGuid = null)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ReceiptVerifier));
            }

            AppReceipt receipt = VerifyCore(receiptDer, _anchors);
            if (!string.Equals(_bundleId, receipt.BundleId, StringComparison.Ordinal))
            {
                throw new VerificationException(
                    VerificationReason.WrongBundleId,
                    "the receipt's bundle id is not the configured one");
            }

            if (deviceGuid is not null)
            {
                // Inside the same categorical guard as the rest: SHA-1 is
                // unavailable outright on a host under a FIPS policy, and that
                // must surface as a verdict rather than as a platform
                // exception the caller has no contract for.
                try
                {
                    VerifyDeviceHash(receipt, deviceGuid);
                }
                catch (VerificationException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new VerificationException(
                        VerificationReason.DeviceHashMismatch,
                        "the device-hash check could not be performed", e);
                }
            }

            return receipt;
        }

        /// <summary>
        /// Verifies a base64-encoded receipt — the usual client transport form.
        /// </summary>
        /// <exception cref="VerificationException">The receipt did not verify.</exception>
        public AppReceipt Verify(string base64Receipt, byte[]? deviceGuid = null)
        {
            return Verify(DecodeBase64(base64Receipt), deviceGuid);
        }

        /// <summary>
        /// Chain and signature verification <strong>without</strong> the
        /// bundle-id check — the primitive under both <see cref="Verify(byte[], byte[])"/>
        /// and <see cref="VerifyReceiptEndpoint"/>, which (like Apple's
        /// endpoint) accepts any bundle.
        /// </summary>
        /// <remarks>
        /// The receipt this returns has been proved Apple-signed, but no claim
        /// in it has been checked: the bundle id in particular is whatever the
        /// receipt says. <strong>A caller unlocking products must compare it
        /// itself</strong>, or use <see cref="Verify(byte[], byte[])"/>.
        /// Public so that a caller emulating Apple's endpoint gets the
        /// primitive rather than having to build a verifier around a bundle id
        /// it does not want checked.
        /// </remarks>
        /// <exception cref="VerificationException">The receipt did not verify.</exception>
        /// <exception cref="ArgumentException">The roots are empty.</exception>
        public static AppReceipt VerifyReceiptCore(
            byte[] receiptDer, IEnumerable<X509Certificate2> trustedRoots)
        {
            List<X509Certificate2> anchors = Certificates.CopyAnchors(trustedRoots, nameof(trustedRoots));
            try
            {
                return VerifyCore(receiptDer, anchors);
            }
            finally
            {
                foreach (X509Certificate2 anchor in anchors)
                {
                    anchor.Dispose();
                }
            }
        }

        /// <summary>Releases the verifier's private copies of the trust anchors.</summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            foreach (X509Certificate2 anchor in _anchors)
            {
                anchor.Dispose();
            }
        }

        /// <summary>
        /// Decodes the base64 text a client actually sends. <c>receipt-data</c>
        /// is "Base64 as defined in RFC 4648", and Foundation's
        /// <c>base64EncodedString(options:)</c> can emit either the standard
        /// (<c>+/</c>) or the URL-safe (<c>-_</c>) alphabet, padded or not,
        /// wrapped with CR/LF at 64 or 76 columns. Everything Foundation can
        /// emit is accepted; a character outside both alphabets, both
        /// alphabets in one string, anything but whitespace after the
        /// padding, and an empty (or whitespace-only) string are rejected.
        /// There is no canonical-trailing-bits check.
        /// </summary>
        internal static byte[] DecodeBase64(string base64Receipt)
        {
            if (base64Receipt is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "receipt is null");
            }

            char[] compact = new char[base64Receipt.Length];
            int length = 0;
            foreach (char c in base64Receipt)
            {
                if (c != '\r' && c != '\n' && c != ' ' && c != '\t')
                {
                    compact[length++] = c;
                }
            }

            // A trailing run of '=' is padding. Anything else there means a
            // '=' sits before the run ends, which the alphabet scan below
            // rejects: '=' is not a recognised data character.
            int dataLength = length;
            while (dataLength > 0 && compact[dataLength - 1] == '=')
            {
                dataLength--;
            }

            if (dataLength == 0)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "receipt is empty");
            }

            if (dataLength % 4 == 1)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "receipt has an impossible base64 length");
            }

            // Padding is optional, but if present it must be exactly what the
            // data length calls for: neither over- nor under-padded.
            int pad = length - dataLength;
            int requiredPad = (4 - dataLength % 4) % 4;
            if (pad != 0 && pad != requiredPad)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "receipt has incorrect base64 padding");
            }

            bool sawStandard = false;
            bool sawUrlSafe = false;
            for (int i = 0; i < dataLength; i++)
            {
                char c = compact[i];
                if (c == '+' || c == '/')
                {
                    sawStandard = true;
                }
                else if (c == '-' || c == '_')
                {
                    sawUrlSafe = true;
                    compact[i] = c == '-' ? '+' : '/';
                }
                else if (!IsBase64Alphanumeric(c))
                {
                    throw new VerificationException(
                        VerificationReason.InvalidReceiptFormat,
                        "receipt contains a character outside the base64 or base64url alphabet");
                }
            }

            if (sawStandard && sawUrlSafe)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat,
                    "receipt mixes the standard and URL-safe base64 alphabets");
            }

            int remainder = dataLength % 4;
            string canonical = remainder == 0
                ? new string(compact, 0, dataLength)
                : new string(compact, 0, dataLength) + new string('=', 4 - remainder);

            try
            {
                return Convert.FromBase64String(canonical);
            }
            catch (FormatException e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "receipt is not valid base64", e);
            }
        }

        private static bool IsBase64Alphanumeric(char c) =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');

        /// <summary>
        /// Containment by category. <c>SignedCms</c> and <c>AsnReader</c> report
        /// malformed input with a platform-specific, undocumented set of types —
        /// <c>AsnContentException</c> derives from <see cref="Exception"/>, not
        /// from <see cref="CryptographicException"/> — so enumerating them is
        /// exactly how an unexpected type escapes the declared contract.
        /// </summary>
        private static AppReceipt VerifyCore(byte[] receiptDer, List<X509Certificate2> anchors)
        {
            try
            {
                return VerifyCoreUnguarded(receiptDer, anchors);
            }
            catch (VerificationException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidReceiptFormat, "malformed receipt", e);
            }
        }

        private static AppReceipt VerifyCoreUnguarded(byte[] receiptDer, List<X509Certificate2> anchors)
        {
            if (receiptDer is null)
            {
                throw Malformed("receipt is null");
            }

            // One structural pass first: it rejects trailing bytes and counts
            // the embedded certificates without decoding any of them. The count
            // is held rather than raised here so the reported reason still
            // follows the cross-port check order; what matters is that nothing
            // has materialised a certificate yet.
            int certificateCount = CmsPreScan.Scan(receiptDer, MaximumEmbeddedCertificates);

            // The signer is judged here, on the raw DER the same pass picked
            // out of the certificate bag, and BEFORE SignedCms sees the blob.
            // Everything below this line runs on a platform decoder, and a
            // platform decoder is entitled to refuse a certificate outright:
            // macOS refuses one claiming an unknown X.509 version or carrying
            // an extension value that does not decode, so the receipt came out
            // as INVALID_RECEIPT_FORMAT there and as INVALID_CERTIFICATE
            // everywhere else. Deciding it first makes the verdict the
            // library's rather than the host's.
            byte[]? namedSigner = CmsPreScan.FindSignerCertificate(receiptDer, MaximumEmbeddedCertificates);
            if (namedSigner is not null)
            {
                RequireReadableSigner(namedSigner);
            }

            SignedCms cms = new SignedCms();
            try
            {
                cms.Decode(receiptDer);
            }
            catch (CryptographicException e)
            {
                throw Malformed("not a PKCS#7/CMS blob", e);
            }

            byte[]? content = cms.ContentInfo.Content;
            if (content is null || content.Length == 0)
            {
                throw Malformed("no encapsulated payload");
            }

            // Parsed before the signature is checked only to learn the creation
            // date, which is the instant the chain's validity is judged at.
            // Nothing from it is trusted, returned or acted on until every
            // check below has passed.
            AppReceipt receipt = ReceiptPayload.Parse(content);

            if (cms.SignerInfos.Count == 0)
            {
                throw Malformed("no signer info");
            }

            if (certificateCount > MaximumEmbeddedCertificates)
            {
                throw new VerificationException(
                    VerificationReason.InvalidChain,
                    "the receipt embeds more than "
                    + MaximumEmbeddedCertificates.ToString(CultureInfo.InvariantCulture)
                    + " certificates");
            }

            SignerInfo signer = cms.SignerInfos[0];
            X509Certificate2? named = signer.Certificate;
            if (named is null)
            {
                throw Malformed("the signer certificate is not embedded in the receipt");
            }

            List<X509Certificate2> embedded = new List<X509Certificate2>(cms.Certificates.Count);
            X509Certificate2 signerCertificate = named;
            foreach (X509Certificate2 certificate in cms.Certificates)
            {
                embedded.Add(certificate);
                if (ByteOps.SequenceEqual(certificate.RawData, named.RawData))
                {
                    signerCertificate = certificate;
                }
            }

            if (namedSigner is null)
            {
                // The pre-scan could not name the signer — a SignerInfo
                // identifying it by subjectKeyIdentifier, say — so this is the
                // first point the check can run. It is a fallback and not the
                // rule: on a host whose decoder refuses the certificate it
                // never runs at all, which is exactly the divergence the
                // pre-scan closes for every signer it can name.
                RequireReadableSigner(signerCertificate.RawData);
            }

            // Deliberately the system clock, with no seam to override it: this
            // is a certificate-validity instant. The fallback only fires for a
            // receipt carrying no creation date (attribute 12).
            DateTimeOffset at = receipt.CreationDate ?? DateTimeOffset.UtcNow;
            CertificateChain.BuildPath(signerCertificate, embedded, anchors, at);

            // After the chain, not before: a foreign chain must report
            // INVALID_CHAIN rather than INVALID_CERTIFICATE_PURPOSE (D13).
            CertificateFields? signerFields = CertificateFields.TryParse(signerCertificate.RawData);
            if (signerFields is null || signerFields.Extension(ReceiptSignerOid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose,
                    "the receipt signer certificate lacks Apple marker OID " + ReceiptSignerOid);
            }

            if (!string.Equals(signerCertificate.PublicKey.Oid?.Value, RsaOid, StringComparison.Ordinal))
            {
                throw new VerificationException(
                    VerificationReason.InvalidSignature, "the receipt signer key is not RSA");
            }

            // Only the digests Apple actually uses for receipts.
            string? digestOid = signer.DigestAlgorithm.Value;
            if (!string.Equals(digestOid, Sha1Oid, StringComparison.Ordinal)
                && !string.Equals(digestOid, Sha256Oid, StringComparison.Ordinal))
            {
                throw Malformed("unsupported receipt digest algorithm");
            }

            try
            {
                // verifySignatureOnly: true is mandatory. The false overload
                // builds an X509Chain against the operating system's trust
                // store — the one thing this library must never do. Our own
                // walk above is what establishes trust, and it re-verifies each
                // certificate's signature, which is also what catches a
                // tampered certificate bag (CheckSignature does not: the
                // signer's signature covers the content, not the bag).
                signer.CheckSignature(verifySignatureOnly: true);
            }
            catch (CryptographicException e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidSignature, "the CMS signature check failed", e);
            }

            return receipt;
        }

        private static void VerifyDeviceHash(AppReceipt receipt, byte[] deviceGuid)
        {
            byte[]? opaqueValue = receipt.OpaqueValueInternal;
            byte[]? sha1Hash = receipt.Sha1HashInternal;
            byte[]? bundleIdBytes = receipt.BundleIdBytesInternal;
            if (opaqueValue is null || sha1Hash is null || bundleIdBytes is null)
            {
                throw new VerificationException(
                    VerificationReason.DeviceHashMismatch,
                    "the receipt lacks the attributes the device-hash check needs");
            }

            byte[] computed;
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] buffer = new byte[deviceGuid.Length + opaqueValue.Length + bundleIdBytes.Length];
                Buffer.BlockCopy(deviceGuid, 0, buffer, 0, deviceGuid.Length);
                Buffer.BlockCopy(opaqueValue, 0, buffer, deviceGuid.Length, opaqueValue.Length);
                Buffer.BlockCopy(
                    bundleIdBytes, 0, buffer, deviceGuid.Length + opaqueValue.Length, bundleIdBytes.Length);
                computed = sha1.ComputeHash(buffer);
            }

            if (!ByteOps.FixedTimeEquals(computed, sha1Hash))
            {
                throw new VerificationException(
                    VerificationReason.DeviceHashMismatch,
                    "the computed device hash does not match attribute 5");
            }
        }

        /// <summary>
        /// The four things the platform CMS decoder lets past that the checks
        /// below assume, settled while the verdict is still "this is not a
        /// certificate" — the receipt-path twin of what
        /// <c>JwsVerifier.LoadX5cEntry</c> settles for an x5c entry, and
        /// checked BEFORE the chain so a defect of the signer cannot come out
        /// as a verdict about the path. The last of them must be answered
        /// here rather than left to the "not RSA" check further down, whose
        /// subject is a READABLE key of the wrong kind
        /// (receipt/reject-signer-*).
        /// </summary>
        /// <param name="rawCertificate">
        /// The certificate's own DER — the bytes out of the certificate bag,
        /// not a re-encoding, and read with this library's own ASN.1 reader.
        /// Every check but the last is decided from those bytes alone, so the
        /// verdict does not depend on what the host's certificate parser is
        /// willing to accept.
        /// </param>
        private static void RequireReadableSigner(byte[] rawCertificate)
        {
            CertificateFields? fields = CertificateFields.TryParse(rawCertificate);
            if (fields is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate,
                    "the receipt signer certificate is not a valid certificate");
            }

            if (fields.Version is < 1 or > 3)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate,
                    "the receipt signer certificate has an unknown X.509 version");
            }

            if (fields.HasDuplicateExtension)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate,
                    "the receipt signer certificate carries a duplicate extension");
            }

            if (fields.HasUndecodableExtension)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate,
                    "the receipt signer certificate has an extension that does not decode");
            }

            if (!HasReadablePublicKey(rawCertificate))
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate,
                    "the receipt signer certificate has an unreadable public key");
            }
        }

        private static bool HasReadablePublicKey(byte[] rawCertificate)
        {
            using (X509Certificate2? certificate = Certificates.TryLoad(rawCertificate))
            {
                if (certificate is null)
                {
                    return false;
                }

                try
                {
                    using (RSA? rsa = certificate.GetRSAPublicKey())
                    {
                        if (rsa is not null)
                        {
                            return true;
                        }
                    }

                    using (ECDsa? ec = certificate.GetECDsaPublicKey())
                    {
                        return ec is not null;
                    }
                }
                catch (CryptographicException)
                {
                    return false;
                }
            }
        }

        private static VerificationException Malformed(string detail, Exception? cause = null)
        {
            return new VerificationException(VerificationReason.InvalidReceiptFormat, detail, cause);
        }
    }
}
