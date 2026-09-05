using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Jws
{
    /// <summary>
    /// Verifies Apple-signed JWS payloads (StoreKit 2 <c>jwsRepresentation</c>,
    /// App Store Server <c>signedTransactionInfo</c> /
    /// <c>signedRenewalInfo</c>, Server Notifications V2) completely offline,
    /// against pinned Apple roots.
    /// </summary>
    /// <remarks>
    /// <para>PLAN.md §2.1: ES256 only, exactly three <c>x5c</c> certificates,
    /// Apple marker OIDs on leaf and intermediate, a path walk to a pinned root
    /// at the payload's signing time, then the signature and the claim checks.
    /// Revocation is disabled by design — no OCSP, no CRL, no AIA fetch, and
    /// the OS trust store is never consulted.</para>
    /// <para>Immutable and thread-safe once constructed. Register it as a
    /// singleton.</para>
    /// </remarks>
    public sealed class JwsVerifier : IDisposable
    {
        /// <summary>Apple marker OID: a leaf certificate used for App Store signing.</summary>
        internal const string LeafOid = "1.2.840.113635.100.6.11.1";

        /// <summary>Apple marker OID: the Worldwide Developer Relations intermediate CA.</summary>
        internal const string IntermediateOid = "1.2.840.113635.100.6.2.1";

        /// <summary>The epoch-millisecond range <see cref="DateTimeOffset"/> can represent.</summary>
        private const double MinUnixMilliseconds = -62135596800000d;

        /// <inheritdoc cref="MinUnixMilliseconds"/>
        private const double MaxUnixMilliseconds = 253402300799999d;

        private readonly List<X509Certificate2> _anchors;
        private readonly string _bundleId;
        private readonly HashSet<AppleEnvironment> _acceptedEnvironments;
        private readonly long? _appAppleId;
        private readonly long? _maxSignedAgeMillis;
        private readonly IClock _clock;
        private bool _disposed;

        /// <summary>Builds a verifier.</summary>
        /// <param name="trustedRoots">
        /// Pinned root CAs — in production <see cref="AppleRootCertificates.JwsRoots"/>.
        /// Copied, so the caller may dispose theirs.
        /// </param>
        /// <param name="bundleId">The bundle id every payload must carry.</param>
        /// <param name="acceptedEnvironments">
        /// Environments to accept. Include <see cref="AppleEnvironment.Sandbox"/>
        /// on endpoints App Review can reach (PLAN.md D3).
        /// </param>
        /// <param name="appAppleId">
        /// The app's Apple id. Required to accept a Production
        /// <c>AppTransaction</c>; unused otherwise.
        /// </param>
        /// <param name="maxSignedAge">
        /// When set, a payload signed longer ago than this is rejected as
        /// <see cref="VerificationReason.StalePayload"/> (PLAN.md D5). This is
        /// the only check the clock drives.
        /// </param>
        /// <param name="clock">
        /// Source of "now" for the staleness rule; defaults to
        /// <see cref="SystemClock"/>. It never reaches a certificate-validity
        /// judgement — see <see cref="IClock"/>.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The roots are empty, the bundle id is null or empty, or the accepted
        /// set is empty. Misconfiguration is not a verification verdict, so it
        /// is never a <see cref="VerificationException"/>.
        /// </exception>
        public JwsVerifier(
            IEnumerable<X509Certificate2> trustedRoots,
            string bundleId,
            IEnumerable<AppleEnvironment> acceptedEnvironments,
            long? appAppleId = null,
            TimeSpan? maxSignedAge = null,
            IClock? clock = null)
        {
            if (string.IsNullOrEmpty(bundleId))
            {
                throw new ArgumentException("bundleId must not be empty", nameof(bundleId));
            }

            if (acceptedEnvironments is null)
            {
                throw new ArgumentException(
                    "acceptedEnvironments must not be empty", nameof(acceptedEnvironments));
            }

            HashSet<AppleEnvironment> accepted = new HashSet<AppleEnvironment>(acceptedEnvironments);
            if (accepted.Count == 0)
            {
                throw new ArgumentException(
                    "acceptedEnvironments must not be empty", nameof(acceptedEnvironments));
            }

            _anchors = Certificates.CopyAnchors(trustedRoots, nameof(trustedRoots));
            _bundleId = bundleId;
            _acceptedEnvironments = accepted;
            _appAppleId = appAppleId;
            _maxSignedAgeMillis = maxSignedAge is TimeSpan age ? (long)age.TotalMilliseconds : (long?)null;
            _clock = clock ?? SystemClock.Instance;
        }

        /// <summary>
        /// Verifies a signed transaction and enforces bundle id and environment.
        /// </summary>
        /// <exception cref="VerificationException">The payload did not verify.</exception>
        public TransactionPayload VerifyTransaction(string jws)
        {
            return Contained(() =>
            {
                IReadOnlyDictionary<string, object?> claims = VerifySignature(jws);
                TransactionPayload payload = new TransactionPayload(claims);
                RequireBundleId(payload.BundleId);
                RequireAcceptedEnvironment(payload.Environment);
                return payload;
            });
        }

        /// <summary>
        /// Verifies a signed <c>AppTransaction</c> and enforces bundle id,
        /// environment (<c>receiptType</c>) and — in Production — the app
        /// Apple id.
        /// </summary>
        /// <exception cref="VerificationException">The payload did not verify.</exception>
        public AppTransactionPayload VerifyAppTransaction(string jws)
        {
            return Contained(() =>
            {
                IReadOnlyDictionary<string, object?> claims = VerifySignature(jws);
                AppTransactionPayload payload = new AppTransactionPayload(claims);
                RequireBundleId(payload.BundleId);
                AppleEnvironment environment = RequireAcceptedEnvironment(payload.ReceiptType);
                if (environment == AppleEnvironment.Production
                    && (_appAppleId is null || _appAppleId != payload.AppAppleId))
                {
                    throw new VerificationException(
                        VerificationReason.WrongAppAppleId,
                        "the payload's app Apple id is not the configured one");
                }

                return payload;
            });
        }

        /// <summary>
        /// Verifies the chain and signature only and returns every claim — for
        /// payload types without a dedicated model (renewal info, notification
        /// envelopes).
        /// </summary>
        /// <remarks>
        /// <strong>No claim is enforced.</strong> The caller must check bundle
        /// id, environment and app Apple id in the returned map itself.
        /// </remarks>
        /// <exception cref="VerificationException">The payload did not verify.</exception>
        public IReadOnlyDictionary<string, object?> VerifyRaw(string jws)
        {
            return Contained(() => VerifySignature(jws));
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
        /// Containment by category, not by enumerating types. The parsers below
        /// are handed attacker-controlled bytes and the platform's failure
        /// surface is neither documented nor stable — <c>AsnContentException</c>
        /// alone derives from <see cref="Exception"/> and not from
        /// <see cref="CryptographicException"/>, so a type-by-type catch leaks.
        /// </summary>
        private T Contained<T>(Func<T> body)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(JwsVerifier));
            }

            try
            {
                return body();
            }
            catch (VerificationException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidJwsFormat, "malformed JWS input", e);
            }
        }

        private IReadOnlyDictionary<string, object?> VerifySignature(string jws)
        {
            if (jws is null)
            {
                throw Format("jws is null");
            }

            string[] parts = jws.Split('.');
            if (parts.Length != 3)
            {
                throw Format(
                    "expected 3 dot-separated segments, got "
                    + parts.Length.ToString(CultureInfo.InvariantCulture));
            }

            IReadOnlyDictionary<string, object?> header = ParseJsonSegment(parts[0], "header");
            if (Internal.Claims.String(header, "alg") != "ES256")
            {
                throw Format("alg must be ES256");
            }

            // Every entry has to be a string as well as present. The header is
            // attacker-supplied JSON, and a number reaching the base64 decode
            // instead was reported as INVALID_CERTIFICATE — a verdict saying
            // something was decoded and found wanting, when nothing had been
            // decoded at all.
            if (!(header.TryGetValue("x5c", out object? x5cValue) && x5cValue is List<object?> x5c)
                || x5c.Count != 3
                || !x5c.TrueForAll(static entry => entry is string))
            {
                throw Format("x5c must contain exactly 3 certificates");
            }

            // x5c[2] is never compared or trusted: only the intermediate
            // being signed by one of our pinned anchors counts, so swapping in
            // an attacker's third element changes nothing. It IS parsed, and
            // then dropped — an entry that is not a certificate is
            // INVALID_CERTIFICATE at every index
            // (transaction/reject-x5c-root-that-is-not-a-certificate).
            X509Certificate2 leaf = LoadX5cEntry((string)x5c[0]!);
            X509Certificate2 intermediate = LoadX5cEntry((string)x5c[1]!);
            LoadX5cEntry((string)x5c[2]!).Dispose();

            RequireMarkerOid(leaf, LeafOid, "leaf");
            RequireMarkerOid(intermediate, IntermediateOid, "intermediate");

            IReadOnlyDictionary<string, object?> payload = ParseJsonSegment(parts[1], "payload");
            double? signedAtMillis = SignedAtMillis(payload);

            // Deliberately DateTimeOffset.UtcNow and not the injected clock:
            // this is a certificate-validity instant, and an injected clock
            // must never be able to move a certificate-validity verdict. The
            // fallback only fires for a payload carrying neither signedDate nor
            // receiptCreationDate. This is the one place in the library that
            // reads the system clock directly.
            DateTimeOffset at = signedAtMillis is double millis
                ? EffectiveDate(millis)
                : DateTimeOffset.UtcNow;
            CertificateChain.ValidateJwsPair(leaf, intermediate, _anchors, at);

            VerifyEs256(leaf, parts[0] + "." + parts[1], DecodeBase64Url(parts[2], "signature"));

            // A payload that states no signing time has no age to be stale by,
            // so the rule does not apply to it — rather than measuring the
            // clock against itself.
            if (_maxSignedAgeMillis is long maxAge && signedAtMillis is double signedAt
                && _clock.UtcNow.ToUnixTimeMilliseconds() - signedAt > maxAge)
            {
                throw new VerificationException(
                    VerificationReason.StalePayload,
                    "the payload is older than the configured max signed age");
            }

            return payload;
        }

        private static double? SignedAtMillis(IReadOnlyDictionary<string, object?> payload)
        {
            return Internal.Claims.Number(payload, "signedDate")
                ?? Internal.Claims.Number(payload, "receiptCreationDate");
        }

        /// <summary>
        /// The instant the payload states, as a point in time. Truncates toward
        /// zero, which is what <c>new Date(x)</c> and Jackson's
        /// <c>asLong()</c> do with a fractional epoch-millisecond claim.
        /// </summary>
        /// <remarks>
        /// A stated instant no certificate can be valid at is a <em>failed</em>
        /// check, never a skipped one. Falling back to "now" here would move
        /// the validity verdict to the system clock and, because the staleness
        /// rule reads the same claim, disable that rule too — two checks
        /// silently dropped on the one claim that drives both. So it is
        /// rejected, and at the reason CONTRACT.md §2.1 step 9 owns, which is
        /// where Java (<c>new Date(long)</c> past the leaf's notAfter) and Node
        /// (an Invalid Date failing <c>validAt</c>'s NaN comparisons) also
        /// land.
        /// </remarks>
        private static DateTimeOffset EffectiveDate(double millis)
        {
            double truncated = Math.Truncate(millis);
            if (double.IsNaN(truncated)
                || truncated < MinUnixMilliseconds
                || truncated > MaxUnixMilliseconds)
            {
                throw new VerificationException(
                    VerificationReason.InvalidChain,
                    "certificate is not valid at the payload's signing time");
            }

            return DateTimeOffset.FromUnixTimeMilliseconds((long)truncated);
        }

        private static X509Certificate2 LoadX5cEntry(string base64)
        {
            byte[] der;
            try
            {
                der = Convert.FromBase64String(base64);
            }
            catch (FormatException e)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry is not valid base64", e);
            }

            X509Certificate2 certificate = Certificates.TryLoad(der)
                ?? throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry is not a valid certificate");

            // Four things the platform decoder lets past, settled here while
            // the verdict is still "this is not a certificate":
            //
            //  - the version, which it keeps as whatever integer it found.
            //    X.509 defines v1, v2 and v3 and nothing else, and nothing
            //    downstream reads the field, so without this a certificate
            //    claiming version 11 verifies like any other.
            //  - a repeated extension, which RFC 5280 4.2 forbids. Every
            //    reader downstream takes the first copy, so without this the
            //    CA flag, the key usage and the marker-OID lookup are each
            //    answered from a copy this library picked and another
            //    implementation need not pick the same one.
            //  - the public key, which it builds lazily, so a namedCurve this
            //    platform does not implement would otherwise surface in the
            //    issuer check and be reported as a chain failure.
            if (certificate.Version is < 1 or > 3)
            {
                certificate.Dispose();
                throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry has an unknown X.509 version");
            }

            CertificateFields? fields = CertificateFields.TryParse(certificate.RawData);
            if (fields?.HasDuplicateExtension == true)
            {
                certificate.Dispose();
                throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry carries a duplicate extension");
            }

            //  - an extension VALUE that stops decoding partway through, which
            //    it never looks inside.
            if (fields?.HasUndecodableExtension == true)
            {
                certificate.Dispose();
                throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry has an extension that does not decode");
            }

            if (!HasReadablePublicKey(certificate))
            {
                certificate.Dispose();
                throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry has an unreadable public key");
            }

            return certificate;
        }

        private static bool HasReadablePublicKey(X509Certificate2 certificate)
        {
            try
            {
                using (ECDsa? ec = certificate.GetECDsaPublicKey())
                {
                    if (ec is not null)
                    {
                        return true;
                    }
                }

                using (RSA? rsa = certificate.GetRSAPublicKey())
                {
                    return rsa is not null;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        private static void RequireMarkerOid(X509Certificate2 certificate, string oid, string role)
        {
            CertificateFields? fields = CertificateFields.TryParse(certificate.RawData);
            if (fields is null || fields.Extension(oid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose,
                    role + " certificate lacks Apple marker OID " + oid);
            }
        }

        private static void VerifyEs256(X509Certificate2 leaf, string signingInput, byte[] signature)
        {
            if (signature.Length != 64)
            {
                throw new VerificationException(
                    VerificationReason.InvalidSignature,
                    "an ES256 signature must be 64 bytes, got "
                    + signature.Length.ToString(CultureInfo.InvariantCulture));
            }

            using (ECDsa? key = leaf.GetECDsaPublicKey())
            {
                if (key is null)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "the leaf key is not EC");
                }

                bool valid;
                try
                {
                    // A JWS ES256 signature is already IEEE P1363 r‖s (RFC
                    // 7515), which is exactly what this overload wants. Do not
                    // port Java's p1363ToDer conversion: .NET's default is the
                    // opposite of JCA's.
                    valid = key.VerifyData(
                        Encoding.ASCII.GetBytes(signingInput), signature, HashAlgorithmName.SHA256);
                }
                catch (CryptographicException e)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "the ES256 signature check errored", e);
                }

                if (!valid)
                {
                    throw new VerificationException(
                        VerificationReason.InvalidSignature, "the ES256 signature check failed");
                }
            }
        }

        private static IReadOnlyDictionary<string, object?> ParseJsonSegment(string segment, string what)
        {
            try
            {
                object? parsed = Json.Parse(Encoding.UTF8.GetString(DecodeBase64Url(segment, what)));
                return parsed as OrderedMap ?? throw Format(what + " is not a JSON object");
            }
            catch (Internal.JsonException e)
            {
                throw Format(what + " is not valid JSON", e);
            }
            catch (DecoderFallbackException e)
            {
                throw Format(what + " is not valid UTF-8", e);
            }
        }

        // RFC 7515 §2: a compact-JWS segment is unpadded canonical base64url.
        // Reject anything outside A-Za-z0-9-_ (this also rejects '=' and
        // '+'/'/'), an impossible length (len % 4 == 1), and a segment whose
        // final character carries non-zero unused bits — checked by
        // requiring the decoded bytes to re-encode to the same string.
        private static byte[] DecodeBase64Url(string value, string what)
        {
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool isValid =
                    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
                if (!isValid)
                {
                    throw Format(what + " is not valid base64url");
                }
            }

            string standard = value.Replace('-', '+').Replace('_', '/');
            switch (standard.Length % 4)
            {
                case 2: standard += "=="; break;
                case 3: standard += "="; break;
                case 1: throw Format(what + " is not valid base64url");
                default: break;
            }

            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(standard);
            }
            catch (FormatException e)
            {
                throw Format(what + " is not valid base64url", e);
            }

            string reencoded = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (!string.Equals(reencoded, value, StringComparison.Ordinal))
            {
                throw Format(what + " is not valid base64url");
            }

            return decoded;
        }

        private void RequireBundleId(string? actual)
        {
            if (!string.Equals(_bundleId, actual, StringComparison.Ordinal))
            {
                throw new VerificationException(
                    VerificationReason.WrongBundleId,
                    "the payload's bundle id is not the configured one");
            }
        }

        private AppleEnvironment RequireAcceptedEnvironment(string? claim)
        {
            if (!AppleEnvironments.TryParse(claim, out AppleEnvironment environment)
                || !_acceptedEnvironments.Contains(environment))
            {
                throw new VerificationException(
                    VerificationReason.WrongEnvironment,
                    "the payload's environment is not in the accepted set");
            }

            return environment;
        }

        private static VerificationException Format(string detail, Exception? cause = null)
        {
            return new VerificationException(VerificationReason.InvalidJwsFormat, detail, cause);
        }
    }
}
