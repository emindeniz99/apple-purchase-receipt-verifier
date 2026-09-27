using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// <c>verifySignedData(jws)</c>: any Apple-signed compact JWS, verified
    /// offline against pinned Apple roots.
    /// </summary>
    /// <remarks>
    /// ES256 only, exactly three <c>x5c</c> certificates, the chain to a
    /// pinned root at the payload's <c>signedDate</c>, Apple's marker OIDs on
    /// leaf and intermediate, then the signature.
    /// </remarks>
    internal static class JwsVerifierCore
    {
        internal const int MaxJwsBytes = 262144;

        private const string LeafOid = "1.2.840.113635.100.6.11.1";
        private const string IntermediateOid = "1.2.840.113635.100.6.2.1";

        // "Representable" means fits a 64-bit signed integer of milliseconds
        // (docs/design/0.7-api.md: "such as 1e300"), not the narrower range
        // DateTimeOffset supports: the chain instant is compared against a
        // certificate's own NotBefore/NotAfter as plain epoch-millisecond
        // longs (Chain.IsValidAt), so a signedDate far outside any calendar
        // DateTimeOffset can name is still usable — and, deliberately, still
        // fails a real certificate's validity window rather than falling
        // back to the clock.
        private const double MinUnixMilliseconds = -9223372036854775000d;
        private const double MaxUnixMilliseconds = 9223372036854775000d;

        internal static JsonPayload Verify(string? jws, IReadOnlyList<X509Certificate2> anchors, Func<long> clock)
        {
            if (string.IsNullOrEmpty(jws))
            {
                throw Malformed("jws is empty");
            }

            if (Utf8Length.Exceeds(jws!, MaxJwsBytes))
            {
                throw new VerificationException(
                    VerificationReason.TooLarge,
                    "jws exceeds the maximum accepted size of " + MaxJwsBytes + " bytes");
            }

            try
            {
                return VerifyUnguarded(jws!, anchors, clock);
            }
            catch (VerificationException)
            {
                throw;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                throw Malformed("unexpected error: " + e.GetType().Name, e);
            }
        }

        private static JsonPayload VerifyUnguarded(string jws, IReadOnlyList<X509Certificate2> anchors, Func<long> clock)
        {
            string[] parts = jws.Split('.');
            if (parts.Length != 3)
            {
                throw Malformed("expected 3 dot-separated segments, got " + parts.Length);
            }

            byte[]? headerBytes = Base64Url.Decode(parts[0]);
            if (headerBytes is null)
            {
                throw Malformed("header is not canonical base64url");
            }

            byte[]? payloadBytes = Base64Url.Decode(parts[1]);
            if (payloadBytes is null)
            {
                throw Malformed("payload is not canonical base64url");
            }

            byte[]? signature = Base64Url.Decode(parts[2]);
            if (signature is null)
            {
                throw Malformed("signature is not canonical base64url");
            }

            (string? alg, List<string>? x5c) = ReadHeader(headerBytes);
            if (alg != "ES256")
            {
                throw Malformed("alg must be ES256");
            }

            if (x5c is null || x5c.Count != 3)
            {
                throw Malformed("x5c must contain exactly 3 certificates");
            }

            LoadedCertificate leaf = ParseX5cEntry(x5c[0]);
            LoadedCertificate intermediate = ParseX5cEntry(x5c[1]);
            ParseX5cEntry(x5c[2]); // parsed, then dropped: nobody vouches for x5c[2].

            PayloadRead payload = ReadPayload(payloadBytes);
            long atMs = payload.SignedDateMs ?? CallClock.Read(clock);
            Chain.ValidatePair(leaf, intermediate, anchors, atMs);

            // The marker OIDs after the chain: a foreign chain is
            // UNTRUSTED_CHAIN whatever it carries, and only a pinned chain can
            // be the wrong kind of Apple certificate.
            if (leaf.Fields.Extension(LeafOid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose, "leaf certificate lacks Apple marker OID " + LeafOid);
            }

            if (intermediate.Fields.Extension(IntermediateOid) is null)
            {
                throw new VerificationException(
                    VerificationReason.InvalidCertificatePurpose,
                    "intermediate certificate lacks Apple marker OID " + IntermediateOid);
            }

            // The leaf's key is about to check the JWS signature; judged only
            // once vouched for and marked as Apple's, same as the
            // intermediate inside Chain.ValidatePair for its own key use.
            Chain.RequireBuildablePublicKey(leaf.Certificate, VerificationReason.InvalidCertificate, "leaf certificate");

            VerifyEs256(leaf, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature);

            if (payload.Json is null)
            {
                throw new VerificationException(
                    VerificationReason.UnreadablePayload, "signed payload is not a JSON object: " + payload.Problem);
            }

            return JsonPayload.Create(payload.Json);
        }

        private static void VerifyEs256(LoadedCertificate leaf, byte[] signingInput, byte[] signature)
        {
            if (signature.Length != 64)
            {
                throw new VerificationException(
                    VerificationReason.InvalidSignature, "an ES256 signature must be 64 bytes");
            }

            bool valid;
            try
            {
                using (ECDsa? key = leaf.Certificate.GetECDsaPublicKey())
                {
                    valid = key is not null
                        && key.VerifyData(signingInput, signature, HashAlgorithmName.SHA256);
                }
            }
            catch (CryptographicException)
            {
                valid = false;
            }

            if (!valid)
            {
                throw new VerificationException(VerificationReason.InvalidSignature, "ES256 signature does not match the leaf key");
            }
        }

        private static LoadedCertificate ParseX5cEntry(string base64)
        {
            byte[]? der = CanonicalBase64.Decode(base64)
                ?? throw new VerificationException(VerificationReason.InvalidCertificate, "x5c entry is not valid base64");

            X509Certificate2? certificate = Certificates.TryLoad(der);
            CertificateFields? fields = certificate is not null ? CertificateFields.TryParse(der) : null;
            if (certificate is null || fields is null)
            {
                throw new VerificationException(VerificationReason.InvalidCertificate, "x5c entry is not a valid certificate");
            }

            LoadedCertificate loaded = new LoadedCertificate(certificate, fields);
            Chain.RequireStructurallySound(loaded, VerificationReason.InvalidCertificate, "x5c entry");
            return loaded;
        }

        private static (string? Alg, List<string>? X5c) ReadHeader(byte[] bytes)
        {
            string? text = StrictUtf8.Decode(bytes);
            if (text is null)
            {
                throw Malformed("header is not UTF-8");
            }

            if (text.Length > 0 && text[0] == '﻿')
            {
                throw Malformed("header starts with a byte order mark");
            }

            OrderedMap members;
            try
            {
                members = Json.ParseObject(text);
            }
            catch (JsonException e)
            {
                throw Malformed("header is not valid JSON", e);
            }

            string? alg = members.TryGetValue("alg", out object? algValue) ? algValue as string : null;
            List<string>? x5c = null;
            if (members.TryGetValue("x5c", out object? x5cValue) && x5cValue is List<object?> list)
            {
                x5c = new List<string>(list.Count);
                foreach (object? entry in list)
                {
                    if (entry is not string s)
                    {
                        return (alg, null);
                    }

                    x5c.Add(s);
                }
            }

            return (alg, x5c);
        }

        private readonly struct PayloadRead
        {
            internal PayloadRead(string? json, string? problem, long? signedDateMs)
            {
                Json = json;
                Problem = problem;
                SignedDateMs = signedDateMs;
            }

            internal string? Json { get; }

            internal string? Problem { get; }

            internal long? SignedDateMs { get; }
        }

        /// <summary>
        /// Reads what verification needs from the payload: the text, if it is
        /// a JSON object in UTF-8 with nothing but whitespace after it and no
        /// byte order mark before it, and its top-level <c>signedDate</c>.
        /// Reading it never fails verification by itself; a payload that does
        /// not parse is carried to the signature check.
        /// </summary>
        private static PayloadRead ReadPayload(byte[] bytes)
        {
            string? text = StrictUtf8.Decode(bytes);
            if (text is null)
            {
                return new PayloadRead(null, "not UTF-8", null);
            }

            if (text.Length > 0 && text[0] == '﻿')
            {
                return new PayloadRead(null, "starts with a byte order mark", null);
            }

            object? value;
            int consumed;
            try
            {
                (value, consumed) = Json.ParsePrefix(text);
            }
            catch (JsonException)
            {
                return new PayloadRead(null, "not valid JSON", null);
            }

            if (value is not OrderedMap members)
            {
                return new PayloadRead(null, "not an object", null);
            }

            if (!OnlyWhitespaceAfter(text, consumed))
            {
                return new PayloadRead(null, "content after the object", null);
            }

            long? signedDate = members.TryGetValue("signedDate", out object? claim) ? AsInstantMs(claim) : null;
            return new PayloadRead(text, null, signedDate);
        }

        private static bool OnlyWhitespaceAfter(string text, int index)
        {
            for (int i = index; i < text.Length; i++)
            {
                if (!IsWhitespace(text[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsWhitespace(char c) => c is ' ' or '\t' or '\n' or '\r';

        private static long? AsInstantMs(object? value)
        {
            double asDouble;
            switch (value)
            {
                case long l: asDouble = l; break;
                case double d: asDouble = d; break;
                default: return null;
            }

            double truncated = Math.Truncate(asDouble);
            if (double.IsNaN(truncated) || truncated < MinUnixMilliseconds || truncated > MaxUnixMilliseconds)
            {
                return null;
            }

            return (long)truncated;
        }

        private static VerificationException Malformed(string detail, Exception? cause = null) =>
            new VerificationException(VerificationReason.Malformed, detail, cause);
    }
}
