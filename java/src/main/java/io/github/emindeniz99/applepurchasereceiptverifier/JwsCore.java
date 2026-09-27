package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * The JWS half of {@link Verifier#verifySignedData}: verifies Apple-signed
 * compact JWS (StoreKit 2 {@code jwsRepresentation}, App Store Server
 * {@code signedTransactionInfo} and {@code signedRenewalInfo}, app
 * transactions, Server Notifications V2) completely offline, against pinned
 * Apple roots.
 *
 * <p>Algorithm: ES256 only, exactly 3 {@code x5c} certs, PKIX path
 * validation to the pinned roots at the payload's {@code signedDate} (the
 * clock when it states none), Apple marker OIDs on leaf and intermediate,
 * then the signature. Offline, like Apple's app-store-server-library with
 * online checks off: no OCSP, so a revoked certificate is not detected, in
 * exchange for no network call. No payload is rejected for its age.</p>
 *
 * <p>Stateless, so safe from many threads: the only shared objects are the
 * private BouncyCastle provider and a Jackson {@link JsonFactory}, both
 * documented thread-safe.</p>
 *
 * <p><strong>Security providers.</strong> Every cryptographic step uses a
 * private BouncyCastle instance that is never registered: the
 * {@code CertificateFactory} for the {@code x5c} certificates, the
 * {@code PKIX} {@code CertPathValidator}, and the ES256 signature check. The
 * JVM's provider list and its {@code java.security} policy,
 * {@code jdk.certpath.disabledAlgorithms} included, do not reach any of them,
 * so they cannot change a verdict.</p>
 */
final class JwsCore {

    /**
     * Ceiling on the compact JWS, in UTF-8 bytes, checked before the input is
     * split or any segment is decoded, because everything below allocates in
     * proportion to it and none of it is behind a signature check.
     *
     * <p>Real Apple JWS payloads, Apple's own mock notification data
     * included, are under 2.5 KB, so 256 KiB is a hundredfold headroom over
     * anything Apple has ever signed.</p>
     */
    static final int MAX_JWS_BYTES = 262144;

    // A segment cannot outgrow the whole JWS, so both length bounds are
    // MAX_JWS_BYTES: consistent with the entry-point bound rather than a
    // second opinion about it.
    static final JsonFactory JSON = BoundedJson.factory(MAX_JWS_BYTES);

    // Shared: BouncyCastle's PKIX validator keeps no per-call state (only
    // final fields, checked in 1.86). Its CertificateFactory keeps stream
    // state and a Signature is stateful by contract, so those stay per call.
    private static final CertPathValidator PKIX = pkixValidator();

    private JwsCore() {}

    /**
     * Verifies {@code jws} and returns its payload.
     *
     * <p>A broken outer structure fails as MALFORMED before any cryptography:
     * not three segments, a segment that is not canonical base64url, a header
     * that is not a JSON object, an {@code alg} other than ES256, an
     * {@code x5c} that is not three strings. A payload that does not parse as
     * a JSON object is not reported here: it is carried past the chain and
     * signature checks with {@code now} standing in for its signing
     * date, and fails as INVALID_SIGNATURE if the signature does not verify,
     * UNREADABLE_PAYLOAD if it does. Nothing unverified gets to decide which
     * of those two a caller sees.</p>
     */
    static JsonPayload verify(@Nullable String jws, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        if (jws == null || jws.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "jws is empty");
        }
        // Before the split, so nothing downstream allocates in proportion to
        // an input this verifier has already decided not to look at.
        if (Utf8Length.exceeds(jws, MAX_JWS_BYTES)) {
            throw new VerificationException(
                    Reason.TOO_LARGE, "jws exceeds the maximum accepted size of " + MAX_JWS_BYTES + " bytes");
        }
        // The steps known to throw unchecked (the x5c decode, the chain
        // check) map it themselves; this catches the ones nobody has found
        // yet, from Jackson or BouncyCastle. MALFORMED rather than
        // INTERNAL_ERROR on purpose: until the signature has verified,
        // everything here runs on input nobody has vouched for, and
        // answering an unknown error with INTERNAL_ERROR ("alert and
        // reconcile") would let anyone raise that alert at will.
        try {
            return verifyUnguarded(jws, trustAnchors, now);
        } catch (RuntimeException e) {
            throw new VerificationException(
                    Reason.MALFORMED, "unexpected " + e.getClass().getName(), e);
        }
    }

    /** Structure, then certificates, chain, OIDs, signature, and last the payload verdict. */
    private static JsonPayload verifyUnguarded(String jws, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        String[] parts = jws.split("\\.", -1);
        if (parts.length != 3) {
            throw new VerificationException(Reason.MALFORMED, "expected 3 dot-separated segments, got " + parts.length);
        }
        byte[] headerBytes = decodeBase64Url(parts[0], "header");
        byte[] payloadBytes = decodeBase64Url(parts[1], "payload");
        byte[] signature = decodeBase64Url(parts[2], "signature");

        Header header = Header.read(headerBytes);
        if (!"ES256".equals(header.alg)) {
            throw new VerificationException(Reason.MALFORMED, "alg must be ES256, got " + SafeText.quote(header.alg));
        }
        if (header.x5c == null || header.x5c.size() != 3) {
            throw new VerificationException(Reason.MALFORMED, "x5c must contain exactly 3 certificates");
        }
        // x5c[2] is decoded but unused: PKIX validates leaf + intermediate against the pinned anchors.
        List<X509Certificate> chain = decodeChain(header.x5c);
        X509Certificate leaf = chain.get(0);
        X509Certificate intermediate = chain.get(1);

        Payload payload = Payload.read(payloadBytes);
        authenticateTopDown(leaf, intermediate, trustAnchors);
        validateChain(
                leaf, intermediate, new Date(payload.signedDate != null ? payload.signedDate : now), trustAnchors);
        // The marker OIDs after the chain, as on the receipt path: a foreign
        // chain is UNTRUSTED_CHAIN whatever it carries. Still before the
        // leaf's key checks the JWS signature.
        if (leaf.getExtensionValue(AppleTrust.SIGNING_LEAF_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "leaf certificate lacks Apple marker OID " + AppleTrust.SIGNING_LEAF_OID);
        }
        if (intermediate.getExtensionValue(AppleTrust.INTERMEDIATE_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "intermediate certificate lacks Apple marker OID " + AppleTrust.INTERMEDIATE_OID);
        }
        verifyEs256(leaf, parts[0] + "." + parts[1], signature);
        if (payload.json == null) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD,
                    "signed payload is not a JSON object: " + payload.problem,
                    payload.error);
        }
        return new JsonPayload(payload.json);
    }

    /**
     * What verification reads from the header: the last {@code alg} and
     * {@code x5c} members, as Jackson's tree model would keep them. The
     * header is outer structure, so anything that stops the read is
     * MALFORMED: bytes that are not strict UTF-8 (Jackson would otherwise
     * guess UTF-16 or UTF-32 from them), a byte order mark (RFC 8259 section
     * 8.1 forbids one), and anything but whitespace after the object.
     */
    static final class Header {
        /** The {@code alg} string; null when absent or not a string. */
        @Nullable
        String alg;

        /** The {@code x5c} entries; null when absent, not an array, or holding anything but strings. */
        @Nullable
        List<String> x5c;

        static Header read(byte[] bytes) throws VerificationException {
            Header header = new Header();
            String text;
            try {
                text = jsonText(bytes);
            } catch (NotJsonText e) {
                throw new VerificationException(
                        Reason.MALFORMED, "header is not JSON text: " + e.getMessage(), e.getCause());
            }
            try (JsonParser parser = JSON.createParser(text.toCharArray())) {
                if (parser.nextToken() != JsonToken.START_OBJECT) {
                    throw new VerificationException(Reason.MALFORMED, "header is not a JSON object");
                }
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String name = parser.currentName();
                    JsonToken value = parser.nextToken();
                    if ("alg".equals(name)) {
                        header.alg = value == JsonToken.VALUE_STRING ? parser.getText() : null;
                    } else if ("x5c".equals(name)) {
                        header.x5c = value == JsonToken.START_ARRAY ? strings(parser) : null;
                    }
                    parser.skipChildren();
                }
                if (parser.nextToken() != null) {
                    throw new VerificationException(Reason.MALFORMED, "content after the header object");
                }
            } catch (IOException | RuntimeException e) {
                throw new VerificationException(Reason.MALFORMED, "header is not valid JSON", e);
            }
            return header;
        }

        /** The array's entries when all are strings, else null; leaves the parser on END_ARRAY. */
        private static @Nullable List<String> strings(JsonParser parser) throws IOException {
            List<String> entries = new ArrayList<String>(3);
            boolean allStrings = true;
            JsonToken token;
            while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
                if (token == JsonToken.VALUE_STRING) {
                    entries.add(parser.getText());
                } else {
                    allStrings = false;
                    parser.skipChildren();
                }
            }
            return allStrings ? entries : null;
        }
    }

    /**
     * What verification reads from the payload: the text, if it is a JSON
     * object in UTF-8 with nothing but whitespace after it and no byte order
     * mark before it, and its top-level {@code signedDate}. Reading it never
     * fails verification by itself; a payload that does not parse is carried
     * to the signature check (see {@link #verify}).
     */
    static final class Payload {
        /** The payload text; null when it is not a JSON object in UTF-8. */
        @Nullable
        String json;

        /** Why {@link #json} is null. */
        @Nullable
        String problem;

        @Nullable
        Exception error;

        /**
         * The last top-level {@code signedDate}, when it is a number a long
         * holds; null when absent, not a number, or out of that range.
         */
        @Nullable
        Long signedDate;

        static Payload read(byte[] bytes) {
            Payload payload = new Payload();
            String text;
            try {
                text = jsonText(bytes);
            } catch (NotJsonText e) {
                payload.unreadable(e.getMessage(), (Exception) e.getCause());
                return payload;
            }
            Long signedDate = null;
            try (JsonParser parser = JSON.createParser(text.toCharArray())) {
                if (parser.nextToken() != JsonToken.START_OBJECT) {
                    payload.unreadable("not an object", null);
                    return payload;
                }
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String name = parser.currentName();
                    JsonToken value = parser.nextToken();
                    if ("signedDate".equals(name)) {
                        // A number no long holds (1e300, say) is no instant,
                        // so it counts as not stated, like a string would.
                        signedDate = value == JsonToken.VALUE_NUMBER_INT || value == JsonToken.VALUE_NUMBER_FLOAT
                                ? instant(parser)
                                : null;
                    }
                    parser.skipChildren();
                }
                if (parser.nextToken() != null) {
                    payload.unreadable("content after the object", null);
                    return payload;
                }
            } catch (IOException | RuntimeException e) {
                // Unchecked too: whatever stops the parse, it is not reported
                // before the signature has been checked.
                payload.unreadable("not valid JSON", e);
                return payload;
            }
            payload.json = text;
            payload.signedDate = signedDate;
            return payload;
        }

        private void unreadable(String problem, @Nullable Exception error) {
            this.problem = problem;
            this.error = error;
        }

        /**
         * The number as epoch milliseconds, or null when no long holds it,
         * with the conversion Jackson's tree model applies: an integer must
         * fit a long, and a fraction or exponent is read as a double and
         * truncated if it lies within the long range.
         */
        private static @Nullable Long instant(JsonParser parser) throws IOException {
            if (parser.currentToken() == JsonToken.VALUE_NUMBER_INT) {
                JsonParser.NumberType type = parser.getNumberType();
                return type == JsonParser.NumberType.BIG_INTEGER ? null : Long.valueOf(parser.getLongValue());
            }
            double value = parser.getDoubleValue();
            return value >= Long.MIN_VALUE && value <= Long.MAX_VALUE ? Long.valueOf((long) value) : null;
        }
    }

    /**
     * A JWS segment as JSON text: strict UTF-8 (Jackson would otherwise guess
     * UTF-16 or UTF-32 from the bytes) with no byte order mark (RFC 8259
     * section 8.1 forbids one). The header and the payload share the rule
     * and differ only in what a refusal means.
     */
    private static String jsonText(byte[] bytes) throws NotJsonText {
        String text;
        try {
            text = StandardCharsets.UTF_8
                    .newDecoder()
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new NotJsonText("not UTF-8", e);
        }
        if (text.startsWith("\uFEFF")) {
            throw new NotJsonText("starts with a byte order mark", null);
        }
        return text;
    }

    /** Why a segment is not JSON text, as a short phrase. */
    private static final class NotJsonText extends Exception {
        private static final long serialVersionUID = 1L;

        NotJsonText(String problem, @Nullable Exception cause) {
            super(problem, cause);
        }
    }

    /**
     * Strict base64url (RFC 7515 §2): the JWS alphabet only, no padding, no
     * whitespace, and the decoded bytes must re-encode to the same string.
     * {@code java.util.Base64}'s URL decoder already rejects every character
     * outside the URL alphabet (whitespace and the standard-base64 {@code +}
     * and {@code /} included) and a length of 1 mod 4. It tolerates padding
     * and a final character whose unused bits are non-zero, and the
     * unpadded re-encode comparison rejects both.
     */
    private static byte[] decodeBase64Url(String value, String what) throws VerificationException {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            String reencoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
            if (!reencoded.equals(value)) {
                throw new VerificationException(Reason.MALFORMED, what + " is not canonical base64url");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.MALFORMED, what + " is not valid base64url", e);
        }
    }

    private static List<X509Certificate> decodeChain(List<String> x5c) throws VerificationException {
        List<X509Certificate> chain = new ArrayList<X509Certificate>(3);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER);
            for (String entry : x5c) {
                byte[] der = StrictBase64.decode(entry, Reason.INVALID_CERTIFICATE, "x5c entry");
                if (Asn1Depth.exceeded(der)) {
                    throw new VerificationException(
                            Reason.INVALID_CERTIFICATE,
                            "x5c[" + chain.size() + "] nests ASN.1 deeper than " + Asn1Depth.MAX_DEPTH + " values");
                }
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                // Result unused: BouncyCastle decodes the signature BIT
                // STRING lazily, so one that is not whole octets would
                // otherwise fail later, inside the path validator, as an
                // unchecked exception. The key is not read here: see
                // authenticateTopDown.
                certificate.getSignature();
                chain.add(certificate);
            }
        } catch (CertificateException | RuntimeException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c[" + chain.size() + "] does not decode", e);
        }
        return chain;
    }

    /**
     * Checks the two signatures from a pinned root down, decoding each
     * certificate's key only after the certificate above it has signed it.
     *
     * <p>BouncyCastle validates an RSA key as it decodes it, with a primality
     * test that costs seconds for a 16384-bit modulus, so decoding the keys
     * of certificates nobody has vouched for would let a small JWS cost
     * seconds of CPU. Here no key Apple did not sign is ever decoded, and
     * {@link #validateChain} then works on keys already authenticated.</p>
     */
    private static void authenticateTopDown(
            X509Certificate leaf, X509Certificate intermediate, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        if (!AppleTrust.signedByAny(intermediate, AppleTrust.roots(trustAnchors))) {
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN, "intermediate certificate is not signed by a pinned Apple root");
        }
        PublicKey intermediateKey = decodeKey(intermediate, 1);
        try {
            leaf.verify(intermediateKey, BouncyCastle.PROVIDER);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN, "leaf certificate is not signed by the intermediate", e);
        }
        decodeKey(leaf, 0);
    }

    /** The key of an x5c entry whose signature has already verified; one no decoder accepts is its verdict. */
    private static PublicKey decodeKey(X509Certificate certificate, int index) throws VerificationException {
        try {
            return certificate.getPublicKey();
        } catch (RuntimeException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c[" + index + "] does not decode", e);
        }
    }

    private static void validateChain(
            X509Certificate leaf, X509Certificate intermediate, Date at, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        try {
            CertPath path = CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER)
                    .generateCertPath(Arrays.asList(leaf, intermediate));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            params.setDate(at);
            PKIX.validate(path, params);
        } catch (CertPathValidatorException e) {
            throw AppleTrust.chainFailure(e, "x5c", "certificate chain", at);
        } catch (InvalidAlgorithmParameterException e) {
            // Raised for the pinned anchors or the path type, never for a certificate.
            throw new VerificationException(Reason.INTERNAL_ERROR, "chain validation rejected its parameters", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.UNTRUSTED_CHAIN, "path validator refused the path", e);
        } catch (RuntimeException e) {
            // BouncyCastle reports some malformed certificate content with
            // unchecked exceptions from inside the validator. Everything here
            // is attacker-controlled and unverified, so it is the chain's
            // failure, and it must not escape as anything but a verdict.
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN,
                    "path validator raised " + e.getClass().getName(),
                    e);
        }
    }

    private static CertPathValidator pkixValidator() {
        try {
            return CertPathValidator.getInstance("PKIX", BouncyCastle.PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("BouncyCastle PKIX validator unavailable", e);
        }
    }

    private static void verifyEs256(X509Certificate leaf, String signingInput, byte[] signature)
            throws VerificationException {
        if (signature.length != 64) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "ES256 signature must be 64 bytes, got " + signature.length);
        }
        try {
            Signature verifier = Signature.getInstance("SHA256withPLAIN-ECDSA", BouncyCastle.PROVIDER);
            // JWS ES256 signatures are raw r || s (RFC 7515), which
            // BouncyCastle's PLAIN-ECDSA takes as is. The JDK's own name for
            // it, SHA256withECDSAinP1363Format, is Java 9+ and this library
            // supports Java 8. An r or s not below the curve order throws
            // here where the JDK returned false; both are INVALID_SIGNATURE.
            verifier.initVerify(leaf.getPublicKey());
            verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signature)) {
                throw new VerificationException(
                        Reason.INVALID_SIGNATURE, "ES256 signature does not match the leaf key");
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "ES256 verifier refused the leaf key or the signature", e);
        }
    }
}
