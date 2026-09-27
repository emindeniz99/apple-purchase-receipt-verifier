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
 * The JWS half of {@link Verifier#verifySignedData}, offline, against the
 * pinned roots: ES256, three {@code x5c} certificates, no revocation check.
 * Stateless; every cryptographic step uses {@link BouncyCastle#PROVIDER}.
 */
final class JwsCore {

    /** In UTF-8 bytes, checked before the split; genuine JWS run from a few KB to roughly 15 KB. */
    static final int MAX_JWS_BYTES = 262144;

    static final JsonFactory JSON = BoundedJson.factory(MAX_JWS_BYTES);

    // Shared: BouncyCastle's validator keeps no per-call state; see java/README.md.
    private static final CertPathValidator PKIX = pkixValidator();

    private JwsCore() {}

    /**
     * Verifies {@code jws} and returns its payload. A payload that is not a
     * JSON object is judged only after the signature (docs/design/0.7-api.md,
     * "Which failure a parse problem gets").
     */
    static JsonPayload verify(@Nullable String jws, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        if (jws == null || jws.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "jws is empty");
        }
        if (Utf8Length.exceeds(jws, MAX_JWS_BYTES)) {
            throw new VerificationException(
                    Reason.TOO_LARGE, "jws exceeds the maximum accepted size of " + MAX_JWS_BYTES + " bytes");
        }
        // MALFORMED, not INTERNAL_ERROR, for what Jackson or BouncyCastle
        // throw unchecked: nothing is signed yet, and anyone could otherwise
        // raise the 21009 alarm.
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
            throw new VerificationException(Reason.MALFORMED, "alg is not ES256");
        }
        if (header.x5c == null || header.x5c.size() != 3) {
            throw new VerificationException(Reason.MALFORMED, "x5c must contain exactly 3 certificates");
        }
        // x5c[2] is decoded but unused: the pinned anchor stands in for it.
        List<X509Certificate> chain = decodeChain(header.x5c);
        X509Certificate leaf = chain.get(0);
        X509Certificate intermediate = chain.get(1);

        // The sender's signedDate picks the instant the chain must be valid at,
        // before anything is trusted. That only moves the validity window; the
        // signature and the chain to a pinned root are still required, as in
        // Apple's own rule. Absent or unreadable, the clock stands in.
        Long signedDate = signedDate(payloadBytes);
        authenticateTopDown(leaf, intermediate, trustAnchors);
        validateChain(leaf, intermediate, new Date(signedDate != null ? signedDate : now), trustAnchors);
        // After the chain, so a foreign chain is UNTRUSTED_CHAIN whatever it carries.
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
        requireJsonObject(payloadBytes);
        return new JsonPayload(new String(payloadBytes, StandardCharsets.UTF_8));
    }

    /**
     * The header's last {@code alg} and {@code x5c} members. Outer structure,
     * so anything that stops the read, content after the object included, is
     * MALFORMED.
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
            readObject(bytes, Reason.MALFORMED, "header", (name, value, parser) -> {
                if ("alg".equals(name)) {
                    header.alg = value == JsonToken.VALUE_STRING ? parser.getText() : null;
                } else if ("x5c".equals(name)) {
                    header.x5c = value == JsonToken.START_ARRAY ? strings(parser) : null;
                }
            });
            return header;
        }

        /** The array's entries when all are strings, else null; leaves the parser on END_ARRAY. */
        private static @Nullable List<String> strings(JsonParser parser) throws IOException {
            List<String> entries = new ArrayList<>(3);
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
     * The payload's last top-level {@code signedDate} as epoch milliseconds,
     * or null when it is absent, not a representable instant, or the payload
     * does not read. Never throws: nothing is trusted yet.
     */
    static @Nullable Long signedDate(byte[] payload) {
        try {
            return readPayload(payload);
        } catch (VerificationException e) {
            return null;
        }
    }

    /** Refuses, as UNREADABLE_PAYLOAD, a signed payload that is not one JSON object in strict UTF-8. */
    static void requireJsonObject(byte[] payload) throws VerificationException {
        readPayload(payload);
    }

    /** Reads the payload as one JSON object with nothing after it; returns its last top-level signedDate. */
    private static @Nullable Long readPayload(byte[] payload) throws VerificationException {
        Long[] signedDate = {null};
        readObject(payload, Reason.UNREADABLE_PAYLOAD, "signed payload", (name, value, parser) -> {
            if ("signedDate".equals(name)) {
                signedDate[0] = instant(parser, value);
            }
        });
        return signedDate[0];
    }

    /** Called with each member's name and first value token; may consume the value. */
    private interface FieldVisitor {
        void field(String name, JsonToken value, JsonParser parser) throws IOException;
    }

    /**
     * Reads {@code bytes} as one JSON object in strict UTF-8 with nothing
     * after it, handing each top-level member to {@code visitor}; anything
     * else is {@code reason}.
     */
    private static void readObject(byte[] bytes, Reason reason, String what, FieldVisitor visitor)
            throws VerificationException {
        String text = jsonText(bytes);
        if (text == null) {
            throw notAnObject(reason, what, "not UTF-8 JSON text", null);
        }
        try (JsonParser parser = JSON.createParser(text.toCharArray())) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw notAnObject(reason, what, "not an object", null);
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                visitor.field(name, parser.nextToken(), parser);
                parser.skipChildren();
            }
            if (parser.nextToken() != null) {
                throw notAnObject(reason, what, "content after the object", null);
            }
        } catch (IOException | RuntimeException e) {
            throw notAnObject(reason, what, "not valid JSON", e);
        }
    }

    private static VerificationException notAnObject(
            Reason reason, String what, String problem, @Nullable Exception cause) {
        return new VerificationException(reason, what + " is not a JSON object: " + problem, cause);
    }

    /**
     * A number as epoch milliseconds, the way Jackson's tree model converts
     * it: an integer must fit a long, and a fraction or exponent is read as
     * a double and truncated when it lies within the long range (2^63
     * saturates). Null for anything else, 1e300 included.
     */
    private static @Nullable Long instant(JsonParser parser, JsonToken value) {
        try {
            if (value == JsonToken.VALUE_NUMBER_INT) {
                return parser.getLongValue();
            }
            if (value == JsonToken.VALUE_NUMBER_FLOAT) {
                double number = parser.getDoubleValue();
                return number >= Long.MIN_VALUE && number <= Long.MAX_VALUE ? (long) number : null;
            }
        } catch (IOException e) {
            // An integer no long holds.
        }
        return null;
    }

    /** Strict UTF-8 with no byte order mark (RFC 8259 8.1), or null; Jackson would guess UTF-16 or UTF-32. */
    private static @Nullable String jsonText(byte[] bytes) {
        try {
            String text = StandardCharsets.UTF_8
                    .newDecoder()
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
            return text.startsWith("\uFEFF") ? null : text;
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /**
     * Strict base64url (RFC 7515 2). The re-encode comparison refuses the
     * padding and the non-zero unused bits that the URL decoder tolerates.
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
        List<X509Certificate> chain = new ArrayList<>(3);
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
                // Forces BouncyCastle's lazy signature decode here, not inside
                // the validator. The key is not read: see authenticateTopDown.
                certificate.getSignature();
                chain.add(certificate);
            }
        } catch (CertificateException | RuntimeException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c[" + chain.size() + "] does not decode", e);
        }
        return chain;
    }

    /** Checks both signatures from a pinned root down, decoding a key only once it is vouched for; see {@link AppleTrust}. */
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
            // BouncyCastle's unchecked exceptions for malformed certificate content.
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
            // Raw r || s (RFC 7515), as PLAIN-ECDSA takes it; the JDK's
            // P1363 name is Java 9+.
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
