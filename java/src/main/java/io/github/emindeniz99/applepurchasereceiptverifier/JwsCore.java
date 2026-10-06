package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
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

    static final JsonFactory JSON = JsonFields.factory();

    // Raw r || s (RFC 7515), as PLAIN-ECDSA takes it; the JDK's P1363 name is Java 9+.
    static final String ES256_ALGORITHM = "SHA256withPLAIN-ECDSA";

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
        // What Jackson or BouncyCastle throw unchecked. No known input
        // reaches this catch (the steps below contain their own failures);
        // it keeps verify from throwing if one ever does.
        try {
            return verifyUnguarded(jws, trustAnchors, now);
        } catch (RuntimeException e) {
            throw VerificationException.unexpected(e);
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
        // Apple's own rule. Absent or unreadable, the receiptCreationDate an app
        // transaction carries stands in, as in Apple's library, then the clock.
        Payload read = readOrNull(payloadBytes);
        Long carried = read == null ? null : read.chainInstant();
        authenticateTopDown(leaf, intermediate, trustAnchors);
        validateChain(leaf, intermediate, new Date(carried != null ? carried : now), trustAnchors);
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
        // A payload that did not read fails here, as UNREADABLE_PAYLOAD.
        Payload payload = read != null ? read : readPayload(payloadBytes);
        return new JsonPayload(new String(payloadBytes, StandardCharsets.UTF_8), payload.environment());
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

    private static @Nullable Payload readOrNull(byte[] payload) {
        try {
            return readPayload(payload);
        } catch (VerificationException e) {
            return null;
        }
    }

    /**
     * Reads the payload as one JSON object with nothing after it, once, for
     * everything this class needs of it. Package-private for the tests and
     * the fuzz harness, which drive it directly.
     */
    static Payload readPayload(byte[] payload) throws VerificationException {
        Payload read = new Payload();
        readObject(payload, Reason.UNREADABLE_PAYLOAD, "signed payload", (name, value, parser) -> {
            if ("signedDate".equals(name)) {
                read.signedDate = JsonFields.instant(parser, value);
            } else if ("receiptCreationDate".equals(name)) {
                read.receiptCreationDate = JsonFields.instant(parser, value);
            } else if ("environment".equals(name)) {
                read.topLevel.state(value, parser);
            } else if ("data".equals(name)) {
                read.data.readContainer(value, parser);
            } else if ("summary".equals(name)) {
                read.summary.readContainer(value, parser);
            }
        });
        return read;
    }

    /**
     * What one read of a signed payload yields: its last top-level
     * {@code signedDate} and {@code receiptCreationDate}, and the three places Apple documents for its
     * environment. A repeated name keeps its last value, a repeated
     * {@code data} or {@code summary} included, as everywhere in a payload.
     */
    static final class Payload {
        @Nullable
        Long signedDate;

        /** The last top-level {@code receiptCreationDate}: an app transaction's. */
        @Nullable
        Long receiptCreationDate;

        /** The instant the chain is judged at: {@code signedDate}, else {@code receiptCreationDate}. */
        @Nullable
        Long chainInstant() {
            return signedDate != null ? signedDate : receiptCreationDate;
        }

        /** The top-level {@code environment}: a transaction, renewal info. */
        final Place topLevel = new Place();

        /** {@code data.environment}: an App Store Server Notification V2. */
        final Place data = new Place();

        /** {@code summary.environment}: a summary notification. */
        final Place summary = new Place();

        /**
         * The first of the three places that is present decides, whatever
         * its value: {@code Production} and {@code Sandbox} map, anything
         * else is null, as is a payload with none of them. The core states
         * the same rule (rust/src/jws.rs; DECISIONS.md R42).
         */
        @Nullable
        Environment environment() {
            for (Place place : new Place[] {topLevel, data, summary}) {
                if (place.present) {
                    return jwsEnvironment(place.value);
                }
            }
            return null;
        }
    }

    /** One place an {@code environment} member may be: whether it is there, and its string value. */
    static final class Place {
        boolean present;

        /** The value when it is a string, else null. */
        @Nullable
        String value;

        /** The member is here: its value is {@code token}, which this leaves for the caller to skip. */
        void state(JsonToken token, JsonParser parser) throws IOException {
            present = true;
            value = token == JsonToken.VALUE_STRING ? parser.getText() : null;
        }

        /**
         * Reads a {@code data} or {@code summary} member for its
         * {@code environment}, forgetting an earlier one of the same name. A
         * value that is not an object holds none. Leaves the parser on the
         * object's closing brace.
         */
        void readContainer(JsonToken token, JsonParser parser) throws IOException {
            present = false;
            value = null;
            if (token != JsonToken.START_OBJECT) {
                return;
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                JsonToken member = parser.nextToken();
                if ("environment".equals(name)) {
                    state(member, parser);
                }
                parser.skipChildren();
            }
        }
    }

    /**
     * What a JWS {@code environment} value names: {@code Production} is
     * {@link Environment#PRODUCTION}, {@code Sandbox} is
     * {@link Environment#SANDBOX}, anything else ({@code Xcode},
     * {@code LocalTesting}, a value that is not a string) is null.
     */
    static @Nullable Environment jwsEnvironment(@Nullable String value) {
        if ("Production".equals(value)) {
            return Environment.PRODUCTION;
        }
        if ("Sandbox".equals(value)) {
            return Environment.SANDBOX;
        }
        return null;
    }

    /**
     * Reads {@code bytes} as one JSON object in strict UTF-8 with nothing
     * after it, handing each top-level member to {@code visitor}; anything
     * else is {@code reason}.
     */
    private static void readObject(byte[] bytes, Reason reason, String what, JsonFields.Visitor visitor)
            throws VerificationException {
        String text = JsonFields.text(bytes);
        if (text == null) {
            throw notAnObject(reason, what, "not UTF-8 JSON text", null);
        }
        try (JsonParser parser = JSON.createParser(text.toCharArray())) {
            if (!JsonFields.read(parser, visitor)) {
                throw notAnObject(reason, what, "not an object", null);
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
            params.addCertPathChecker(AppleTrust.HANDLED_CRITICAL_EXTENSIONS);
            // Per call, so no BouncyCastle object is shared between threads.
            CertPathValidator.getInstance("PKIX", BouncyCastle.PROVIDER).validate(path, params);
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

    /**
     * ES256 is P-256 with a 64-byte r || s (RFC 7518 3.4). PLAIN-ECDSA alone
     * takes twice the leaf curve's order, so without the length check a
     * P-384 leaf would verify a 96-byte signature.
     */
    private static void verifyEs256(X509Certificate leaf, String signingInput, byte[] signature)
            throws VerificationException {
        if (signature.length != 64) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "ES256 signature must be 64 bytes, got " + signature.length);
        }
        try {
            Signature verifier = Signature.getInstance(ES256_ALGORITHM, BouncyCastle.PROVIDER);
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
