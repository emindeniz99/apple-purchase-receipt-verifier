package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifies Apple-signed JWS payloads (StoreKit 2 {@code jwsRepresentation},
 * App Store Server {@code signedTransactionInfo} / {@code signedRenewalInfo},
 * Server Notifications V2) completely offline, against pinned Apple roots.
 *
 * <p>Algorithm: PLAN.md §2.1 — ES256 only, exactly 3 {@code x5c} certs,
 * Apple marker OIDs on leaf and intermediate, PKIX path validation to the
 * pinned roots at the payload's signing time, then signature + claim checks.
 * Mirrors the checks of Apple's official app-store-server-library in offline
 * mode (no OCSP — see PLAN.md §2.3 for the trade-off).</p>
 *
 * <p>Thread-safe once constructed.</p>
 */
public final class JwsVerifier {

    /** Apple marker OID: leaf certificate used for App Store signing. */
    static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

    private final Set<TrustAnchor> trustAnchors;
    private final String bundleId;
    private final Set<Environment> acceptedEnvironments;
    private final Long appAppleId;
    private final Long maxSignedAgeMillis;
    private final Clock clock;
    private final ObjectMapper mapper;

    /**
     * @param trustedRoots         pinned root CAs (production:
     *                             {@code AppleRootCerts.jwsRoots()})
     * @param bundleId             the app's bundle id every payload must carry
     * @param acceptedEnvironments environments to accept — include SANDBOX in
     *                             endpoints App Review can hit (PLAN.md D3)
     */
    public JwsVerifier(Set<X509Certificate> trustedRoots, String bundleId,
                       Set<Environment> acceptedEnvironments) {
        this(trustedRoots, bundleId, acceptedEnvironments, null, null, null);
    }

    /**
     * @param appAppleId   the app's Apple id; required to accept PRODUCTION
     *                     AppTransactions, unused otherwise
     * @param maxSignedAge if non-null, payloads whose signing time is older
     *                     than this many milliseconds are rejected as
     *                     {@link Reason#STALE_PAYLOAD} (PLAN.md D5)
     */
    public JwsVerifier(Set<X509Certificate> trustedRoots, String bundleId,
                       Set<Environment> acceptedEnvironments, Long appAppleId,
                       Long maxSignedAge) {
        this(trustedRoots, bundleId, acceptedEnvironments, appAppleId, maxSignedAge, null);
    }

    /**
     * @param clock source of "now" for the time-dependent checks; {@code null}
     *              (the default of every other constructor) means
     *              {@link Clock#systemUTC()}, so existing callers are
     *              unaffected. {@code java.time.Clock} is the JDK's own
     *              injectable time source — it supplies an instant rather than
     *              a timestamp or a duration, {@link Clock#fixed} pins it for
     *              a test, and it is available on the Java 8 baseline (PLAN.md
     *              D2), so no bespoke supplier interface is needed.
     *
     *              <p>It drives exactly one thing: the {@code maxSignedAge}
     *              staleness rule. Certificate validity is NEVER judged by it
     *              — at the payload's own signing date when the payload states
     *              one (PLAN.md §2.1 step 4), and at the system clock when it
     *              states none — so an injected clock cannot move a
     *              chain verdict for any payload at all.</p>
     */
    public JwsVerifier(Set<X509Certificate> trustedRoots, String bundleId,
                       Set<Environment> acceptedEnvironments, Long appAppleId,
                       Long maxSignedAge, Clock clock) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        if (bundleId == null) {
            throw new IllegalArgumentException("bundleId must not be null");
        }
        if (acceptedEnvironments == null || acceptedEnvironments.isEmpty()) {
            throw new IllegalArgumentException("acceptedEnvironments must not be empty");
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        this.trustAnchors = anchors;
        this.bundleId = bundleId;
        this.acceptedEnvironments = EnumSet.copyOf(acceptedEnvironments);
        this.appAppleId = appAppleId;
        this.maxSignedAgeMillis = maxSignedAge;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.mapper = new ObjectMapper()
                .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    }

    /**
     * Verifies a signed transaction ({@code jwsRepresentation} /
     * {@code signedTransactionInfo}) and checks bundle id + environment.
     */
    public TransactionPayload verifyTransaction(String jws) throws VerificationException {
        JsonNode node = verifySignature(jws);
        TransactionPayload payload;
        try {
            payload = mapper.treeToValue(node, TransactionPayload.class);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "unparseable transaction payload", e);
        }
        requireBundleId(payload.bundleId());
        requireAcceptedEnvironment(payload.environment());
        return payload;
    }

    /**
     * Verifies a signed {@code AppTransaction} and checks bundle id,
     * environment ({@code receiptType}), and — in PRODUCTION — the app Apple id.
     */
    public AppTransactionPayload verifyAppTransaction(String jws) throws VerificationException {
        JsonNode node = verifySignature(jws);
        AppTransactionPayload payload;
        try {
            payload = mapper.treeToValue(node, AppTransactionPayload.class);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "unparseable AppTransaction payload", e);
        }
        requireBundleId(payload.bundleId());
        Environment env = requireAcceptedEnvironment(payload.receiptType());
        if (env == Environment.PRODUCTION
                && (appAppleId == null || !appAppleId.equals(payload.appAppleId()))) {
            throw new VerificationException(Reason.WRONG_APP_APPLE_ID,
                    "expected " + appAppleId + " but payload has " + payload.appAppleId());
        }
        return payload;
    }

    /**
     * Verifies the signature/chain only and returns the raw claims — for
     * payload types without a dedicated model (renewal info, notification
     * envelopes). <strong>The caller must check bundle id / environment /
     * app Apple id in the returned claims itself.</strong>
     */
    public Map<String, Object> verifyRaw(String jws) throws VerificationException {
        JsonNode node = verifySignature(jws);
        return mapper.convertValue(node, new TypeReference<Map<String, Object>>() {
        });
    }

    /** Cryptographic verification: format → certs → OIDs → chain → signature. */
    private JsonNode verifySignature(String jws) throws VerificationException {
        if (jws == null) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "jws is null");
        }
        String[] parts = jws.split("\\.", -1);
        if (parts.length != 3) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT,
                    "expected 3 dot-separated segments, got " + parts.length);
        }
        JsonNode header = parseJson(parts[0], "header");
        if (!"ES256".equals(header.path("alg").asText())) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT,
                    "alg must be ES256, got " + header.path("alg").asText());
        }
        JsonNode x5c = header.path("x5c");
        if (!x5c.isArray() || x5c.size() != 3) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT,
                    "x5c must contain exactly 3 certificates");
        }
        List<X509Certificate> chain = decodeChain(x5c);
        X509Certificate leaf = chain.get(0);
        X509Certificate intermediate = chain.get(1);
        if (leaf.getExtensionValue(LEAF_OID) == null) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE_PURPOSE,
                    "leaf certificate lacks Apple marker OID " + LEAF_OID);
        }
        if (intermediate.getExtensionValue(INTERMEDIATE_OID) == null) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE_PURPOSE,
                    "intermediate certificate lacks Apple marker OID " + INTERMEDIATE_OID);
        }

        JsonNode payload = parseJson(parts[1], "payload");
        Long signedAtMillis = signedAtMillis(payload);
        // Deliberately System.currentTimeMillis(), not this.clock: the instant
        // below is a certificate-validity instant, and an injected clock must
        // never be able to move a certificate-validity verdict. The fallback
        // only fires for a payload carrying neither signedDate nor
        // receiptCreationDate, where PLAN.md §2.1 step 4's "else current time"
        // leaves the window anchored to real time. node and python agree.
        validateChain(leaf, intermediate, signedAtMillis != null
                ? new Date(signedAtMillis.longValue()) : new Date());

        byte[] signature = decodeBase64Url(parts[2], "signature");
        verifyEs256(leaf, parts[0] + "." + parts[1], signature);

        // A payload that states no signing time has no age to be stale by, so
        // the rule does not apply to it — rather than measuring the clock
        // against itself.
        if (maxSignedAgeMillis != null && signedAtMillis != null) {
            long signedAt = signedAtMillis.longValue();
            if (clock.millis() - signedAt > maxSignedAgeMillis) {
                throw new VerificationException(Reason.STALE_PAYLOAD,
                        "payload signed at " + signedAt + " exceeds max age " + maxSignedAgeMillis + "ms");
            }
        }
        return payload;
    }

    private JsonNode parseJson(String base64Url, String what) throws VerificationException {
        byte[] bytes = decodeBase64Url(base64Url, what);
        try {
            return mapper.readTree(bytes);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not valid JSON", e);
        }
    }

    private static byte[] decodeBase64Url(String value, String what) throws VerificationException {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not valid base64url", e);
        }
    }

    private static List<X509Certificate> decodeChain(JsonNode x5c) throws VerificationException {
        List<X509Certificate> chain = new ArrayList<X509Certificate>(3);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (JsonNode certNode : x5c) {
                byte[] der = Base64.getMimeDecoder().decode(certNode.asText());
                chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c entry is not valid base64", e);
        } catch (CertificateException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c entry is not a valid certificate", e);
        }
        return chain;
    }

    /**
     * Signing time the payload states: {@code signedDate} (transactions,
     * renewal info, notifications) or {@code receiptCreationDate}
     * (AppTransaction), or {@code null} when it states neither. Chain validity
     * is checked at this instant so payloads signed with since-rotated
     * certificates keep verifying (PLAN.md §2.1 step 4).
     */
    private static Long signedAtMillis(JsonNode payload) {
        JsonNode signedDate = payload.path("signedDate");
        if (signedDate.canConvertToLong()) {
            return Long.valueOf(signedDate.asLong());
        }
        JsonNode receiptCreationDate = payload.path("receiptCreationDate");
        if (receiptCreationDate.canConvertToLong()) {
            return Long.valueOf(receiptCreationDate.asLong());
        }
        return null;
    }

    private void validateChain(X509Certificate leaf, X509Certificate intermediate, Date at)
            throws VerificationException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath path = cf.generateCertPath(Arrays.asList(leaf, intermediate));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            params.setDate(at);
            CertPathValidator.getInstance("PKIX").validate(path, params);
        } catch (CertPathValidatorException e) {
            throw new VerificationException(Reason.INVALID_CHAIN,
                    "certificate chain does not validate to a pinned Apple root: " + e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation rejected parameters", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation unavailable", e);
        }
    }

    private static void verifyEs256(X509Certificate leaf, String signingInput, byte[] signature)
            throws VerificationException {
        if (signature.length != 64) {
            throw new VerificationException(Reason.INVALID_SIGNATURE,
                    "ES256 signature must be 64 bytes, got " + signature.length);
        }
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(leaf.getPublicKey());
            verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(p1363ToDer(signature))) {
                throw new VerificationException(Reason.INVALID_SIGNATURE, "ES256 signature check failed");
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "ES256 signature check errored", e);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "signature re-encoding failed", e);
        }
    }

    /**
     * JWS ES256 signatures are raw {@code r ‖ s} (RFC 7515); JCA's
     * SHA256withECDSA wants ASN.1 DER. The P1363-format JCA algorithm would
     * avoid this, but it's Java 9+ and our baseline is 8 (PLAN.md D2).
     */
    private static byte[] p1363ToDer(byte[] p1363) throws IOException {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(p1363, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363, 32, 64));
        return new DERSequence(new ASN1Encodable[]{new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();
    }

    private void requireBundleId(String actual) throws VerificationException {
        if (!bundleId.equals(actual)) {
            throw new VerificationException(Reason.WRONG_BUNDLE_ID,
                    "expected " + bundleId + " but payload has " + actual);
        }
    }

    /** Accept-set environment routing (PLAN.md D3): returns the matched environment. */
    private Environment requireAcceptedEnvironment(String claim) throws VerificationException {
        Environment env = Environment.fromValue(claim);
        if (env == null || !acceptedEnvironments.contains(env)) {
            throw new VerificationException(Reason.WRONG_ENVIRONMENT,
                    "payload environment " + claim + " not in accepted set " + acceptedEnvironments);
        }
        return env;
    }
}
