package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.AppleTrust;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.BoundedJson;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.SafeText;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.jspecify.annotations.Nullable;

/**
 * Verifies Apple-signed JWS payloads (StoreKit 2 {@code jwsRepresentation},
 * App Store Server {@code signedTransactionInfo} / {@code signedRenewalInfo},
 * Server Notifications V2) completely offline, against pinned Apple roots.
 *
 * <p>Algorithm: ES256 only, exactly 3 {@code x5c} certs, Apple marker OIDs on
 * leaf and intermediate, PKIX path validation to the pinned roots at the
 * payload's signing time, then signature + claim checks. Mirrors the checks
 * of Apple's official app-store-server-library in offline mode: no OCSP, so a
 * revoked certificate is not detected, in exchange for no network call.</p>
 *
 * <p>Thread-safe once constructed.</p>
 *
 * <p>The {@code jws} argument of all three entry points is {@code @Nullable}
 * on purpose: a null input is a verdict about the input, so it is reported as
 * {@link Reason#INVALID_JWS_FORMAT} like any other unusable one rather than as
 * a {@link NullPointerException} a caller cannot catch alongside the others.</p>
 *
 * <p><strong>Security providers.</strong> Every cryptographic lookup here
 * resolves through the JVM's provider list: {@code CertificateFactory} for
 * the {@code x5c} certificates, the {@code PKIX} {@code CertPathValidator},
 * and {@code SHA256withECDSA}. BouncyCastle is used only to DER-encode the
 * signature, not as a provider. A host that inserts BouncyCastle at position
 * 1 therefore gets BouncyCastle's X.509 parser, path validator and ECDSA for
 * all three. This library's tests run against the JDK's providers, so under
 * that host an unusual certificate may get a different verdict. This class
 * reads the provider order and never changes it.</p>
 */
public final class JwsVerifier {

    /**
     * Ceiling on the compact JWS this verifier will look at, in characters.
     *
     * <p>Checked before the input is split or any segment is decoded, because
     * everything below allocates in proportion to it: base64url decoding
     * produces three quarters of the segment again as bytes, Jackson's tree
     * holds the parsed header and payload, and none of that is behind a
     * signature check, so an oversized input would surface as
     * {@link OutOfMemoryError} rather than the declared
     * {@link VerificationException}.
     *
     * <p>Real Apple JWS payloads, Apple's own mock notification data
     * included, are under 2.5 KB, so 256 KiB is a hundredfold headroom over
     * anything Apple has ever signed. The same constant in every port. A
     * compact JWS is base64url and dots, so its characters and its bytes are
     * the same count for any input that could verify.
     */
    public static final int MAX_JWS_BYTES = 262144;

    private final Set<TrustAnchor> trustAnchors;
    private final String bundleId;
    private final Set<Environment> acceptedEnvironments;
    private final @Nullable Long appAppleId;
    private final @Nullable Long maxSignedAgeMillis;
    private final Clock clock;
    private final ObjectMapper mapper;

    /**
     * @param trustedRoots         pinned root CAs (production:
     *                             {@code AppleRootCerts.jwsRoots()})
     * @param bundleId             the app's bundle id every payload must carry
     * @param acceptedEnvironments environments to accept; include SANDBOX in
     *                             endpoints App Review can hit, because App
     *                             Review buys with sandbox accounts against
     *                             the production app
     */
    public JwsVerifier(Set<X509Certificate> trustedRoots, String bundleId, Set<Environment> acceptedEnvironments) {
        this(trustedRoots, bundleId, acceptedEnvironments, null, null, null);
    }

    /**
     * @param appAppleId   the app's Apple id; required to accept PRODUCTION
     *                     AppTransactions, unused otherwise
     * @param maxSignedAge if non-null, payloads whose signing time is older
     *                     than this many milliseconds are rejected as
     *                     {@link Reason#STALE_PAYLOAD}; {@code null} applies
     *                     no age limit
     */
    public JwsVerifier(
            Set<X509Certificate> trustedRoots,
            String bundleId,
            Set<Environment> acceptedEnvironments,
            @Nullable Long appAppleId,
            @Nullable Long maxSignedAge) {
        this(trustedRoots, bundleId, acceptedEnvironments, appAppleId, maxSignedAge, null);
    }

    /**
     * @param clock source of "now" for the {@code maxSignedAge} staleness
     *              rule and nothing else; {@code null} (the default of every
     *              other constructor) means {@link Clock#systemUTC()}.
     *              Certificate validity is never judged by it (it uses the
     *              payload's signing date, or the system clock when there is
     *              none), so an injected clock cannot move a chain verdict.
     */
    public JwsVerifier(
            Set<X509Certificate> trustedRoots,
            String bundleId,
            Set<Environment> acceptedEnvironments,
            @Nullable Long appAppleId,
            @Nullable Long maxSignedAge,
            @Nullable Clock clock) {
        Set<TrustAnchor> anchors = AppleTrust.anchors(trustedRoots);
        if (bundleId == null) {
            throw new IllegalArgumentException("bundleId must not be null");
        }
        if (acceptedEnvironments == null || acceptedEnvironments.isEmpty()) {
            throw new IllegalArgumentException("acceptedEnvironments must not be empty");
        }
        this.trustAnchors = anchors;
        this.bundleId = bundleId;
        this.acceptedEnvironments = EnumSet.copyOf(acceptedEnvironments);
        this.appAppleId = appAppleId;
        this.maxSignedAgeMillis = maxSignedAge;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        // A segment cannot outgrow the whole JWS, so both length bounds are
        // MAX_JWS_BYTES: consistent with the entry-point bound rather than a
        // second opinion about it.
        this.mapper = new ObjectMapper(BoundedJson.factory(MAX_JWS_BYTES));
    }

    /**
     * Verifies a signed transaction ({@code jwsRepresentation} /
     * {@code signedTransactionInfo}) and checks bundle id + environment.
     */
    public TransactionPayload verifyTransaction(@Nullable String jws) throws VerificationException {
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
    public AppTransactionPayload verifyAppTransaction(@Nullable String jws) throws VerificationException {
        JsonNode node = verifySignature(jws);
        AppTransactionPayload payload;
        try {
            payload = mapper.treeToValue(node, AppTransactionPayload.class);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "unparseable AppTransaction payload", e);
        }
        requireBundleId(payload.bundleId());
        Environment env = requireAcceptedEnvironment(payload.receiptType());
        if (env == Environment.PRODUCTION && (appAppleId == null || !appAppleId.equals(payload.appAppleId()))) {
            throw new VerificationException(
                    Reason.WRONG_APP_APPLE_ID, "expected " + appAppleId + " but payload has " + payload.appAppleId());
        }
        return payload;
    }

    /**
     * Verifies the signature/chain only and returns the raw claims — for
     * payload types without a dedicated model (renewal info, notification
     * envelopes). <strong>The caller must check bundle id / environment /
     * app Apple id in the returned claims itself.</strong>
     */
    public Map<String, @Nullable Object> verifyRaw(@Nullable String jws) throws VerificationException {
        JsonNode node = verifySignature(jws);
        return mapper.convertValue(node, new TypeReference<Map<String, @Nullable Object>>() {});
    }

    /** Cryptographic verification: format → certs → OIDs → chain → signature. */
    private JsonNode verifySignature(@Nullable String jws) throws VerificationException {
        if (jws == null) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "jws is null");
        }
        // Before the split, so nothing downstream allocates in proportion to
        // an input this verifier has already decided not to look at.
        if (jws.length() > MAX_JWS_BYTES) {
            throw new VerificationException(
                    Reason.INVALID_JWS_FORMAT,
                    "jws exceeds the maximum accepted size of " + MAX_JWS_BYTES + " characters");
        }
        String[] parts = jws.split("\\.", -1);
        if (parts.length != 3) {
            throw new VerificationException(
                    Reason.INVALID_JWS_FORMAT, "expected 3 dot-separated segments, got " + parts.length);
        }
        JsonNode header = parseJson(parts[0], "header");
        if (!"ES256".equals(header.path("alg").asText())) {
            throw new VerificationException(
                    Reason.INVALID_JWS_FORMAT,
                    "alg must be ES256, got "
                            + SafeText.quote(header.path("alg").asText()));
        }
        JsonNode x5c = header.path("x5c");
        if (!x5c.isArray() || x5c.size() != 3 || !allTextual(x5c)) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "x5c must contain exactly 3 certificates");
        }
        // x5c[2] is decoded but unused: PKIX validates leaf + intermediate against the pinned anchors.
        List<X509Certificate> chain = decodeChain(x5c);
        X509Certificate leaf = chain.get(0);
        X509Certificate intermediate = chain.get(1);
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

        JsonNode payload = parseJson(parts[1], "payload");
        Long signedAtMillis = signedAtMillis(payload);
        // The system clock, not this.clock: this is a certificate-validity
        // instant, which an injected clock must never move. It is only used
        // when the payload states no signing time.
        validateChain(leaf, intermediate, signedAtMillis != null ? new Date(signedAtMillis.longValue()) : new Date());

        byte[] signature = decodeBase64Url(parts[2], "signature");
        verifyEs256(leaf, parts[0] + "." + parts[1], signature);

        // A payload that states no signing time has no age to be stale by, so
        // the rule does not apply to it — rather than measuring the clock
        // against itself.
        if (maxSignedAgeMillis != null && signedAtMillis != null) {
            long signedAt = signedAtMillis.longValue();
            if (clock.millis() - signedAt > maxSignedAgeMillis) {
                throw new VerificationException(
                        Reason.STALE_PAYLOAD,
                        "payload signed at " + signedAt + " exceeds max age " + maxSignedAgeMillis + "ms");
            }
        }
        return payload;
    }

    /**
     * A JWS header and payload must be JSON objects (RFC 7515). An empty
     * segment reads as {@code MissingNode} or {@code null}, and a scalar or
     * array fails later as a {@link NullPointerException} rather than a
     * {@link VerificationException}, so {@code isObject()} is checked here.
     */
    private JsonNode parseJson(String base64Url, String what) throws VerificationException {
        byte[] bytes = decodeBase64Url(base64Url, what);
        JsonNode node;
        try {
            node = mapper.readTree(bytes);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not valid JSON", e);
        }
        if (node == null || !node.isObject()) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not a JSON object");
        }
        return node;
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
                throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not canonical base64url");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, what + " is not valid base64url", e);
        }
    }

    private static List<X509Certificate> decodeChain(JsonNode x5c) throws VerificationException {
        List<X509Certificate> chain = new ArrayList<X509Certificate>(3);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (JsonNode certNode : x5c) {
                // RFC 7515 4.1.6: standard base64, no line breaks. The MIME
                // decoder would silently skip any illegal character instead.
                byte[] der = Base64.getDecoder().decode(certNode.asText());
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
     * certificates keep verifying.
     */
    private static @Nullable Long signedAtMillis(JsonNode payload) throws VerificationException {
        Long signedDate = instantClaim(payload, "signedDate");
        return signedDate != null ? signedDate : instantClaim(payload, "receiptCreationDate");
    }

    /**
     * One signing-time claim, or {@code null} when the payload does not state
     * it. A claim that IS a number but does not fit a long — {@code 1e300},
     * say — is not "not stated": treating it as absent would fall through to
     * the current-time anchor and validate the chain against today, which is
     * an attacker choosing the instant a certificate's window is judged at.
     * An instant no calendar can express is inside no window.
     */
    private static @Nullable Long instantClaim(JsonNode payload, String name) throws VerificationException {
        JsonNode claim = payload.path(name);
        if (claim.canConvertToLong()) {
            return Long.valueOf(claim.asLong());
        }
        if (claim.isNumber()) {
            throw new VerificationException(
                    Reason.INVALID_CHAIN,
                    "payload signing date " + SafeText.quote(claim.asText()) + " is not a valid instant");
        }
        return null;
    }

    private static boolean allTextual(JsonNode x5c) {
        for (JsonNode entry : x5c) {
            if (!entry.isTextual()) {
                return false;
            }
        }
        return true;
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
            throw new VerificationException(
                    Reason.INVALID_CHAIN,
                    "certificate chain does not validate to a pinned Apple root: " + e.getMessage(),
                    e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation rejected parameters", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation unavailable", e);
        }
    }

    private static void verifyEs256(X509Certificate leaf, String signingInput, byte[] signature)
            throws VerificationException {
        if (signature.length != 64) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "ES256 signature must be 64 bytes, got " + signature.length);
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
     * avoid this, but it's Java 9+ and this library supports Java 8.
     */
    private static byte[] p1363ToDer(byte[] p1363) throws IOException {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(p1363, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363, 32, 64));
        return new DERSequence(new ASN1Encodable[] {new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();
    }

    private void requireBundleId(@Nullable String actual) throws VerificationException {
        if (!bundleId.equals(actual)) {
            throw new VerificationException(
                    Reason.WRONG_BUNDLE_ID, "expected " + bundleId + " but payload has " + SafeText.quote(actual));
        }
    }

    /** Checks the claim against the accepted set and returns the matched environment. */
    private Environment requireAcceptedEnvironment(@Nullable String claim) throws VerificationException {
        Environment env = Environment.fromValue(claim);
        if (env == null || !acceptedEnvironments.contains(env)) {
            throw new VerificationException(
                    Reason.WRONG_ENVIRONMENT,
                    "payload environment " + SafeText.quote(claim) + " not in accepted set " + acceptedEnvironments);
        }
        return env;
    }
}
