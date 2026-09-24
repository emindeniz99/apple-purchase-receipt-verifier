package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.AppleTrust;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.BouncyCastle;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.BoundedJson;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.SafeText;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
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
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * <p><strong>Security providers.</strong> Every cryptographic step uses a
 * private BouncyCastle instance that is never registered: the
 * {@code CertificateFactory} for the {@code x5c} certificates, the
 * {@code PKIX} {@code CertPathValidator}, and the ES256 signature check. The
 * JVM's provider list and its {@code java.security} policy,
 * {@code jdk.certpath.disabledAlgorithms} included, do not reach any of them,
 * so they cannot change a verdict. The trade-off: an administrator cannot
 * restrict this class through that policy either.</p>
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
        this(trustedRoots, bundleId, acceptedEnvironments, null);
    }

    /**
     * No payload is rejected for its age: how old a signed payload may be is
     * the caller's decision, made on its {@code signedDate} (PLAN.md D5).
     *
     * @param appAppleId the app's Apple id; required to accept PRODUCTION
     *                   AppTransactions, unused otherwise
     */
    public JwsVerifier(
            Set<X509Certificate> trustedRoots,
            String bundleId,
            Set<Environment> acceptedEnvironments,
            @Nullable Long appAppleId) {
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
        TransactionPayload payload = StrictClaims.read(verifySignature(jws), TransactionPayload.class);
        requireBundleId(payload.bundleId());
        requireAcceptedEnvironment(payload.environment());
        return payload;
    }

    /**
     * Verifies a signed {@code AppTransaction} and checks bundle id,
     * environment ({@code receiptType}), and — in PRODUCTION — the app Apple id.
     */
    public AppTransactionPayload verifyAppTransaction(@Nullable String jws) throws VerificationException {
        AppTransactionPayload payload = StrictClaims.read(verifySignature(jws), AppTransactionPayload.class);
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

    /**
     * {@link #verifySignatureUnguarded}, with any unchecked exception it lets
     * out reported as {@link Reason#INVALID_JWS_FORMAT}, as
     * {@code ReceiptVerifier.verifyCore} does for receipts.
     *
     * <p>The steps that are known to throw unchecked (the x5c decode, the
     * chain check) already map it themselves; this catches the ones nobody
     * has found yet, from Jackson or BouncyCastle, so they cannot escape the
     * declared {@link VerificationException} contract. INVALID_JWS_FORMAT
     * rather than INTERNAL_ERROR on purpose: everything in here runs on
     * input no signature has vouched for, and answering an unknown error
     * with INTERNAL_ERROR ("not the client's fault, retry or escalate")
     * would let anyone raise that alert at will. The claims are mapped to
     * their model only after this returns, once the signature has passed.</p>
     */
    private JsonNode verifySignature(@Nullable String jws) throws VerificationException {
        try {
            return verifySignatureUnguarded(jws);
        } catch (VerificationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new VerificationException(Reason.INVALID_JWS_FORMAT, "unexpected " + e, e);
        }
    }

    /** Cryptographic verification: format → certs → OIDs → chain → signature. */
    private JsonNode verifySignatureUnguarded(@Nullable String jws) throws VerificationException {
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
        // The system clock, only when the payload states no signing time.
        validateChain(leaf, intermediate, signedAtMillis != null ? new Date(signedAtMillis.longValue()) : new Date());

        byte[] signature = decodeBase64Url(parts[2], "signature");
        verifyEs256(leaf, parts[0] + "." + parts[1], signature);
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

    /**
     * Decodes one x5c entry. RFC 7515 4.1.6: standard base64, no line breaks.
     * The MIME decoder would silently skip any illegal character instead. The
     * basic decoder accepts omitted padding and decodes {@code ""}, so the
     * length is held to a non-zero multiple of four first, as receipt-data
     * is. Package-private so the conformance suite can run the shared base64
     * spellings against it directly.
     */
    static byte[] decodeX5cEntry(String text) throws VerificationException {
        if (text.isEmpty() || text.length() % 4 != 0) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c entry is not canonically padded base64");
        }
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c entry is not valid base64", e);
        }
    }

    private static List<X509Certificate> decodeChain(JsonNode x5c) throws VerificationException {
        List<X509Certificate> chain = new ArrayList<X509Certificate>(3);
        CertificateFactory cf = x509Factory();
        try {
            for (JsonNode certNode : x5c) {
                byte[] der = decodeX5cEntry(certNode.asText());
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                // Results unused: BouncyCastle decodes the key and the
                // signature BIT STRING lazily, so a key on an unimplemented
                // curve or a signature that is not whole octets would
                // otherwise fail later, inside the path validator, as an
                // unchecked exception.
                certificate.getPublicKey();
                certificate.getSignature();
                chain.add(certificate);
            }
        } catch (CertificateException | RuntimeException e) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE, "x5c[" + chain.size() + "] does not decode", e);
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
        CertPathValidator validator;
        try {
            validator = CertPathValidator.getInstance("PKIX", BouncyCastle.PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new VerificationException(Reason.INTERNAL_ERROR, "PKIX path validation is not available", e);
        }
        try {
            CertPath path = x509Factory().generateCertPath(Arrays.asList(leaf, intermediate));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            params.setDate(at);
            validator.validate(path, params);
        } catch (CertPathValidatorException e) {
            throw new VerificationException(
                    Reason.INVALID_CHAIN,
                    "certificate chain does not validate to a pinned Apple root: " + e.getMessage(),
                    e);
        } catch (InvalidAlgorithmParameterException e) {
            // Raised for the pinned anchors or the path type, never for a certificate.
            throw new VerificationException(Reason.INTERNAL_ERROR, "chain validation rejected its parameters", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "path validator refused the path", e);
        } catch (RuntimeException e) {
            // BouncyCastle reports some malformed certificate content with
            // unchecked exceptions from inside the validator. Everything here
            // is attacker-controlled and unverified, so it is the chain's
            // failure, and it must not escape as anything but a verdict.
            throw new VerificationException(Reason.INVALID_CHAIN, "path validator raised " + e, e);
        }
    }

    /** BouncyCastle's X.509 factory; its absence would be the library's failure, not the input's. */
    private static CertificateFactory x509Factory() throws VerificationException {
        try {
            return CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER);
        } catch (CertificateException e) {
            throw new VerificationException(Reason.INTERNAL_ERROR, "X.509 certificate decoding is not available", e);
        }
    }

    private static void verifyEs256(X509Certificate leaf, String signingInput, byte[] signature)
            throws VerificationException {
        if (signature.length != 64) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "ES256 signature must be 64 bytes, got " + signature.length);
        }
        Signature verifier;
        try {
            verifier = Signature.getInstance("SHA256withPLAIN-ECDSA", BouncyCastle.PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new VerificationException(Reason.INTERNAL_ERROR, "ES256 verification is not available", e);
        }
        try {
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
