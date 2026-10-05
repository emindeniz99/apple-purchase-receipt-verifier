package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.jspecify.annotations.Nullable;

/**
 * The one {@link Verifier}. Everything per-instance is built once here (the
 * trust anchors); every call keeps its state in locals, so one instance
 * serves every thread.
 *
 * <p>Each method reads the clock once, before any input is looked at, so
 * a clock that throws is {@link Reason#INTERNAL_ERROR} (the host's fault)
 * and never lands inside a guard that reports unexpected exceptions on
 * unverified input as {@link Reason#MALFORMED}.</p>
 */
final class DefaultVerifier implements Verifier {

    private final Set<TrustAnchor> trustAnchors;
    private final Clock clock;

    DefaultVerifier(Config config) {
        Objects.requireNonNull(config, "config");
        ClasspathGuard.check(DefaultVerifier.class.getClassLoader());
        initialise(DefaultVerifier::buildStaticState);
        // Not behind runtimeProbe: neither looks at the provider's engines,
        // which is what a test double stands in for.
        requireBouncyCastle(BouncyCastle.PROVIDER);
        requireReceiptNesting();
        // A bad config (an empty root set) fails before the probe's cost.
        this.trustAnchors = AppleTrust.anchors(config.roots());
        if (config.runtimeProbe()) {
            // Outside the probe's try: a root that does not parse is this
            // library's defect, not the runtime's.
            probeRuntime(BouncyCastle.PROVIDER, AppleRootCerts.roots());
        }
        this.clock = config.clock();
    }

    /**
     * Runs {@code buildStaticState}, turning a {@link LinkageError} into an
     * {@link IllegalStateException} that names the error and the floors, so a
     * Jackson below 2.16, a missing or pre-1.70 BouncyCastle or a time-zone database
     * without America/Los_Angeles fails {@link Verifier#create} rather than a
     * verify call, which must not throw.
     */
    static void initialise(Runnable buildStaticState) {
        try {
            buildStaticState.run();
        } catch (LinkageError e) {
            // An ExceptionInInitializerError has no message of its own; its
            // cause says which initialiser failed and why.
            String error = e.getCause() != null ? e + ", caused by " + e.getCause() : e.toString();
            throw new IllegalStateException(
                    "the verifier could not initialise (" + error + "); it needs jackson-core 2.16 or later,"
                            + " BouncyCastle (bcprov, bcutil, bcpkix) 1.86 or later, and a time-zone"
                            + " database that has America/Los_Angeles",
                    e);
        }
    }

    /**
     * Reading these fields runs the static initialisers that build them. The
     * BouncyCastle helpers are built per call, so the provider and a bcpkix
     * class are touched here to load both jars before the first verify, and
     * so is every BouncyCastle class ReceiptDecoder names: ASN1UTF8String and
     * ASN1IA5String arrived in bcprov 1.70, and an older jar would otherwise
     * throw out of the first verifyReceipt. A jar from 1.70 on links, and
     * {@link #requireBouncyCastle} refuses it below 1.86.
     * EndpointResponse's initialiser loads the Pacific time zone, which a JRE
     * with a truncated tzdb would fail on the first endpoint call otherwise.
     * The readers' factories need jackson-core 2.15, and the name bound read
     * here is 2.16 API, so a Jackson below the floor fails here.
     */
    private static void buildStaticState() {
        Objects.requireNonNull(JwsCore.JSON);
        Objects.requireNonNull(Endpoint.JSON);
        JwsCore.JSON.streamReadConstraints().getMaxNameLength();
        Objects.requireNonNull(EndpointResponse.JSON);
        Objects.requireNonNull(BouncyCastle.PROVIDER);
        Objects.requireNonNull(JcaSignerInfoVerifierBuilder.class);
        Objects.requireNonNull(ASN1Encodable.class);
        Objects.requireNonNull(ASN1IA5String.class);
        Objects.requireNonNull(ASN1Integer.class);
        Objects.requireNonNull(ASN1OctetString.class);
        Objects.requireNonNull(ASN1Primitive.class);
        Objects.requireNonNull(ASN1Sequence.class);
        Objects.requireNonNull(ASN1Set.class);
        Objects.requireNonNull(ASN1String.class);
        Objects.requireNonNull(ASN1UTF8String.class);
    }

    /** The release named in BouncyCastle's provider info, "BouncyCastle Security Provider v1.86". */
    private static final Pattern BOUNCY_CASTLE_RELEASE = Pattern.compile("v(\\d{1,4})\\.(\\d{1,4})");

    /**
     * How deep a genuine Apple receipt nests constructed ASN.1 values, as
     * BouncyCastle's bound counts them: the public sandbox receipts parse
     * with {@code org.bouncycastle.asn1.max_cons_depth} at 9 and fail at 8,
     * the same as {@link #RECEIPT_NESTING} SEQUENCEs around an INTEGER
     * (docs/evidence/2026-10-04-java-bc-floor.md).
     */
    static final int RECEIPT_NESTING = 9;

    /**
     * Refuses a bcprov older than 1.86, reading the release from the provider
     * instance this library holds, so nothing is registered with
     * {@code Security}. The info string ("BouncyCastle Security Provider
     * v1.81.1") is compared by its parts; the double BouncyCastle passes to
     * {@link Provider}'s constructor (1.81.1 is {@code 1.8101}) is the
     * fallback for an info string without a release in it. 1.84 added the
     * ASN.1 nesting bound (bcprov 1.81 throws {@code StackOverflowError} out
     * of {@code verifyReceipt} on a deeply nested receipt), and 1.85 fixed
     * CVE-2026-12860 (RSA PKCS#1 verification skipped two hash bytes), which
     * the receipt signature check reaches, and CVE-2026-13506. Every bcprov
     * from 1.70 links, so the class loading in {@link #buildStaticState}
     * cannot tell these apart (docs/evidence/2026-10-04-java-bc-floor.md).
     *
     * @throws IllegalStateException naming the release found
     */
    @SuppressWarnings("deprecation")
    static void requireBouncyCastle(Provider provider) {
        String info = String.valueOf(provider.getInfo());
        Matcher release = BOUNCY_CASTLE_RELEASE.matcher(info);
        boolean atFloor = release.find()
                ? Integer.parseInt(release.group(1)) * 1000 + Integer.parseInt(release.group(2)) >= 1086
                : provider.getVersion() >= 1.86;
        if (!atFloor) {
            throw new IllegalStateException("BouncyCastle bcprov on the classpath is \"" + info
                    + "\"; the verifier needs 1.86 or later: 1.84 added the ASN.1 nesting bound that"
                    + " keeps a deeply nested receipt from overflowing the stack, and 1.85 fixed"
                    + " CVE-2026-12860 in the RSA signature check receipts use (and CVE-2026-13506)."
                    + " Resolve bcprov, bcutil and bcpkix to 1.86 or later");
        }
    }

    /**
     * Parses {@link #RECEIPT_NESTING} nested SEQUENCEs around an INTEGER, as
     * deep as a genuine Apple receipt nests, so a host that set
     * {@code org.bouncycastle.asn1.max_cons_depth} below that fails
     * {@link Verifier#create} instead of answering {@link Reason#MALFORMED}
     * to every genuine receipt. BouncyCastle reads the setting each time it
     * opens a stream, so this sees it as it stands at create.
     *
     * @throws IllegalStateException if BouncyCastle refuses the nesting
     */
    static void requireReceiptNesting() {
        byte[] der = {0x02, 0x01, 0x00};
        for (int i = 0; i < RECEIPT_NESTING; i++) {
            byte[] outer = new byte[der.length + 2];
            outer[0] = 0x30;
            outer[1] = (byte) der.length;
            System.arraycopy(der, 0, outer, 2, der.length);
            der = outer;
        }
        try {
            ASN1Primitive.fromByteArray(der);
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException(
                    "BouncyCastle refuses ASN.1 nested " + RECEIPT_NESTING + " deep, which every genuine Apple"
                            + " receipt reaches, so each would fail as MALFORMED;"
                            + " org.bouncycastle.asn1.max_cons_depth is set below " + RECEIPT_NESTING
                            + " (java.security or a system property): " + e.getMessage(),
                    e);
        }
    }

    /**
     * Asks {@code provider} for the SHA-256 digest, the ES256 signature, the
     * X.509 certificate factory, the PKIX validator and builder and the
     * Collection cert store, and checks each of {@code roots} (the bundled
     * Apple roots) against its own signature with it, so a runtime that
     * cannot verify (a stripped JRE, a FIPS-mode JDK that refuses the
     * provider) fails {@link Verifier#create} instead of the first call. It needs no receipt or
     * JWS fixture. The SHA-1 RSA root stays in: BouncyCastle ignores the
     * JDK's disabled-algorithm lists, and the receipt path needs SHA-1 RSA.
     * The RSA engines behind the CMS signer verifier are not asked for by
     * name; the roots' signatures exercise RSA only as far as they reach.
     *
     * @throws IllegalStateException if an engine is missing, the provider
     *     throws, or a root does not verify
     */
    static void probeRuntime(Provider provider, Set<X509Certificate> roots) {
        try {
            MessageDigest.getInstance("SHA-256", provider);
            Signature.getInstance(JwsCore.ES256_ALGORITHM, provider);
            CertificateFactory.getInstance("X.509", provider);
            CertPathValidator.getInstance("PKIX", provider);
            CertPathBuilder.getInstance("PKIX", provider);
            CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.emptyList()), provider);
            for (X509Certificate root : roots) {
                root.verify(root.getPublicKey(), provider);
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            // A FIPS or stripped provider can throw ProviderException, a
            // RuntimeException, where a missing engine would be checked.
            throw new IllegalStateException("this runtime cannot verify Apple signatures: " + e.getMessage(), e);
        }
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        try {
            long now = clock.millis();
            return VerificationResult.of(ReceiptCore.verify(base64, trustAnchors, now));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
        try {
            long now = clock.millis();
            return VerificationResult.of(JwsCore.verify(jws, trustAnchors, now));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
        Objects.requireNonNull(environment, "environment");
        long now;
        try {
            now = clock.millis();
        } catch (RuntimeException e) {
            return EndpointResponse.status(AppleStatus.INTERNAL_DATA_ACCESS_ERROR);
        }
        // One read serves both the chain instant and request_date.
        return Endpoint.respond(environment, requestJson, trustAnchors, now);
    }

    private static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
