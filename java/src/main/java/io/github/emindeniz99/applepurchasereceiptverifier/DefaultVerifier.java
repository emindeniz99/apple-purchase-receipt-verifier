package io.github.emindeniz99.applepurchasereceiptverifier;

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
        initialise(DefaultVerifier::buildStaticState);
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
     * Jackson below 2.16, a broken BouncyCastle or a time-zone database
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
                            + " BouncyCastle (bcprov, bcpkix) 1.86 or a compatible release, and a time-zone"
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
     * throw out of the first verifyReceipt.
     * EndpointResponse's initialiser loads the Pacific time zone, which a JRE
     * with a truncated tzdb would fail on the first endpoint call otherwise.
     */
    private static void buildStaticState() {
        Objects.requireNonNull(JwsCore.JSON);
        Objects.requireNonNull(Endpoint.JSON);
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

    /**
     * Asks {@code provider} for the SHA-256 digest, the ES256 signature, the
     * X.509 certificate factory, the PKIX validator and builder and the
     * Collection cert store, and checks each of {@code roots} (the bundled
     * Apple roots) against its own signature with it, so a runtime that
     * cannot verify (a stripped JRE, a FIPS-mode JDK that refuses the
     * provider) fails {@link Verifier#create} instead of answering
     * {@link Reason#INTERNAL_ERROR} on the first call. It needs no receipt or
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
