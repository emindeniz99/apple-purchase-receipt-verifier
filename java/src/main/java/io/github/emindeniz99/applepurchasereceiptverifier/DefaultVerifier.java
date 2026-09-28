package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Objects;
import java.util.Set;
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
        if (config.runtimeProbe()) {
            probeRuntime(BouncyCastle.PROVIDER);
        }
        this.trustAnchors = AppleTrust.anchors(config.roots());
        this.clock = config.clock();
    }

    /**
     * Runs {@code buildStaticState}, turning a {@link LinkageError} into an
     * {@link IllegalStateException} that names the dependency floor, so a
     * Jackson below 2.16 or a broken BouncyCastle fails {@link Verifier#create}
     * rather than a verify call, which must not throw.
     */
    static void initialise(Runnable buildStaticState) {
        try {
            buildStaticState.run();
        } catch (LinkageError e) {
            throw new IllegalStateException(
                    "the verifier could not initialise; it needs jackson-core 2.16 or later and BouncyCastle"
                            + " (bcprov, bcpkix) 1.86",
                    e);
        }
    }

    /**
     * Reading these fields runs the static initialisers that build them. The
     * BouncyCastle helpers are built per call, so the provider and a bcpkix
     * class are touched here to load both jars before the first verify.
     */
    private static void buildStaticState() {
        Objects.requireNonNull(JwsCore.JSON);
        Objects.requireNonNull(Endpoint.JSON);
        Objects.requireNonNull(BouncyCastle.PROVIDER);
        Objects.requireNonNull(JcaSignerInfoVerifierBuilder.class);
    }

    /**
     * Asks {@code provider} for every engine a verify call uses and checks
     * each bundled Apple root's own signature with it, so a runtime that
     * cannot verify (a stripped JRE, a FIPS-mode JDK that refuses the
     * provider) fails {@link Verifier#create} instead of answering
     * {@link Reason#INTERNAL_ERROR} on the first call. It needs no receipt or
     * JWS fixture. The SHA-1 RSA root stays in: BouncyCastle ignores the
     * JDK's disabled-algorithm lists, and the receipt path needs SHA-1 RSA.
     *
     * @throws IllegalStateException if an engine is missing or a root does not verify
     */
    static void probeRuntime(Provider provider) {
        try {
            MessageDigest.getInstance("SHA-256", provider);
            Signature.getInstance(JwsCore.ES256_ALGORITHM, provider);
            CertificateFactory.getInstance("X.509", provider);
            CertPathValidator.getInstance("PKIX", provider);
            CertPathBuilder.getInstance("PKIX", provider);
            for (X509Certificate root : AppleRootCerts.roots()) {
                root.verify(root.getPublicKey(), provider);
            }
        } catch (GeneralSecurityException e) {
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
