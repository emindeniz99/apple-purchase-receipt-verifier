package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.time.Clock;
import java.util.Objects;
import java.util.Set;
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

    /** Reading these fields runs the static initialisers that build them. */
    private static void buildStaticState() {
        Objects.requireNonNull(JwsCore.JSON);
        Objects.requireNonNull(Endpoint.JSON);
        Objects.requireNonNull(EndpointResponse.JSON);
        Objects.requireNonNull(ReceiptCore.SIGNER_VERIFIERS);
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

    static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
