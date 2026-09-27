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
 * <p>Each method reads the clock once, outside the checks, and hands the
 * value down. A clock that throws is the host's fault, not the input's, so
 * it must never land inside a guard that reports unexpected exceptions on
 * unverified input as {@link Reason#MALFORMED}.</p>
 */
final class DefaultVerifier implements Verifier {

    private final Set<TrustAnchor> trustAnchors;
    private final Clock clock;

    DefaultVerifier(Config config) {
        Objects.requireNonNull(config, "config");
        this.trustAnchors = AppleTrust.anchors(config.roots());
        this.clock = config.clock();
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        try {
            return VerificationResult.of(ReceiptCore.verify(base64, trustAnchors, clock.millis()));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
        try {
            return VerificationResult.of(JwsCore.verify(jws, trustAnchors, clock.millis()));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
        Objects.requireNonNull(environment, "environment");
        long nowMillis;
        try {
            nowMillis = clock.millis();
        } catch (RuntimeException e) {
            return EndpointResponse.status(AppleStatus.INTERNAL_DATA_ACCESS_ERROR);
        }
        return Endpoint.respond(environment, requestJson, trustAnchors, nowMillis);
    }

    static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
