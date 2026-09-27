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
 * <p>Each method hands a {@link CallClock} down, which reads the clock at
 * most once and only when a verdict needs it, so input that fails its own
 * checks never reaches it. A clock that throws is the host's fault, not the
 * input's, so the {@link CallClock} reports it as
 * {@link Reason#INTERNAL_ERROR} and it never lands inside a guard that
 * reports unexpected exceptions on unverified input as
 * {@link Reason#MALFORMED}.</p>
 */
final class DefaultVerifier implements Verifier {

    private final Set<TrustAnchor> trustAnchors;
    private final Clock clock;

    /**
     * The classes whose static state (the bounded Jackson factories, the
     * shared BouncyCastle signer-verifier builder) is built on first use.
     * Initialised by the constructor, so a Jackson below 2.16 or a broken
     * BouncyCastle fails {@link Verifier#create} rather than the first call,
     * where it would escape a method documented never to throw.
     */
    private static final String[] STATIC_STATE = {
        JwsCore.class.getName(),
        Endpoint.class.getName(),
        EndpointResponse.class.getName(),
        ReceiptCore.class.getName(),
    };

    DefaultVerifier(Config config) {
        Objects.requireNonNull(config, "config");
        initialise(STATIC_STATE);
        this.trustAnchors = AppleTrust.anchors(config.roots());
        this.clock = config.clock();
    }

    /**
     * Initialises each named class, turning a failure into an
     * {@link IllegalStateException} that names the dependency floor.
     */
    static void initialise(String... classNames) {
        ClassLoader loader = DefaultVerifier.class.getClassLoader();
        for (String name : classNames) {
            try {
                Class.forName(name, true, loader);
            } catch (ClassNotFoundException | LinkageError e) {
                throw new IllegalStateException(
                        "the verifier could not initialise " + name
                                + "; it needs jackson-core 2.16 or later and BouncyCastle (bcprov, bcpkix) 1.86",
                        e);
            }
        }
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        try {
            return VerificationResult.of(ReceiptCore.verify(base64, trustAnchors, new CallClock(clock)));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
        try {
            return VerificationResult.of(JwsCore.verify(jws, trustAnchors, new CallClock(clock)));
        } catch (VerificationException e) {
            return VerificationResult.failed(e.toFailure());
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
        Objects.requireNonNull(environment, "environment");
        return Endpoint.respond(environment, requestJson, trustAnchors, new CallClock(clock));
    }

    static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
