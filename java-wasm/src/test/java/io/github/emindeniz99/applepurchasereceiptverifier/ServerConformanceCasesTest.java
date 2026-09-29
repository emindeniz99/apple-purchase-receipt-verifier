package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;

/**
 * The conformance cases on the server engine, through
 * {@link ServerSource#executable} and the managed child. One child runs per
 * root set (the roots go to it in the handshake); each case's clock reaches
 * it as {@code X-Aprv-Now-Ms}, since the shared verifier reads a clock that
 * answers with the clock of the case calling it.
 */
@Tag("server")
class ServerConformanceCasesTest extends ConformanceCases {

    private static final ThreadLocal<Clock> CASE_CLOCK = new ThreadLocal<>();

    /** Reads the calling case's clock. */
    private static final Clock CLOCK = new Clock() {
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis());
        }

        @Override
        public long millis() {
            Clock clock = CASE_CLOCK.get();
            return (clock != null ? clock : Clock.systemUTC()).millis();
        }
    };

    private final Map<Set<X509Certificate>, ServerVerifier> children = new HashMap<>();

    @AfterEach
    void stopTheChildren() {
        synchronized (children) {
            for (ServerVerifier child : children.values()) {
                child.close();
            }
            children.clear();
        }
    }

    @Override
    String engineName() {
        return "server";
    }

    private ServerVerifier child(Set<X509Certificate> roots) {
        synchronized (children) {
            return children.computeIfAbsent(roots, r -> (ServerVerifier) Verifier.create(
                    Config.builder().roots(r).clock(CLOCK).build(),
                    Engine.server(ServerSource.executable(ServerTests.binary()))));
        }
    }

    @Override
    Verifier verifier(Config config) {
        ServerVerifier child = child(new HashSet<>(config.roots()));
        Clock clock = config.clock();
        return new Verifier() {
            @Override
            public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
                CASE_CLOCK.set(clock);
                try {
                    return child.verifyReceipt(base64);
                } finally {
                    CASE_CLOCK.remove();
                }
            }

            @Override
            public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
                CASE_CLOCK.set(clock);
                try {
                    return child.verifySignedData(jws);
                } finally {
                    CASE_CLOCK.remove();
                }
            }

            @Override
            public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
                CASE_CLOCK.set(clock);
                try {
                    return child.verifyReceiptEndpoint(environment, requestJson);
                } finally {
                    CASE_CLOCK.remove();
                }
            }
        };
    }
}
