package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.Closeable;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.time.Clock;
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * The {@link Verifier} over {@code aprv-server} (the server engine). It reads
 * the clock once per call before the input is touched and sends it as
 * {@code X-Aprv-Now-Ms}, posts the input bytes cut as the Endive engine cuts
 * them ({@link WasmVerifier#bytes}), and maps the answer: a 200 through the
 * same {@link Wire} decoder as the Endive engine, and a 413 the same way, since its body is the module's own answer to an
 * input over the cap ({@code TOO_LARGE}, 21002 from the endpoint); every
 * problem as {@link Reason#INTERNAL_ERROR} with a {@link ServerProblem} cause,
 * and a server that does not answer as {@link Reason#INTERNAL_ERROR} with a
 * {@link ServerProcessFailure} cause (ARCHITECTURE.md §4, the six outcomes).
 *
 * <p>{@link Closeable}: {@link #close()} stops a managed child now. Without
 * it the child stops when this verifier becomes unreachable, or when the JVM
 * exits (a shutdown hook, and the child's own stdin EOF even after
 * {@code kill -9}).</p>
 */
final class ServerVerifier implements Verifier, Closeable {

    /**
     * Whether the server answered with the module's JSON: a 200, or a 413
     * whose body is the module's own answer to an input over the cap. A 413
     * that is a problem document (a server older than that rule) is not.
     */
    static boolean moduleAnswered(HttpConn.Response response) {
        return response.status == 200
                || (response.status == 413
                        && response.contentType.toLowerCase(Locale.ROOT).startsWith("application/json"));
    }

    private final Clock clock;
    private final Holder holder;

    /**
     * @param open resolves the sources and starts or reaches the server
     * @param now whether to do that now (the runtime probe) or at the first call
     */
    ServerVerifier(Config config, java.util.function.Supplier<ServerConnection> open, boolean now) {
        this.clock = config.clock();
        this.holder = new Holder(open);
        if (now) {
            holder.get();
        }
        Reaper.register(this, holder);
    }

    /** The connection, for tests; resolves it when the probe was off. */
    ServerConnection connection() {
        return holder.get();
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        return verify("/v1/receipt/verify", base64, Wire::receiptAnswer);
    }

    @Override
    public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
        return verify("/v1/signed-data/verify", jws, Wire::signedDataAnswer);
    }

    @Override
    public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
        Objects.requireNonNull(environment, "environment");
        String path =
                environment == Environment.PRODUCTION ? "/v1/verify-receipt/production" : "/v1/verify-receipt/sandbox";
        try {
            long now = clock.millis();
            HttpConn.Response response = holder.get().send("POST", path, bytes(requestJson), now);
            if (moduleAnswered(response)) {
                return Wire.endpointAnswer(response.text());
            }
            return "{\"status\":" + AppleStatus.INTERNAL_DATA_ACCESS_ERROR + "}";
        } catch (RuntimeException e) {
            return "{\"status\":" + AppleStatus.INTERNAL_DATA_ACCESS_ERROR + "}";
        }
    }

    private <T> VerificationResult<T> verify(
            String path, @Nullable String input, Function<String, VerificationResult<T>> decode) {
        try {
            long now = clock.millis();
            HttpConn.Response response = holder.get().send("POST", path, bytes(input), now);
            if (moduleAnswered(response)) {
                return decode.apply(response.text());
            }
            ServerProblem problem = ServerJson.problem(response);
            return VerificationResult.failed(new Failure(Reason.INTERNAL_ERROR, problem.getMessage(), problem));
        } catch (GuestFailure | ServerProcessFailure e) {
            return VerificationResult.failed(new Failure(Reason.INTERNAL_ERROR, e.getMessage(), e));
        } catch (RuntimeException e) {
            // A clock that threw, or a defect here: worded as the main artifact words it.
            return VerificationResult.failed(new Failure(
                    Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e));
        }
    }

    /**
     * The input cut as the Endive engine cuts it ({@link WasmVerifier#bytes}):
     * the server reads only that many bytes of a larger body before it
     * answers and closes, so sending the rest would meet a reset instead of
     * the module's TOO_LARGE answer.
     */
    private static byte[] bytes(@Nullable String text) {
        return WasmVerifier.bytes(text);
    }

    /** Stops a managed child now; later calls answer {@link Reason#INTERNAL_ERROR}. Idempotent. */
    @Override
    public void close() {
        holder.close();
    }

    /**
     * The connection, opened once: at {@code create} with the probe, else at
     * the first call. Kept apart from the verifier so the reaper can close it
     * after the verifier is gone.
     */
    static final class Holder {
        private final java.util.function.Supplier<ServerConnection> open;
        private volatile @Nullable ServerConnection connection;
        private volatile boolean closed;

        Holder(java.util.function.Supplier<ServerConnection> open) {
            this.open = open;
        }

        ServerConnection get() {
            ServerConnection current = connection;
            if (current != null) {
                return current;
            }
            synchronized (this) {
                if (closed) {
                    throw new ServerProcessFailure("the server engine was closed");
                }
                if (connection == null) {
                    connection = open.get();
                    Reaper.OPEN.add(this);
                }
                return connection;
            }
        }

        synchronized void close() {
            closed = true;
            Reaper.OPEN.remove(this);
            ServerConnection current = connection;
            connection = null;
            if (current != null) {
                current.close();
            }
        }
    }

    /**
     * Closes the connections of verifiers that became unreachable, and of
     * every open one when the JVM exits.
     */
    static final class Reaper {
        static final Set<Holder> OPEN = Collections.newSetFromMap(new ConcurrentHashMap<Holder, Boolean>());
        private static final ReferenceQueue<ServerVerifier> QUEUE = new ReferenceQueue<>();
        private static final Set<Ref> REFS = Collections.newSetFromMap(new ConcurrentHashMap<Ref, Boolean>());

        static {
            Thread reaper = new Thread(
                    () -> {
                        while (true) {
                            try {
                                Reference<? extends ServerVerifier> ref = QUEUE.remove();
                                REFS.remove(ref);
                                ((Ref) ref).holder.close();
                            } catch (InterruptedException e) {
                                return;
                            } catch (RuntimeException e) {
                                // one failed close must not end the reaper
                            }
                        }
                    },
                    "aprv-server-reaper");
            reaper.setDaemon(true);
            reaper.start();
            Runtime.getRuntime()
                    .addShutdownHook(new Thread(
                            () -> {
                                for (Holder holder : OPEN) {
                                    holder.close();
                                }
                            },
                            "aprv-server-shutdown"));
        }

        private static final class Ref extends PhantomReference<ServerVerifier> {
            final Holder holder;

            Ref(ServerVerifier verifier, Holder holder) {
                super(verifier, QUEUE);
                this.holder = holder;
            }
        }

        static void register(ServerVerifier verifier, Holder holder) {
            REFS.add(new Ref(verifier, holder));
        }
    }
}
