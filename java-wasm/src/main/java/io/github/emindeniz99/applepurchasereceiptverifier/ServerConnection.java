package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;

/**
 * Requests to one {@code aprv-server}: either one the caller runs
 * ({@link ServerSource#url}, a fixed address) or a supervised child
 * ({@link ServerProcess}). Keeps a pool of keep-alive connections, one
 * request at a time on each, so calls on several threads run in parallel.
 * At most {@code maxIdle} connections are kept between calls, as
 * {@link GuestPool} keeps instances; one returned past that is closed, so a
 * burst of callers does not leave a socket open per caller on both sides.
 *
 * <p>A request whose connection fails is sent again, up to three times in
 * all: a keep-alive connection the server closed is replaced, and a child
 * that died is started again first. Verification has no side effects, so a
 * retry cannot change an answer. When every attempt fails the call throws
 * {@link ServerProcessFailure}.</p>
 */
final class ServerConnection {

    static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    /** Above the server's default guest time limit of 10 s per call. */
    static final int READ_TIMEOUT_MILLIS = 60_000;

    private static final int ATTEMPTS = 3;

    private final HttpConn.@Nullable Target fixed;
    private final @Nullable ServerProcess process;
    private final String description;
    private final int maxIdle;
    private final ConcurrentLinkedQueue<HttpConn> idle = new ConcurrentLinkedQueue<>();
    private final AtomicInteger idleCount = new AtomicInteger();
    private volatile boolean closed;
    /** The module's {@code max_input_bytes}, as {@code GET /v1/info} stated it; 0 until it is read. */
    private volatile int maxInputBytes;

    private ServerConnection(
            HttpConn.@Nullable Target fixed, @Nullable ServerProcess process, String description, int maxIdle) {
        this.fixed = fixed;
        this.process = process;
        this.description = description;
        this.maxIdle = maxIdle;
    }

    /** The idle connections kept by default: the CPU count, at least two, as for {@link GuestPool}. */
    private static int defaultMaxIdle() {
        return Math.max(2, Runtime.getRuntime().availableProcessors());
    }

    static ServerConnection fixed(HttpConn.Target target, String description) {
        return fixed(target, description, defaultMaxIdle());
    }

    static ServerConnection fixed(HttpConn.Target target, String description, int maxIdle) {
        return new ServerConnection(target, null, description, maxIdle);
    }

    /** Starts the child now, so a start failure belongs to the source that named it. */
    static ServerConnection managed(ServerProcess process, String description) {
        process.target();
        return new ServerConnection(null, process, description, defaultMaxIdle());
    }

    String description() {
        return description;
    }

    /**
     * The most bytes of one input to send: the module's
     * {@code max_input_bytes}, which {@link ServerSources#open} reads before it
     * hands the connection out.
     *
     * @throws ServerProcessFailure when it was never read, rather than cut
     *     every input to nothing
     */
    int maxInputBytes() {
        int max = maxInputBytes;
        if (max < 1) {
            throw new ServerProcessFailure("aprv-server (" + description + "): its max_input_bytes was never read");
        }
        return max;
    }

    void maxInputBytes(int maxInputBytes) {
        this.maxInputBytes = maxInputBytes;
    }

    @Nullable
    ServerProcess process() {
        return process;
    }

    /**
     * One request and its complete response, whatever its status.
     *
     * @throws ServerProcessFailure when the server cannot be reached after
     *     every attempt
     */
    HttpConn.Response send(String method, String path, byte[] body, @Nullable Long nowMs) {
        IOException last = null;
        for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
            if (closed) {
                throw new ServerProcessFailure("the server engine was closed");
            }
            HttpConn.Target target = process != null ? process.target() : fixed;
            HttpConn conn = takeIdle();
            while (conn != null && conn.target != target) {
                conn.close(); // a connection to a child that has since been replaced
                conn = takeIdle();
            }
            try {
                if (conn == null) {
                    conn = new HttpConn(target, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS);
                }
                HttpConn.Response response = conn.exchange(method, path, body, nowMs);
                if (!conn.reusable() || closed || !keepIdle(conn)) {
                    conn.close();
                }
                return response;
            } catch (IOException e) {
                last = e;
                if (conn != null) {
                    conn.close();
                }
                if (process != null) {
                    process.recover(target.generation);
                }
            }
        }
        throw new ServerProcessFailure(
                "aprv-server (" + description + ") did not answer " + method + " " + path + ": " + last, last);
    }

    /** How many connections are idle now, for tests. */
    int idle() {
        return idleCount.get();
    }

    @Nullable
    private HttpConn takeIdle() {
        HttpConn conn = idle.poll();
        if (conn != null) {
            idleCount.decrementAndGet();
        }
        return conn;
    }

    /** Keeps {@code conn} for a later call, unless {@code maxIdle} are kept already. */
    private boolean keepIdle(HttpConn conn) {
        if (idleCount.incrementAndGet() <= maxIdle) {
            idle.add(conn);
            return true;
        }
        idleCount.decrementAndGet();
        return false;
    }

    /** Closes the pooled connections and stops the child, if this connection owns one. */
    void close() {
        closed = true;
        HttpConn conn;
        while ((conn = takeIdle()) != null) {
            conn.close();
        }
        if (process != null) {
            process.stop();
        }
    }
}
