package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.jspecify.annotations.Nullable;

/**
 * Requests to one {@code aprv-server}: either one the caller runs
 * ({@link ServerSource#url}, a fixed address) or a supervised child
 * ({@link ServerProcess}). Keeps a pool of keep-alive connections, one
 * request at a time on each, so calls on several threads run in parallel.
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
    private final ConcurrentLinkedQueue<HttpConn> idle = new ConcurrentLinkedQueue<>();
    private volatile boolean closed;

    private ServerConnection(HttpConn.@Nullable Target fixed, @Nullable ServerProcess process, String description) {
        this.fixed = fixed;
        this.process = process;
        this.description = description;
    }

    static ServerConnection fixed(HttpConn.Target target, String description) {
        return new ServerConnection(target, null, description);
    }

    /** Starts the child now, so a start failure belongs to the source that named it. */
    static ServerConnection managed(ServerProcess process, String description) {
        process.target();
        return new ServerConnection(null, process, description);
    }

    String description() {
        return description;
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
            HttpConn conn = idle.poll();
            while (conn != null && conn.target != target) {
                conn.close(); // a connection to a child that has since been replaced
                conn = idle.poll();
            }
            try {
                if (conn == null) {
                    conn = new HttpConn(target, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS);
                }
                HttpConn.Response response = conn.exchange(method, path, body, nowMs);
                if (conn.reusable() && !closed) {
                    idle.add(conn);
                } else {
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

    /** Closes the pooled connections and stops the child, if this connection owns one. */
    void close() {
        closed = true;
        HttpConn conn;
        while ((conn = idle.poll()) != null) {
            conn.close();
        }
        if (process != null) {
            process.stop();
        }
    }
}
