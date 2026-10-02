package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import org.jspecify.annotations.Nullable;

/**
 * Requests to one {@code aprv-server}: either one the caller runs
 * ({@link ServerSource#url}, a fixed address) or a supervised child
 * ({@link ServerProcess}). Each request goes through the JDK's
 * {@link HttpURLConnection}, whose keep-alive cache reuses connections, one
 * request at a time on each, so calls on several threads run in parallel.
 *
 * <p>A request whose connection fails is tried again, up to three attempts
 * in all: a keep-alive connection the server closed is replaced, and a child
 * that died is started again first. Inside each attempt HttpURLConnection
 * may send the request up to twice more ({@link #exchange}), so one call
 * can put it on up to nine connections, and a server that reads each
 * request and closes before the status line receives it six times. On
 * Java 8 only, a server that answers 401 with a challenge the JVM's
 * default {@link java.net.Authenticator} has credentials for receives the
 * request up to {@code http.maxRedirects} (20) times an attempt, each
 * after the first with those credentials, and 60 times in a call when it
 * answers only that way ({@link #exchange}); any of those sends can also
 * take the resends above. Verification has no side effects, so a retry
 * cannot change an answer.
 * When every attempt fails the call throws {@link ServerProcessFailure}.</p>
 */
final class ServerConnection {

    static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    /** Above the server's default guest time limit of 10 s per call. */
    static final int READ_TIMEOUT_MILLIS = 60_000;

    /** Larger than any answer the module writes (the payload of a 3 MiB receipt, as JSON). */
    static final int MAX_RESPONSE = 64 << 20;

    private static final int ATTEMPTS = 3;

    /** {@code HttpURLConnection.setAuthenticator}, from Java 9; null on Java 8. */
    private static final @Nullable Method SET_AUTHENTICATOR = setAuthenticatorMethod();

    /** Has no credentials for any request: {@link Authenticator}'s own answer is null. */
    private static final Authenticator NO_CREDENTIALS = new Authenticator() {};

    /** The default {@link SSLContext} {@link #tlsFactory} was taken from. */
    private static @Nullable SSLContext tlsContext;

    private static @Nullable SSLSocketFactory tlsFactory;

    /** Where the server is: host, port, TLS or not, a base path, the token, and which child it is. */
    static final class Target {
        final String host;
        final int port;
        final boolean tls;
        final String basePath;
        final @Nullable String token;
        final int generation;

        Target(String host, int port, boolean tls, String basePath, @Nullable String token, int generation) {
            this.host = host;
            this.port = port;
            this.tls = tls;
            this.basePath = basePath;
            this.token = token;
            this.generation = generation;
        }
    }

    /** A complete response. */
    static final class Response {
        final int status;
        final String contentType;
        final byte[] body;

        Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    private final @Nullable Target fixed;
    private final @Nullable ServerProcess process;
    private final String description;
    private volatile boolean closed;

    private ServerConnection(@Nullable Target fixed, @Nullable ServerProcess process, String description) {
        this.fixed = fixed;
        this.process = process;
        this.description = description;
    }

    static ServerConnection fixed(Target target, String description) {
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
    Response send(String method, String path, byte[] body, @Nullable Long nowMs) {
        IOException last = null;
        for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
            if (closed) {
                throw new ServerProcessFailure("the server engine was closed");
            }
            Target target = process != null ? process.target() : fixed;
            try {
                return exchange(target, method, path, body, nowMs, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS);
            } catch (IOException e) {
                last = e;
                if (process != null) {
                    process.recover(target.generation);
                }
            }
        }
        throw new ServerProcessFailure(
                "aprv-server (" + description + ") did not answer " + method + " " + path + ": " + last, last);
    }

    /**
     * One request on {@link HttpURLConnection}. {@code nowMs}, when given,
     * goes out as {@code X-Aprv-Now-Ms}. The connection is opened with
     * {@link Proxy#NO_PROXY}, so no {@code http.proxyHost},
     * {@code https.proxyHost} or HTTP proxy from the default
     * {@code ProxySelector} sends a request elsewhere. The socket under it
     * still asks the default {@code ProxySelector} for a SOCKS proxy
     * ({@code socket://}, or {@code socksProxyHost}) on Java 8 for both
     * schemes and on JDK 21 for {@code https}, as the hand-written client
     * did on every JDK. It follows no redirect and uses no response cache.
     *
     * <p>Over {@code https} the request never uses
     * {@link HttpsURLConnection}'s JVM-wide defaults, which any code in the
     * JVM can replace (a trust-all socket factory with an allow-all hostname
     * verifier is a common pair). Its socket factory is the default
     * {@link SSLContext}'s. The hand-written client took
     * {@code SSLSocketFactory.getDefault()}, which a class named by the
     * {@code ssl.SocketFactory.provider} security property replaces; this
     * one does not follow that property, and like any HttpsURLConnection it
     * applies the {@code https.protocols} and {@code https.cipherSuites}
     * system properties. Its hostname verifier refuses every name: with a
     * verifier that is not the JDK's default, the JDK checks the
     * certificate against the host by RFC 2818 after the handshake and asks
     * the verifier only on a mismatch, before any request byte or the token
     * is written.</p>
     *
     * <p>A 401 is returned as it is. On Java 9 and later the connection gets
     * its own {@link java.net.Authenticator} that has no credentials, so a
     * {@code WWW-Authenticate} challenge is never answered with those of the
     * JVM's default Authenticator, which the hand-written client never
     * consulted either. Java 8 has no per-connection Authenticator: there,
     * while the default Authenticator answers a challenge, the JDK sends
     * the request again with its credentials (and the body and token) on a
     * new connection, up to {@code http.maxRedirects} (20 by default) sends
     * in all, and then drops the last 401's body. Setting an
     * {@code Authorization} header does not stop that on any JDK
     * (docs/evidence/2026-10-02-java-httpurlconnection.md).</p>
     *
     * <p>A POST body is buffered, not streamed. HttpURLConnection then writes
     * the headers and a body of up to about 8 KiB (a g5 receipt) in one
     * write, and reads the body of a 401. Streamed with
     * {@code setFixedLengthStreamingMode}, the headers go out first, Nagle's
     * algorithm holds the body back 1 to 2 ms a call, and a 401's body is
     * dropped (docs/evidence/2026-10-02-java-httpurlconnection.md). The
     * price is HttpURLConnection's own resends, on a new connection each:
     * once when a buffered request's connection fails before the status
     * line, other than by a read timeout ({@code sun.net.http.retryPost}, a
     * JVM-wide property this library does not set), and once when writing
     * the request fails, whatever that property says. A resend cannot
     * change a verdict: verification has no side effects and the request
     * carries its own {@code X-Aprv-Now-Ms}.</p>
     *
     * <p>The body must be framed, as the hand-written client required: by
     * chunked encoding, or by a {@code Content-Length} of at most
     * {@link #MAX_RESPONSE} whose bytes all arrive. Only a 204, a 304 or the
     * answer to a HEAD may carry neither.</p>
     *
     * @throws IOException when the server cannot be reached or fails TLS, the
     *     answer is not HTTP, its body is unframed or over
     *     {@link #MAX_RESPONSE} bytes, or the connection closes inside it
     *     ({@link EOFException})
     */
    static Response exchange(
            Target target,
            String method,
            String path,
            byte[] body,
            @Nullable Long nowMs,
            int connectTimeoutMillis,
            int readTimeoutMillis)
            throws IOException {
        URL url = new URL(target.tls ? "https" : "http", target.host, target.port, target.basePath + path);
        HttpURLConnection http = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        try {
            if (target.tls) {
                if (!(http instanceof HttpsURLConnection)) {
                    // A URLStreamHandlerFactory replaced the JDK's https handler.
                    throw new IOException("the JVM's https handler is not an HttpsURLConnection");
                }
                HttpsURLConnection https = (HttpsURLConnection) http;
                https.setSSLSocketFactory(tlsFactory());
                https.setHostnameVerifier((host, session) -> false);
            }
            withoutCredentials(http);
            http.setRequestMethod(method);
            http.setConnectTimeout(connectTimeoutMillis);
            http.setReadTimeout(readTimeoutMillis);
            http.setUseCaches(false);
            http.setInstanceFollowRedirects(false);
            if (target.token != null) {
                http.setRequestProperty("X-Aprv-Token", target.token);
            }
            if (nowMs != null) {
                http.setRequestProperty("X-Aprv-Now-Ms", Long.toUnsignedString(nowMs));
            }
            if (method.equals("POST")) {
                http.setRequestProperty("Content-Type", "application/octet-stream");
                http.setDoOutput(true);
                try (OutputStream out = http.getOutputStream()) {
                    out.write(body);
                }
            }
            int status = http.getResponseCode();
            if (status < 0) {
                throw new IOException("not an HTTP response");
            }
            String encoding = http.getHeaderField("Transfer-Encoding");
            boolean chunked =
                    encoding != null && encoding.toLowerCase(Locale.ROOT).contains("chunked");
            long length = chunked ? -1 : http.getContentLengthLong();
            if (length > MAX_RESPONSE) {
                throw new IOException("a response over " + MAX_RESPONSE + " bytes");
            }
            if (!chunked && length < 0 && status != 204 && status != 304 && !method.equals("HEAD")) {
                throw new IOException("a response with neither Content-Length nor chunked encoding");
            }
            // HttpURLConnection reads a status of 400 or more from the error stream.
            InputStream in = status >= 400 ? http.getErrorStream() : http.getInputStream();
            byte[] responseBody = in == null ? new byte[0] : read(in);
            if (length >= 0 && responseBody.length != length) {
                throw new EOFException("the connection closed inside a response");
            }
            String contentType = http.getContentType();
            return new Response(status, contentType == null ? "" : contentType, responseBody);
        } catch (IOException | RuntimeException e) {
            http.disconnect();
            throw e;
        }
    }

    /**
     * The default {@link SSLContext}'s socket factory, one instance for as
     * long as that context stays the default: the JDK's keep-alive cache
     * reuses a connection only for the same factory instance, and the
     * context makes a new one on each call.
     */
    private static synchronized SSLSocketFactory tlsFactory() throws IOException {
        SSLContext context;
        try {
            context = SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("no default TLS context", e);
        }
        SSLSocketFactory factory = tlsFactory;
        if (context != tlsContext || factory == null) {
            factory = context.getSocketFactory();
            tlsContext = context;
            tlsFactory = factory;
        }
        return factory;
    }

    private static @Nullable Method setAuthenticatorMethod() {
        try {
            return HttpURLConnection.class.getMethod("setAuthenticator", Authenticator.class);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    /**
     * Gives the connection {@link #NO_CREDENTIALS}, so that a 401 with a
     * {@code WWW-Authenticate} challenge comes back as it is, never resent
     * with credentials from {@link Authenticator#setDefault}. Java 9 and
     * later; Java 8 has no per-connection Authenticator ({@link #exchange}).
     */
    private static void withoutCredentials(HttpURLConnection http) throws IOException {
        Method method = SET_AUTHENTICATOR;
        if (method == null) {
            return;
        }
        try {
            method.invoke(http, NO_CREDENTIALS);
        } catch (InvocationTargetException e) {
            // java.net.HttpURLConnection's own method throws: a
            // URLStreamHandlerFactory replaced the JDK's handler.
            throw new IOException("the JVM's http handler takes no per-connection Authenticator", e.getCause());
        } catch (IllegalAccessException e) {
            throw new IOException("HttpURLConnection.setAuthenticator is not accessible", e);
        }
    }

    /**
     * The whole body, then closed: a body read to its end hands the
     * connection back to the keep-alive cache.
     */
    private static byte[] read(InputStream in) throws IOException {
        try (InputStream body = in) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[16 << 10];
            int n;
            while ((n = body.read(buffer)) >= 0) {
                if (bytes.size() + n > MAX_RESPONSE) {
                    throw new IOException("a response over " + MAX_RESPONSE + " bytes");
                }
                bytes.write(buffer, 0, n);
            }
            return bytes.toByteArray();
        }
    }

    /** Refuses later calls and stops the child, if this connection owns one. */
    void close() {
        closed = true;
        if (process != null) {
            process.stop();
        }
    }
}
