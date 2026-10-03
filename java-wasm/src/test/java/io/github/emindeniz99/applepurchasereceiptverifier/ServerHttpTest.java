package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What {@link HttpConn} and {@link ServerConnection} accept from a server,
 * against servers on raw sockets that misbehave on purpose, and under
 * JVM-wide settings that other code can change. A verdict is only as good
 * as the bytes it came from: a server that is not the one the source names
 * must be refused before it sees the token, and a body cut short or framed
 * two ways must not reach the caller as an answer.
 */
class ServerHttpTest {

    private static final String TOKEN = "a-token-only-the-real-server-may-see";

    @TempDir
    Path temp;

    /**
     * Code elsewhere in the JVM that trusts every certificate and every
     * name for {@link HttpsURLConnection} (a common legacy pair) does not
     * reach the engine: a self-signed server is refused before the request,
     * and the token, are written. The control shows the same server is
     * accepted by a plain HttpsURLConnection under those defaults.
     */
    @Test
    void aForgedServerIsRefusedWhateverTheJvmWideHttpsDefaults() throws Exception {
        KeyStore keys = keyStore("forged", "SAN=ip:127.0.0.1,dns:localhost");
        SSLSocketFactory factoryBefore = HttpsURLConnection.getDefaultSSLSocketFactory();
        HostnameVerifier verifierBefore = HttpsURLConnection.getDefaultHostnameVerifier();
        try (TlsServer server = new TlsServer(keys)) {
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[] {new TrustAll()}, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(trustAll.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);

            HttpURLConnection control = (HttpURLConnection)
                    new URL("https://127.0.0.1:" + server.port() + "/v1/info").openConnection(Proxy.NO_PROXY);
            assertEquals(200, control.getResponseCode(), "the JVM-wide defaults accept the forged server");
            control.disconnect();

            Engine.Server engine =
                    Engine.server(ServerSource.url(URI.create("https://127.0.0.1:" + server.port()), TOKEN));
            assertThrows(IllegalStateException.class, () -> Verifier.create(Config.defaults(), engine));
            assertFalse(server.received().contains(TOKEN), server.received());
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(factoryBefore);
            HttpsURLConnection.setDefaultHostnameVerifier(verifierBefore);
        }
    }

    /**
     * A certificate the JVM trusts, issued for another name, is refused
     * even with an allow-all default hostname verifier, and the server
     * reads nothing. HttpConn sets endpoint identification on the socket,
     * so the name fails inside the handshake. The JDK's message for the
     * name differs between versions, so the test reads what the server
     * saw, not the message.
     */
    @Test
    void aTrustedCertificateForAnotherNameIsRefused() throws Exception {
        KeyStore keys = keyStore("other", "SAN=dns:other.example");
        HostnameVerifier verifierBefore = HttpsURLConnection.getDefaultHostnameVerifier();
        try (TlsServer server = new TlsServer(keys);
                JvmTrust trust = new JvmTrust(keys)) {
            HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
            assertThrows(IOException.class, () -> get(server.port(), true, 5_000));
            assertTrue(server.connectionsDone.tryAcquire(10, TimeUnit.SECONDS), "the client closed the connection");
            assertEquals("", server.received());
        } finally {
            HttpsURLConnection.setDefaultHostnameVerifier(verifierBefore);
        }
    }

    /** The same trust with the right name is accepted, and the token reaches the server. */
    @Test
    void aTrustedCertificateForTheHostIsAccepted() throws Exception {
        KeyStore keys = keyStore("right", "SAN=ip:127.0.0.1");
        try (TlsServer server = new TlsServer(keys);
                JvmTrust trust = new JvmTrust(keys)) {
            assertEquals("{}", get(server.port(), true, 5_000).text());
            assertTrue(server.received().contains("X-Aprv-Token: " + TOKEN), server.received());
        }
    }

    /**
     * A body shorter than its Content-Length is an {@link EOFException},
     * which {@link ServerConnection#send} retries like a dropped
     * connection: three attempts, then a failure, never the short body.
     */
    @Test
    void aTruncatedBodyIsRefusedAndRetried() throws Exception {
        String head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n";
        try (RawServer server = new RawServer(head + "{\"status\":0,\"receipt\":{\"bundle_i")) {
            assertThrows(EOFException.class, () -> get(server.port(), false, 5_000));
            ServerConnection connection = ServerConnection.fixed(target(server.port(), false), "test");
            int before = server.requests.get();
            assertThrows(ServerProcessFailure.class, () -> connection.send("POST", "/v1/x", new byte[] {1}, 0L));
            assertEquals(3, server.requests.get() - before, "attempts");
        }
    }

    /**
     * A body is framed by chunks only when Transfer-Encoding is exactly
     * {@code chunked}: under {@code gzip, chunked} the chunks hold gzip
     * bytes. This body is cut short as well.
     */
    @Test
    void aTransferCodingOtherThanChunkedAloneIsRefused() throws Exception {
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n20\r\n{\"status\":0,")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * A coding whose name only contains {@code chunked} does not stand in
     * for a body's framing, and it does not make a Content-Length beside
     * it valid either. This body also ends before its length.
     */
    @Test
    void aTransferCodingNamedLikeChunkedIsRefused() throws Exception {
        try (RawServer server = new RawServer(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\nContent-Length: 100\r\n\r\n{\"status\":0,")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * A server that answers 401 with a Basic challenge never gets the
     * JVM's default {@link Authenticator}'s credentials: HttpConn asks no
     * Authenticator, so the 401 comes back with its problem document after
     * one connection and one request, on every JDK. HttpURLConnection on
     * Java 8 answered it 19 times an attempt (DECISIONS.md R17).
     */
    @Test
    void aBasicChallengeIsNotAnsweredWithTheJvmsCredentials() throws Exception {
        String problem = "{\"code\":\"UNAUTHORIZED\"}";
        String response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"aprv\"\r\n"
                + "Content-Type: application/problem+json\r\nContent-Length: " + problem.length() + "\r\n\r\n"
                + problem;
        AtomicInteger asked = new AtomicInteger();
        try (RawServer server = new RawServer(response)) {
            Authenticator.setDefault(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    asked.incrementAndGet();
                    return new PasswordAuthentication("app-user", "app-password".toCharArray());
                }
            });
            ServerConnection connection = ServerConnection.fixed(target(server.port(), false), "test");
            HttpConn.Response answer = connection.send("POST", "/v1/x", new byte[] {1}, 0L);
            assertEquals(401, answer.status);
            assertEquals(problem, answer.text());
            assertEquals(1, server.connections.get(), "connections");
            assertEquals(1, server.requests.get(), "requests");
            assertEquals(0, asked.get(), "the default Authenticator was asked");
            assertFalse(server.received().contains("Authorization"), server.received());
        } finally {
            Authenticator.setDefault(null);
        }
    }

    /** A truncated chunked body is refused too. */
    @Test
    void aTruncatedChunkedBodyIsRefused() throws Exception {
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n{\"status\":0,")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /** A body framed only by the connection's close might be cut short, so it is refused. */
    @Test
    void anUnframedBodyIsRefused() throws Exception {
        try (RawServer server = new RawServer("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":0}")) {
            IOException e = assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
            assertTrue(e.getMessage().contains("neither Content-Length nor chunked"), String.valueOf(e));
        }
    }

    /** A declared length over the cap is refused from the headers, without waiting for the body. */
    @Test
    void aDeclaredLengthOverTheCapIsRefusedFromTheHeaders() throws Exception {
        String head = "HTTP/1.1 200 OK\r\nContent-Length: " + (HttpConn.MAX_RESPONSE + 1L) + "\r\n\r\n";
        try (RawServer server = new RawServer(head, false)) {
            IOException e = assertThrows(IOException.class, () -> get(server.port(), false, 10_000));
            assertFalse(e instanceof SocketTimeoutException, String.valueOf(e));
            assertTrue(e.getMessage().contains("over " + HttpConn.MAX_RESPONSE), String.valueOf(e));
        }
    }

    /** Framed bodies, by length and by chunks, are read whole. */
    @Test
    void framedBodiesAreRead() throws Exception {
        try (RawServer server = new RawServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")) {
            assertEquals("{}", get(server.port(), false, 5_000).text());
        }
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n")) {
            assertEquals("{}", get(server.port(), false, 5_000).text());
        }
    }

    /**
     * A server that closes every connection before its status line gets a
     * POST three times: once per attempt of ServerConnection.send, and
     * never again inside an attempt (HttpURLConnection resent it once in
     * each, six in all).
     */
    @Test
    void aConnectionThatDiesBeforeTheStatusLineGetsTheRequestThreeTimes() throws Exception {
        try (RawServer server = new RawServer("")) {
            ServerConnection connection = ServerConnection.fixed(target(server.port(), false), "test");
            assertThrows(ServerProcessFailure.class, () -> connection.send("POST", "/v1/x", new byte[] {1}, 0L));
            assertEquals(3, server.requests.get(), "requests the server read");
        }
    }

    // ------------------------------------- the gaps docs/evidence/2026-10-02-java-http-options.md found

    /**
     * The two transfer-coding tests above send a body that fails anyway
     * (it ends before its chunk or its length). With a complete chunked
     * body, a coding other than {@code chunked} alone must still be refused:
     * {@code gzip, chunked} would hand over gzip bytes, and {@code xchunked}
     * is not chunked at all.
     */
    @Test
    void aCompleteBodyUnderAnotherTransferCodingIsRefused() throws Exception {
        for (String coding : new String[] {"gzip, chunked", "xchunked", "chunked, chunked"}) {
            try (RawServer server =
                    new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: " + coding + "\r\n\r\n2\r\n{}\r\n0\r\n\r\n")) {
                assertThrows(IOException.class, () -> get(server.port(), false, 5_000), coding);
            }
        }
    }

    /** Two Content-Lengths that differ leave the body's end unknown (RFC 9112 §6.3): refused. */
    @Test
    void twoDifferentContentLengthsAreRefused() throws Exception {
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 4\r\n\r\n{}XX")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * Whitespace between a field name and its colon must be rejected
     * (RFC 9112 §5.1); read as Content-Length it frames by a header a
     * proxy in between might have ignored.
     */
    @Test
    void whitespaceBeforeTheColonIsRefused() throws Exception {
        try (RawServer server = new RawServer("HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\n{}")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * A header line that starts with whitespace is an obsolete line fold
     * (RFC 9112 §5.2): read as its own field it would frame the body by a
     * Content-Length that a proxy in between reads as part of {@code X}.
     */
    @Test
    void whitespaceAtTheStartOfAHeaderLineIsRefused() throws Exception {
        try (RawServer server = new RawServer("HTTP/1.1 200 OK\r\nX: a\r\n Content-Length: 2\r\n\r\n{}")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * Two Transfer-Encoding lines are one list of codings, {@code chunked,
     * chunked} (RFC 9110 §5.3): chunked applied twice, which the
     * one-line form above refuses, must be refused when split as well.
     */
    @Test
    void aRepeatedTransferEncodingLineIsRefused() throws Exception {
        try (RawServer server = new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")) {
            assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
        }
    }

    /**
     * A chunk size is hex digits and nothing else (RFC 9112 §7.1). A sign,
     * whitespace or a {@code 0x} prefix that a lenient parser skips would
     * let a proxy in between and this client split the body in different
     * places. Eight digits or more are refused as well: seven already
     * exceed the 64 MiB cap. An extension after {@code ;} is still read.
     */
    @Test
    void aChunkSizeOtherThanHexDigitsIsRefused() throws Exception {
        for (String size : new String[] {"+2", " 2", "2 ", "0x2", "-2", "", "00000002"}) {
            try (RawServer server = new RawServer(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + size + "\r\n{}\r\n0\r\n\r\n")) {
                assertThrows(IOException.class, () -> get(server.port(), false, 5_000), "[" + size + "]");
            }
        }
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;name=value\r\n{}\r\n0\r\n\r\n")) {
            assertEquals("{}", get(server.port(), false, 5_000).text());
        }
    }

    /**
     * Lines end with CRLF. A bare LF taken as a line end, or a CR dropped
     * from inside a line, reads a head that a stricter parser in between
     * reads differently (RFC 9112 §2.2); aprv-server writes CRLF only.
     */
    @Test
    void aLineEndOtherThanCrlfIsRefused() throws Exception {
        String[] responses = {
            "HTTP/1.1 200 OK\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\n{}",
            "HTTP/1.1 200 OK\r\nContent-\rLength: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\n{}\r\n0\r\n\r\n",
        };
        for (String response : responses) {
            try (RawServer server = new RawServer(response)) {
                assertThrows(IOException.class, () -> get(server.port(), false, 5_000), response);
            }
        }
    }

    /**
     * A message with both Transfer-Encoding and Content-Length "ought to be
     * handled as an error", and the connection must not be reused
     * (RFC 9112 §6.3).
     */
    @Test
    void contentLengthWithChunkedIsNotReused() throws Exception {
        try (RawServer server = new RawServer(
                "HTTP/1.1 200 OK\r\nContent-Length: 40\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
                false)) {
            try (HttpConn conn = new HttpConn(target(server.port(), false), 5_000, 5_000)) {
                try {
                    conn.exchange("GET", "/v1/info", new byte[0], null);
                } catch (IOException refused) {
                    return; // refusing it is fine too
                }
                assertFalse(conn.reusable(), "the connection is kept for another request");
            }
        }
    }

    /**
     * A default ProxySelector set by other code in the JVM that sends
     * socket:// to a SOCKS proxy must not carry the token there: the
     * engine connects directly. The SOCKS listener accepts and reads.
     */
    @Test
    void aDefaultProxySelectorDoesNotRouteTheEngine() throws Exception {
        try (RawServer socks = new RawServer("", false);
                RawServer server = new RawServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")) {
            ProxySelector before = ProxySelector.getDefault();
            ProxySelector.setDefault(new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    return Collections.singletonList(
                            uri.getScheme().equals("socket")
                                    ? new Proxy(
                                            Proxy.Type.SOCKS,
                                            new InetSocketAddress(InetAddress.getLoopbackAddress(), socks.port()))
                                    : Proxy.NO_PROXY);
                }

                @Override
                public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
            });
            try {
                assertEquals("{}", get(server.port(), false, 2_000).text());
                assertEquals(0, socks.connections.get(), "connections to the SOCKS proxy");
            } finally {
                ProxySelector.setDefault(before);
            }
        }
    }

    /**
     * A JVM-wide default SSLContext that trusts everything (other code's
     * SSLContext.setDefault) must not make the engine accept a forged
     * server or send it the token.
     */
    @Test
    void aTrustAllDefaultSslContextDoesNotReachTheEngine() throws Exception {
        KeyStore keys = keyStore("forged-default", "SAN=ip:127.0.0.1");
        SSLContext before = SSLContext.getDefault();
        try (TlsServer server = new TlsServer(keys)) {
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[] {new TrustAll()}, null);
            SSLContext.setDefault(trustAll);
            assertThrows(IOException.class, () -> get(server.port(), true, 5_000));
            assertFalse(server.received().contains(TOKEN), server.received());
        } finally {
            SSLContext.setDefault(before);
        }
    }

    private static HttpConn.Target target(int port, boolean tls) {
        return new HttpConn.Target("127.0.0.1", port, tls, "", TOKEN, 0);
    }

    private static HttpConn.Response get(int port, boolean tls, int readTimeoutMillis) throws IOException {
        try (HttpConn conn = new HttpConn(target(port, tls), 5_000, readTimeoutMillis)) {
            return conn.exchange("GET", "/v1/info", new byte[0], null);
        }
    }

    /** A key pair and a self-signed certificate from the test JDK's keytool. */
    private KeyStore keyStore(String name, String subjectAltNames) throws Exception {
        Path file = temp.resolve(name + ".p12");
        Process keytool = new ProcessBuilder(
                        Paths.get(System.getProperty("java.home"), "bin", "keytool")
                                .toString(),
                        "-genkeypair",
                        "-keystore",
                        file.toString(),
                        "-storetype",
                        "PKCS12",
                        "-storepass",
                        "changeit",
                        "-keypass",
                        "changeit",
                        "-alias",
                        "server",
                        "-keyalg",
                        "EC",
                        "-keysize",
                        "256",
                        "-validity",
                        "2",
                        "-dname",
                        "CN=" + name,
                        "-ext",
                        subjectAltNames)
                .redirectErrorStream(true)
                .start();
        String output = new String(readAll(keytool.getInputStream()), StandardCharsets.UTF_8);
        assertEquals(0, keytool.waitFor(), output);
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            keys.load(in, "changeit".toCharArray());
        }
        return keys;
    }

    /**
     * Makes the JVM trust exactly the certificate in {@code keys}, as a
     * trust store that holds it would: the {@code javax.net.ssl.trustStore}
     * properties, which HttpConn's own TLS context reads, and the default
     * {@link SSLContext} and {@link HttpsURLConnection}'s default socket
     * factory, which the controls use. Restored on close.
     */
    private final class JvmTrust implements AutoCloseable {
        private final SSLContext contextBefore = SSLContext.getDefault();
        private final SSLSocketFactory factoryBefore = HttpsURLConnection.getDefaultSSLSocketFactory();
        private final String storeBefore = System.getProperty("javax.net.ssl.trustStore");
        private final String passwordBefore = System.getProperty("javax.net.ssl.trustStorePassword");
        private final String typeBefore = System.getProperty("javax.net.ssl.trustStoreType");

        JvmTrust(KeyStore keys) throws Exception {
            KeyStore trust = KeyStore.getInstance("JKS");
            trust.load(null, null);
            trust.setCertificateEntry("server", keys.getCertificate("server"));
            Path store = temp.resolve("trust-" + System.nanoTime() + ".jks");
            try (OutputStream out = Files.newOutputStream(store)) {
                trust.store(out, "changeit".toCharArray());
            }
            System.setProperty("javax.net.ssl.trustStore", store.toString());
            System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
            System.setProperty("javax.net.ssl.trustStoreType", "JKS");
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            SSLContext.setDefault(context);
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        }

        @Override
        public void close() {
            SSLContext.setDefault(contextBefore);
            HttpsURLConnection.setDefaultSSLSocketFactory(factoryBefore);
            restore("javax.net.ssl.trustStore", storeBefore);
            restore("javax.net.ssl.trustStorePassword", passwordBefore);
            restore("javax.net.ssl.trustStoreType", typeBefore);
        }

        private void restore(String key, String value) {
            if (value == null) {
                System.clearProperty(key);
            } else {
                System.setProperty(key, value);
            }
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) >= 0) {
            bytes.write(buffer, 0, n);
        }
        return bytes.toByteArray();
    }

    /** Reads one request's head and body; null when the client closed first. */
    private static String readRequest(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (head.length() < 4 || !head.substring(head.length() - 4).equals("\r\n\r\n")) {
            int c = in.read();
            if (c < 0) {
                return head.length() == 0 ? null : head.toString();
            }
            head.append((char) c);
        }
        for (String line : head.toString().split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                int length = Integer.parseInt(line.substring(15).trim());
                for (int i = 0; i < length; i++) {
                    if (in.read() < 0) {
                        break;
                    }
                }
            }
        }
        return head.toString();
    }

    /** Trusts every certificate: the legacy pattern the engine must not be reached by. */
    private static final class TrustAll implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /**
     * Answers each request on a connection with {@code response}, raw, then
     * closes the connection (or, when {@code close} is false, holds it open
     * until the client goes); counts the connections it accepted and the
     * requests it read.
     */
    private static final class RawServer implements AutoCloseable {
        final ServerSocket socket;
        final AtomicInteger connections = new AtomicInteger();
        final AtomicInteger requests = new AtomicInteger();
        private final List<Socket> open = new ArrayList<>();
        private final StringBuffer received = new StringBuffer();

        RawServer(String response) throws IOException {
            this(response, true);
        }

        RawServer(String response, boolean close) throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (true) {
                    Socket client;
                    try {
                        client = socket.accept();
                    } catch (IOException e) {
                        return;
                    }
                    connections.incrementAndGet();
                    synchronized (open) {
                        open.add(client);
                    }
                    try {
                        String request = readRequest(client.getInputStream());
                        if (request != null) {
                            received.append(request);
                            requests.incrementAndGet();
                            OutputStream out = client.getOutputStream();
                            out.write(response.getBytes(StandardCharsets.ISO_8859_1));
                            out.flush();
                        }
                        if (close) {
                            client.close();
                        }
                    } catch (IOException e) {
                        // the client went away
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        /** The heads of the requests read so far. */
        String received() {
            return received.toString();
        }

        @Override
        public void close() throws IOException {
            socket.close();
            synchronized (open) {
                for (Socket client : open) {
                    client.close();
                }
            }
        }
    }

    /**
     * A TLS server with the given key that records what clients send and
     * answers each request with {@code {}}. {@link #handshake} opens on the
     * first completed handshake, and {@link #connectionsDone} gets a permit
     * each time a connection's requests have all been read.
     */
    private static final class TlsServer implements AutoCloseable {
        final SSLServerSocket socket;
        final CountDownLatch handshake = new CountDownLatch(1);
        final Semaphore connectionsDone = new Semaphore(0);
        private final StringBuffer received = new StringBuffer();

        TlsServer(KeyStore keys) throws Exception {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, "changeit".toCharArray());
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(factory.getKeyManagers(), null, null);
            socket = (SSLServerSocket)
                    context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (true) {
                    try (SSLSocket client = (SSLSocket) socket.accept()) {
                        client.setSoTimeout(5_000);
                        try {
                            client.startHandshake();
                            handshake.countDown();
                            String request;
                            while ((request = readRequest(client.getInputStream())) != null) {
                                received.append(request);
                                client.getOutputStream()
                                        .write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                                                .getBytes(StandardCharsets.US_ASCII));
                            }
                        } catch (IOException e) {
                            // a refused handshake, a closed connection
                        } finally {
                            connectionsDone.release();
                        }
                    } catch (IOException e) {
                        return;
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        String received() {
            return received.toString();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
