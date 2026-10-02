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
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.util.List;
import java.util.Locale;
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
 * What {@link ServerConnection} accepts from a server, against servers on
 * raw sockets that misbehave on purpose. A verdict is only as good as the
 * bytes it came from: a server that is not the one the source names must
 * be refused before it sees the token, and a body cut short must not reach
 * the caller as an answer.
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
     * even with an allow-all default hostname verifier: the server
     * completes the handshake (so trust passed) and never sees a request.
     */
    @Test
    void aTrustedCertificateForAnotherNameIsRefused() throws Exception {
        KeyStore keys = keyStore("other", "SAN=dns:other.example");
        HostnameVerifier verifierBefore = HttpsURLConnection.getDefaultHostnameVerifier();
        try (TlsServer server = new TlsServer(keys);
                JvmTrust trust = new JvmTrust(keys)) {
            HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
            IOException e = assertThrows(IOException.class, () -> get(server.port(), true, 5_000));
            assertTrue(e.getMessage().contains("hostname wrong"), String.valueOf(e));
            assertTrue(server.handshakes.get() > 0, "the handshake completed, so the name was what failed");
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
     * {@code chunked}, the one value the JDK de-chunks. Here the JDK
     * hands over the chunked bytes as they are and stops at the close, so
     * reading them as a chunked answer would take a cut-short body whole.
     */
    @Test
    void aTransferCodingOtherThanChunkedAloneIsRefused() throws Exception {
        try (RawServer server =
                new RawServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n20\r\n{\"status\":0,")) {
            IOException e = assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
            assertTrue(e.getMessage().contains("Transfer-Encoding gzip, chunked"), String.valueOf(e));
        }
    }

    /**
     * A coding whose name only contains {@code chunked} does not stand in
     * for a body's framing: here the JDK reads by the Content-Length, and
     * the body ends before it.
     */
    @Test
    void aTransferCodingNamedLikeChunkedIsRefused() throws Exception {
        try (RawServer server = new RawServer(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\nContent-Length: 100\r\n\r\n{\"status\":0,")) {
            IOException e = assertThrows(IOException.class, () -> get(server.port(), false, 5_000));
            assertTrue(e.getMessage().contains("Transfer-Encoding xchunked"), String.valueOf(e));
        }
    }

    /**
     * A server that answers 401 with a Basic challenge never gets the
     * JVM's default {@link Authenticator}'s credentials on Java 9 and
     * later: the 401 comes back after one request, as the hand-written
     * client returned it. Java 8 has no per-connection Authenticator, so
     * there the JDK resends the request with the credentials up to
     * {@code http.maxRedirects} (20) times an attempt; this pins that
     * bound, the residual DECISIONS.md R17 records.
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
            if (System.getProperty("java.specification.version").equals("1.8")) {
                assertThrows(ServerProcessFailure.class, () -> connection.send("POST", "/v1/x", new byte[] {1}, 0L));
                assertEquals(3 * 20, server.requests.get(), "requests on Java 8: 20 an attempt");
                assertTrue(server.received().contains("Authorization: Basic"), server.received());
            } else {
                ServerConnection.Response answer = connection.send("POST", "/v1/x", new byte[] {1}, 0L);
                assertEquals(401, answer.status);
                assertEquals(problem, answer.text());
                assertEquals(1, server.requests.get(), "requests");
                assertEquals(0, asked.get(), "the default Authenticator was asked");
                assertFalse(server.received().contains("Authorization"), server.received());
            }
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
        String head = "HTTP/1.1 200 OK\r\nContent-Length: " + (ServerConnection.MAX_RESPONSE + 1L) + "\r\n\r\n";
        try (RawServer server = new RawServer(head, false)) {
            IOException e = assertThrows(IOException.class, () -> get(server.port(), false, 10_000));
            assertFalse(e instanceof SocketTimeoutException, String.valueOf(e));
            assertTrue(e.getMessage().contains("over " + ServerConnection.MAX_RESPONSE), String.valueOf(e));
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
     * POST six times: the JDK resends it once inside each of the three
     * attempts (sun.net.http.retryPost, true by default).
     */
    @Test
    void aConnectionThatDiesBeforeTheStatusLineGetsTheRequestSixTimes() throws Exception {
        try (RawServer server = new RawServer("")) {
            ServerConnection connection = ServerConnection.fixed(target(server.port(), false), "test");
            assertThrows(ServerProcessFailure.class, () -> connection.send("POST", "/v1/x", new byte[] {1}, 0L));
            assertEquals(6, server.requests.get(), "requests the server read");
        }
    }

    private static ServerConnection.Target target(int port, boolean tls) {
        return new ServerConnection.Target("127.0.0.1", port, tls, "", TOKEN, 0);
    }

    private static ServerConnection.Response get(int port, boolean tls, int readTimeoutMillis) throws IOException {
        return ServerConnection.exchange(
                target(port, tls), "GET", "/v1/info", new byte[0], null, 5_000, readTimeoutMillis);
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
     * trust store that holds it would: the default {@link SSLContext} and
     * {@link HttpsURLConnection}'s default socket factory, which the JDK
     * takes from that context once and keeps. Restored on close.
     */
    private static final class JvmTrust implements AutoCloseable {
        private final SSLContext contextBefore = SSLContext.getDefault();
        private final SSLSocketFactory factoryBefore = HttpsURLConnection.getDefaultSSLSocketFactory();

        JvmTrust(KeyStore keys) throws Exception {
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            trust.setCertificateEntry("server", keys.getCertificate("server"));
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
     * until the client goes); counts the requests it read.
     */
    private static final class RawServer implements AutoCloseable {
        final ServerSocket socket;
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

    /** A TLS server with the given key that records what clients send and answers each request with {@code {}}. */
    private static final class TlsServer implements AutoCloseable {
        final SSLServerSocket socket;
        final AtomicInteger handshakes = new AtomicInteger();
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
                            handshakes.incrementAndGet();
                            String request;
                            while ((request = readRequest(client.getInputStream())) != null) {
                                received.append(request);
                                client.getOutputStream()
                                        .write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                                                .getBytes(StandardCharsets.US_ASCII));
                            }
                        } catch (IOException e) {
                            // a refused handshake, a closed connection
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
