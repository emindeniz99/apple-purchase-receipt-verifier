package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * One POST per scenario, from each candidate client, to a server on a raw
 * socket that misbehaves on purpose, or under JVM-wide state that other
 * code in the same JVM (or a -D flag) could set. Prints one line per
 * scenario and client: what the client returned, and what the server (and
 * any proxy listener) saw.
 *
 * <p>Modes: {@code plain} (framing, auth, redirects, resends, proxies) and
 * {@code tls KEYSTORE_DIR} (run with -Djavax.net.ssl.trustStore pointing at
 * a store that trusts the "right" and "other" certificates; see run.sh).</p>
 */
public final class ClientMatrix {

    static final String TOKEN = "a-token-only-the-real-server-may-see";
    static final int CAP = 64 << 20;
    static final int READ_TIMEOUT = 3_000;

    /** What a client sends: one POST with the token header, the response body read whole up to CAP. */
    interface Client {
        String name();

        Answer post(String scheme, String host, int port, byte[] body) throws Exception;
    }

    static final class Answer {
        final int status;
        final byte[] body;

        Answer(int status, byte[] body) {
            this.status = status;
            this.body = body;
        }

        @Override
        public String toString() {
            String text = new String(body, StandardCharsets.ISO_8859_1);
            if (text.length() > 24) {
                text = text.substring(0, 24) + "...";
            }
            return "ACCEPTED " + status + " body=" + body.length + "B '" + text.replace("\r", "\\r").replace("\n", "\\n")
                    + "'";
        }
    }

    // ------------------------------------------------------------------ clients

    /** The hand-written client on origin/main. */
    static final class HttpConnClient implements Client {
        @Override
        public String name() {
            return "httpconn";
        }

        @Override
        public Answer post(String scheme, String host, int port, byte[] body) throws Exception {
            HttpConn.Target target = new HttpConn.Target(host, port, scheme.equals("https"), "", TOKEN, 0);
            try (HttpConn conn = new HttpConn(target, 5_000, READ_TIMEOUT)) {
                HttpConn.Response r = conn.exchange("POST", "/v1/x", body, 0L);
                return new Answer(r.status, r.body);
            }
        }
    }

    static List<Client> clients() {
        List<Client> clients = new ArrayList<>();
        clients.add(new HttpConnClient());
        clients.add(Hc5Clients.hardened());
        clients.add(Hc5Clients.defaults());
        if (!System.getProperty("java.specification.version").startsWith("1.")) {
            try {
                Class<?> jnh = Class.forName("io.github.emindeniz99.applepurchasereceiptverifier.JnhClients");
                clients.add((Client) jnh.getMethod("hardened").invoke(null));
                clients.add((Client) jnh.getMethod("defaults").invoke(null));
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        }
        return clients;
    }

    static List<Client> hardenedClients() {
        List<Client> clients = new ArrayList<>();
        for (Client client : clients()) {
            if (!client.name().endsWith("-default")) {
                clients.add(client);
            }
        }
        return clients;
    }

    // ------------------------------------------------------------------ scenarios

    static String ok(String headers, String body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + headers + "\r\n" + body;
    }

    static void plain() throws Exception {
        Map<String, String> canned = new LinkedHashMap<>();
        canned.put("framed by length", ok("Content-Length: 2\r\n", "{}"));
        canned.put("framed by chunks", ok("Transfer-Encoding: chunked\r\n", "2\r\n{}\r\n0\r\n\r\n"));
        canned.put("short of Content-Length", ok("Content-Length: 100\r\n", "{\"status\":0,"));
        canned.put("chunk cut short", ok("Transfer-Encoding: chunked\r\n", "20\r\n{\"status\":0,"));
        canned.put("unframed, read to close", ok("Connection: close\r\n", "{}"));
        canned.put("TE gzip, chunked (complete)", ok("Transfer-Encoding: gzip, chunked\r\n", "2\r\n{}\r\n0\r\n\r\n"));
        canned.put("TE xchunked (complete chunks)", ok("Transfer-Encoding: xchunked\r\n", "2\r\n{}\r\n0\r\n\r\n"));
        canned.put("two different Content-Lengths", ok("Content-Length: 2\r\nContent-Length: 4\r\n", "{}XX"));
        canned.put("Content-Length and chunked", ok("Content-Length: 40\r\nTransfer-Encoding: chunked\r\n",
                "2\r\n{}\r\n0\r\n\r\n"));
        canned.put("Content-Length with a sign", ok("Content-Length: +2\r\n", "{}"));
        canned.put("space before the colon", ok("Content-Length : 2\r\n", "{}"));
        canned.put("Content-Encoding gzip", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                + "Content-Length: " + gzip("{}").length() + "\r\n\r\n" + gzip("{}"));
        canned.put("closed before the status line", "");

        for (Map.Entry<String, String> scenario : canned.entrySet()) {
            for (Client client : clients()) {
                try (RawServer server = new RawServer(scenario.getValue(), true)) {
                    String outcome = call(client, "http", server.port());
                    report(scenario.getKey(), client, outcome, server.stats());
                }
            }
        }

        // A declared length over the cap, with the body never sent: refused from the headers, or a wait?
        // The *-default clients are left out here and below: HttpClient 5's default read timeout is
        // 3 minutes, and java.net.http's default has none.
        for (Client client : hardenedClients()) {
            try (RawServer server = new RawServer(ok("Content-Length: " + (CAP + 1L) + "\r\n", ""), false)) {
                long t0 = System.nanoTime();
                String outcome = call(client, "http", server.port());
                report("Content-Length over the cap, no body", client,
                        outcome + " after " + (System.nanoTime() - t0) / 1_000_000 + " ms", server.stats());
            }
        }

        // A body dripped one byte every 700 ms: under the read timeout each time, 5.6 s in all.
        for (Client client : hardenedClients()) {
            try (RawServer server = new RawServer(ok("Content-Length: 8\r\n", "{\"a\":12}"), true)) {
                server.dripMillis = 700;
                long t0 = System.nanoTime();
                String outcome = call(client, "http", server.port());
                report("body dripped (read timeout 3 s)", client,
                        outcome + " after " + (System.nanoTime() - t0) / 1_000_000 + " ms", server.stats());
            }
        }

        // 401 with a Basic challenge while the JVM has a default Authenticator.
        AtomicInteger asked = new AtomicInteger();
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                asked.incrementAndGet();
                return new PasswordAuthentication("app-user", "app-password".toCharArray());
            }
        });
        String problem = "{\"code\":\"UNAUTHORIZED\"}";
        for (Client client : clients()) {
            asked.set(0);
            try (RawServer server = new RawServer("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\n"
                    + "Content-Type: application/problem+json\r\nContent-Length: " + problem.length() + "\r\n\r\n"
                    + problem, true)) {
                String outcome = call(client, "http", server.port());
                report("401 Basic, default Authenticator set", client, outcome + "; Authenticator asked " + asked.get(),
                        server.stats());
            }
        }
        Authenticator.setDefault(null);

        // Redirects to a second server: followed (and with what) or returned?
        for (String code : new String[] {"307 Temporary Redirect", "302 Found"}) {
            for (Client client : clients()) {
                try (RawServer elsewhere = new RawServer(ok("Content-Length: 2\r\n", "{}"), true);
                        RawServer server = new RawServer("HTTP/1.1 " + code + "\r\nLocation: http://127.0.0.1:"
                                + elsewhere.port() + "/elsewhere\r\nContent-Length: 0\r\n\r\n", true)) {
                    String outcome = call(client, "http", server.port());
                    report("redirect " + code.substring(0, 3), client, outcome + "; elsewhere saw " + elsewhere.stats(),
                            server.stats());
                }
            }
        }

        // A default ProxySelector (in-JVM code) that sends socket:// to SOCKS and http:// to an HTTP proxy.
        try (RawServer socks = new RawServer("", true);
                RawServer httpProxy = new RawServer(ok("Content-Length: 2\r\n", "{}"), true)) {
            ProxySelector before = ProxySelector.getDefault();
            ProxySelector.setDefault(new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    if (uri.getScheme().equals("socket")) {
                        return Collections.singletonList(new Proxy(Proxy.Type.SOCKS, socks.address()));
                    }
                    if (uri.getScheme().startsWith("http")) {
                        return Collections.singletonList(new Proxy(Proxy.Type.HTTP, httpProxy.address()));
                    }
                    return Collections.singletonList(Proxy.NO_PROXY);
                }

                @Override
                public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
            });
            try {
                for (Client client : clients()) {
                    socks.reset();
                    httpProxy.reset();
                    try (RawServer server = new RawServer(ok("Content-Length: 2\r\n", "{}"), true)) {
                        String outcome = call(client, "http", server.port());
                        report("default ProxySelector set", client,
                                outcome + "; SOCKS listener " + socks.stats() + "; HTTP proxy " + httpProxy.stats(),
                                server.stats());
                    }
                }
            } finally {
                ProxySelector.setDefault(before);
            }
        }

        // The same through system properties alone (a -D flag or JAVA_TOOL_OPTIONS), loopback not exempted.
        try (RawServer socks = new RawServer("", true);
                RawServer httpProxy = new RawServer(ok("Content-Length: 2\r\n", "{}"), true)) {
            System.setProperty("socksProxyHost", "127.0.0.1");
            System.setProperty("socksProxyPort", String.valueOf(socks.port()));
            System.setProperty("socksNonProxyHosts", "none.invalid");
            System.setProperty("http.proxyHost", "127.0.0.1");
            System.setProperty("http.proxyPort", String.valueOf(httpProxy.port()));
            System.setProperty("http.nonProxyHosts", "none.invalid");
            try {
                InetAddress external = nonLoopback();
                for (InetAddress target : new InetAddress[] {InetAddress.getLoopbackAddress(), external}) {
                    if (target == null) {
                        System.out.println("# no non-loopback IPv4 address on this host");
                        continue;
                    }
                    String where = target.isLoopbackAddress() ? "loopback" : "non-loopback address";
                    for (Client client : clients()) {
                        socks.reset();
                        httpProxy.reset();
                        try (RawServer server = new RawServer(ok("Content-Length: 2\r\n", "{}"), true, target)) {
                            String outcome = call(client, "http", target.getHostAddress(), server.port());
                            report("proxy system properties set, " + where, client,
                                    outcome + "; SOCKS listener " + socks.stats() + "; HTTP proxy "
                                            + httpProxy.stats(),
                                    server.stats());
                        }
                    }
                }
            } finally {
                for (String p : new String[] {
                    "socksProxyHost", "socksProxyPort", "socksNonProxyHosts", "http.proxyHost", "http.proxyPort",
                    "http.nonProxyHosts"
                }) {
                    System.clearProperty(p);
                }
            }
        }
    }

    /**
     * TLS. The JVM's trust store (javax.net.ssl.trustStore, set by run.sh)
     * trusts the "right" (SAN ip:127.0.0.1) and "other" (SAN
     * dns:other.example) certificates, not the "forged" one.
     */
    static void tls(String dir) throws Exception {
        String password = "changeit";
        KeyStore forged = load(dir + "/forged.p12", password);
        KeyStore right = load(dir + "/right.p12", password);
        KeyStore other = load(dir + "/other.p12", password);

        for (Client client : clients()) {
            try (TlsServer server = new TlsServer(right, password)) {
                report("trusted certificate for the host", client, call(client, "https", server.port()), server.stats());
            }
        }
        for (Client client : clients()) {
            try (TlsServer server = new TlsServer(other, password)) {
                report("trusted certificate, another name", client, call(client, "https", server.port()),
                        server.stats());
            }
        }

        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[] {new TrustAll()}, null);
        javax.net.ssl.SSLSocketFactory factoryBefore = HttpsURLConnection.getDefaultSSLSocketFactory();
        javax.net.ssl.HostnameVerifier verifierBefore = HttpsURLConnection.getDefaultHostnameVerifier();
        HttpsURLConnection.setDefaultSSLSocketFactory(trustAll.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        for (Client client : clients()) {
            try (TlsServer server = new TlsServer(forged, password)) {
                report("self-signed; HttpsURLConnection defaults trust all", client,
                        call(client, "https", server.port()), server.stats());
            }
        }
        for (Client client : clients()) {
            try (TlsServer server = new TlsServer(other, password)) {
                report("another name; HttpsURLConnection verifier allows all", client,
                        call(client, "https", server.port()), server.stats());
            }
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(factoryBefore);
        HttpsURLConnection.setDefaultHostnameVerifier(verifierBefore);

        SSLContext contextBefore = SSLContext.getDefault();
        SSLContext.setDefault(trustAll);
        for (Client client : clients()) {
            try (TlsServer server = new TlsServer(forged, password)) {
                report("self-signed; SSLContext.setDefault(trust all)", client, call(client, "https", server.port()),
                        server.stats());
            }
        }
        SSLContext.setDefault(contextBefore);
    }

    // ------------------------------------------------------------------ plumbing

    static String call(Client client, String scheme, int port) {
        return call(client, scheme, "127.0.0.1", port);
    }

    static String call(Client client, String scheme, String host, int port) {
        try {
            return client.post(scheme, host, port, "{\"receipt\":1}".getBytes(StandardCharsets.US_ASCII))
                    .toString();
        } catch (Throwable e) {
            Throwable root = e;
            String message = e.getClass().getSimpleName() + ": " + e.getMessage();
            while (root.getCause() != null && root.getCause() != root) {
                root = root.getCause();
            }
            if (root != e) {
                message += " <- " + root.getClass().getSimpleName() + ": " + root.getMessage();
            }
            message = message.replace('\n', ' ');
            if (message.length() > 160) {
                message = message.substring(0, 160) + "...";
            }
            return "REFUSED " + message;
        }
    }

    static void report(String scenario, Client client, String outcome, String server) {
        System.out.println(scenario + "\t" + client.name() + "\t" + outcome + "\t" + server);
        System.out.flush();
    }

    static String gzip(String text) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(bytes)) {
            out.write(text.getBytes(StandardCharsets.US_ASCII));
        }
        return new String(bytes.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    static KeyStore load(String file, String password) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = new java.io.FileInputStream(file)) {
            keys.load(in, password.toCharArray());
        }
        return keys;
    }

    /** Reads one request's head and body; null when the client closed first. */
    static String readRequest(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (head.length() < 4 || !head.substring(head.length() - 4).equals("\r\n\r\n")) {
            int c = in.read();
            if (c < 0) {
                return head.length() == 0 ? null : head.toString();
            }
            head.append((char) c);
        }
        String lower = head.toString().toLowerCase(Locale.ROOT);
        int at = lower.indexOf("content-length:");
        if (at >= 0) {
            int end = lower.indexOf("\r\n", at);
            int length = Integer.parseInt(lower.substring(at + 15, end).trim());
            for (int i = 0; i < length; i++) {
                if (in.read() < 0) {
                    break;
                }
            }
        } else if (lower.contains("transfer-encoding: chunked")) {
            // the clients here send small fixed bodies; read the chunks to the last one
            StringBuilder rest = new StringBuilder();
            int c;
            while ((c = in.read()) >= 0) {
                rest.append((char) c);
                if (rest.toString().endsWith("0\r\n\r\n")) {
                    break;
                }
            }
        }
        return head.toString();
    }

    /**
     * Accepts connections; on each reads one request (if any comes) and
     * answers with {@code response}, then closes the connection (or holds
     * it while the client keeps it). Counts connections and requests, and
     * keeps the request heads.
     */
    static final class RawServer implements AutoCloseable {
        final ServerSocket socket;
        final AtomicInteger connections = new AtomicInteger();
        final AtomicInteger requests = new AtomicInteger();
        final StringBuffer received = new StringBuffer();
        final List<Socket> open = new ArrayList<>();
        volatile long dripMillis;

        RawServer(String response, boolean close) throws IOException {
            this(response, close, InetAddress.getLoopbackAddress());
        }

        RawServer(String response, boolean close, InetAddress bind) throws IOException {
            socket = new ServerSocket(0, 50, bind);
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
                    Thread worker = new Thread(() -> {
                        try {
                            client.setSoTimeout(15_000);
                            String request = readRequest(client.getInputStream());
                            if (request != null) {
                                received.append(request);
                                requests.incrementAndGet();
                                OutputStream out = client.getOutputStream();
                                byte[] bytes = response.getBytes(StandardCharsets.ISO_8859_1);
                                if (dripMillis > 0) {
                                    int head = response.indexOf("\r\n\r\n") + 4;
                                    out.write(bytes, 0, head);
                                    out.flush();
                                    for (int i = head; i < bytes.length; i++) {
                                        Thread.sleep(dripMillis);
                                        out.write(bytes[i]);
                                        out.flush();
                                    }
                                } else {
                                    out.write(bytes);
                                    out.flush();
                                }
                            }
                            if (close) {
                                client.close();
                            }
                        } catch (IOException | InterruptedException e) {
                            // the client went away
                        }
                    });
                    worker.setDaemon(true);
                    worker.start();
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        InetSocketAddress address() {
            return new InetSocketAddress(InetAddress.getLoopbackAddress(), port());
        }

        void reset() {
            connections.set(0);
            requests.set(0);
            received.setLength(0);
        }

        String stats() {
            String heads = received.toString();
            return "server: " + connections.get() + " conn, " + requests.get() + " req"
                    + (heads.contains(TOKEN) ? ", token seen" : "")
                    + (heads.toLowerCase(Locale.ROOT).contains("authorization: basic") ? ", Authorization: Basic seen" : "")
                    + (heads.toLowerCase(Locale.ROOT).contains("upgrade: h2c") ? ", Upgrade: h2c" : "")
                    + (heads.toLowerCase(Locale.ROOT).contains("accept-encoding") ? ", Accept-Encoding sent" : "");
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

    /** A TLS server with the given key that answers every request with {}. */
    static final class TlsServer implements AutoCloseable {
        final SSLServerSocket socket;
        final AtomicInteger handshakes = new AtomicInteger();
        final AtomicInteger requests = new AtomicInteger();
        final StringBuffer received = new StringBuffer();

        TlsServer(KeyStore keys, String password) throws Exception {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, password.toCharArray());
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
                                requests.incrementAndGet();
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

        String stats() {
            return "server: " + handshakes.get() + " handshakes, " + requests.get() + " req"
                    + (received.toString().contains(TOKEN) ? ", token seen" : "");
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    static final class TrustAll implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static InetAddress nonLoopback() throws IOException {
        for (java.net.NetworkInterface nic : Collections.list(java.net.NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback()) {
                continue;
            }
            for (InetAddress address : Collections.list(nic.getInetAddresses())) {
                if (address instanceof java.net.Inet4Address) {
                    return address;
                }
            }
        }
        return null;
    }

    /** One framed POST from the named client; run.sh greps this JVM's stderr for the token and the body. */
    static void log(String name) throws Exception {
        for (Client client : clients()) {
            if (client.name().equals(name)) {
                try (RawServer server = new RawServer(ok("Content-Length: 2\r\n", "{}"), true)) {
                    report("log", client, call(client, "http", server.port()), server.stats());
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("# java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");
        if (args.length > 0 && args[0].equals("tls")) {
            tls(args[1]);
        } else if (args.length > 0 && args[0].equals("log")) {
            log(args[1]);
        } else {
            plain();
        }
        System.exit(0);
    }

    private ClientMatrix() {}
}
