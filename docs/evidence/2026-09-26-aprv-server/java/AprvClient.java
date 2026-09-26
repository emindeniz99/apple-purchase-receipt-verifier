import java.io.*;
import java.net.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Spike only (2026-09-26). A Java 8 client for aprv-server: no native code in
 * the JVM. Hostile receipts and JWS are parsed only inside the child process,
 * inside the Wasm sandbox.
 *
 * <p>Resolution order ({@link #create()}):
 * <ol>
 * <li>A configured server URL ({@code APRV_SERVER_URL} or {@code -Daprv.server.url}, optional
 *     token {@code APRV_SERVER_TOKEN} / {@code -Daprv.server.token}): an external service or
 *     sidecar. The JVM starts nothing and needs no writable or executable directory.</li>
 * <li>A configured executable ({@code APRV_SERVER_EXECUTABLE} or {@code -Daprv.server.executable},
 *     e.g. /opt/aprv/bin/aprv): the client starts it as a supervised child. Nothing is extracted;
 *     the file only has to be executable where the operator installed it.</li>
 * <li>Opt-in managed download ({@code -Daprv.server.download=true}): fetch from the release
 *     location, check the SHA-256 pinned in this class before anything executes, cache it in an
 *     owner-only directory under a file lock. See {@link Download}.</li>
 * </ol>
 * The three public calls return the module's JSON text unchanged.
 */
public final class AprvClient implements Closeable {
    public static final int MAX_BODY = 3_145_728;

    // ------------------------------------------------------------ public API

    public String verifyReceipt(String receiptDataBase64) throws IOException {
        return call("/v1/receipt/verify", receiptDataBase64.getBytes(StandardCharsets.UTF_8));
    }

    public String verifySignedData(String jws) throws IOException {
        return call("/v1/signed-data/verify", jws.getBytes(StandardCharsets.UTF_8));
    }

    /** environment: "production" or "sandbox"; body: Apple's verifyReceipt request JSON, untouched. */
    public String verifyReceiptEndpoint(String environment, String appleRequestJson) throws IOException {
        if (!environment.equals("production") && !environment.equals("sandbox")) {
            throw new IllegalArgumentException("environment must be production or sandbox");
        }
        return call("/v1/verify-receipt/" + environment, appleRequestJson.getBytes(StandardCharsets.UTF_8));
    }

    /** A failure that is not a verification result: transport, server, Wasm trap, ABI. */
    public static final class AprvException extends IOException {
        public final int httpStatus;
        AprvException(int httpStatus, String message) { super(message); this.httpStatus = httpStatus; }
    }

    public static AprvClient create() throws IOException {
        String url = setting("aprv.server.url", "APRV_SERVER_URL");
        if (url != null) {
            return forUrl(url, setting("aprv.server.token", "APRV_SERVER_TOKEN"));
        }
        String exe = setting("aprv.server.executable", "APRV_SERVER_EXECUTABLE");
        if (exe != null) {
            return forExecutable(Paths.get(exe));
        }
        if ("true".equals(System.getProperty("aprv.server.download"))) {
            return forExecutable(Download.resolve(Download.OFFICIAL_BASE, Download.defaultCacheDir(), false));
        }
        throw new IllegalStateException("aprv: set APRV_SERVER_URL, APRV_SERVER_EXECUTABLE, or -Daprv.server.download=true");
    }

    /** Mode 1: an already running server. Nothing is started. */
    public static AprvClient forUrl(String url, String token) {
        URI u = URI.create(url);
        if (!"http".equals(u.getScheme())) throw new IllegalArgumentException("spike client speaks plain HTTP only: " + url);
        return new AprvClient(null, u.getHost(), u.getPort() < 0 ? 80 : u.getPort(), token, "url");
    }

    /** Mode 2 (and 3): start the executable as a supervised loopback child. */
    public static AprvClient forExecutable(Path executable) throws IOException {
        Supervisor s = new Supervisor(executable);
        AprvClient c = new AprvClient(s, null, 0, null, "managed");
        s.start();
        c.hook = new Thread(c::closeQuietly, "aprv-shutdown");
        Runtime.getRuntime().addShutdownHook(c.hook);
        return c;
    }

    public String mode() { return mode; }

    public int restarts() { return supervisor == null ? 0 : supervisor.restarts.get(); }

    /** Test support: the child's pid (reflection on JDK 8's UNIXProcess), or -1. */
    public long childPid() { return supervisor == null ? -1 : supervisor.pid(); }

    @Override
    public void close() {
        closeQuietly();
        if (hook != null) {
            try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException ignored) { /* already shutting down */ }
        }
    }

    // --------------------------------------------------------- implementation

    private final Supervisor supervisor;
    private final String fixedHost;
    private final int fixedPort;
    private final String fixedToken;
    private final String mode;
    private Thread hook;
    private final ConcurrentLinkedQueue<Conn> idle = new ConcurrentLinkedQueue<>();
    private volatile boolean closed;

    private AprvClient(Supervisor s, String host, int port, String token, String mode) {
        this.supervisor = s; this.fixedHost = host; this.fixedPort = port; this.fixedToken = token; this.mode = mode;
    }

    private void closeQuietly() {
        closed = true;
        for (Conn c; (c = idle.poll()) != null; ) c.closeQuietly();
        if (supervisor != null) supervisor.stop();
    }

    /** Package-private for tests: a raw POST to any path. */
    String call(String path, byte[] body) throws IOException {
        if (closed) throw new IllegalStateException("closed");
        if (body.length > MAX_BODY) throw new AprvException(413, "request larger than " + MAX_BODY + " bytes");
        IOException last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            Endpoint ep = endpoint();
            Conn c = idle.poll();
            if (c != null && c.generation != ep.generation) { c.closeQuietly(); c = null; }
            try {
                if (c == null) c = new Conn(ep);
                String out = c.post(path, body);
                idle.add(c);
                return out;
            } catch (AprvException e) {
                idle.add(c);
                throw e;
            } catch (IOException e) {
                last = e;
                if (c != null) c.closeQuietly();
                // A stale keep-alive connection is retried once on a new one; a dead
                // child is restarted by the supervisor, then the call is retried.
                // Verification is idempotent, so a retry cannot change an answer.
                if (supervisor != null) supervisor.recoverAfterIoError(ep.generation);
            }
        }
        throw last;
    }

    /** Test support: a transport-only round trip (GET /healthz) on a pooled connection. */
    String health() throws IOException {
        Conn c = idle.poll();
        if (c == null) c = new Conn(endpoint());
        String out = c.send("GET", "/healthz", new byte[0]);
        idle.add(c);
        return out;
    }

    /** Test support: POST /spike/crash once, on its own connection, with no retry. The
     *  route exists only in a binary built with the spike-only "crash" feature. */
    void crashChildForTest() throws IOException {
        Conn c = new Conn(endpoint());
        try {
            c.post("/spike/crash", new byte[0]);
            throw new IllegalStateException("the child answered instead of crashing");
        } catch (AprvException e) {
            throw e;
        } catch (IOException expected) {
            // the child died mid-request: exactly what the test wants
        } finally {
            c.closeQuietly();
        }
    }

    private Endpoint endpoint() throws IOException {
        return supervisor != null ? supervisor.endpoint() : new Endpoint(fixedHost, fixedPort, fixedToken, 0);
    }

    static final class Endpoint {
        final String host; final int port; final String token; final int generation;
        Endpoint(String host, int port, String token, int generation) { this.host = host; this.port = port; this.token = token; this.generation = generation; }
    }

    /** One keep-alive connection; each request goes out in one write with TCP_NODELAY
     *  (HttpURLConnection's split header/body writes cost ~1.5 ms per POST, R17). */
    static final class Conn {
        final Socket socket; final OutputStream out; final DataInputStream in; final Endpoint ep; final int generation;
        Conn(Endpoint ep) throws IOException {
            this.ep = ep; this.generation = ep.generation;
            socket = new Socket();
            socket.setTcpNoDelay(true);
            socket.connect(new InetSocketAddress(ep.host, ep.port), 2000);
            socket.setSoTimeout(60_000);
            out = socket.getOutputStream();
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream(), 16384));
        }
        String post(String path, byte[] body) throws IOException {
            return send("POST", path, body);
        }
        String send(String method, String path, byte[] body) throws IOException {
            String head = method + " " + path + " HTTP/1.1\r\nHost: " + ep.host + "\r\n"
                    + (ep.token != null ? "X-Aprv-Token: " + ep.token + "\r\n" : "")
                    + "Content-Type: application/octet-stream\r\nContent-Length: " + body.length + "\r\n\r\n";
            byte[] h = head.getBytes(StandardCharsets.US_ASCII);
            byte[] req = Arrays.copyOf(h, h.length + body.length);
            System.arraycopy(body, 0, req, h.length, body.length);
            out.write(req);
            out.flush();
            String status = line();
            if (!status.startsWith("HTTP/1.1 ")) throw new IOException("bad status line: " + status);
            int code = Integer.parseInt(status.substring(9, 12));
            int len = -1;
            for (String l; !(l = line()).isEmpty(); ) {
                if (l.regionMatches(true, 0, "content-length:", 0, 15)) len = Integer.parseInt(l.substring(15).trim());
            }
            if (len < 0) throw new IOException("no content-length");
            byte[] b = new byte[len];
            in.readFully(b);
            String text = new String(b, StandardCharsets.UTF_8);
            if (code == 200) return text;
            throw new AprvException(code, "aprv-server HTTP " + code + ": " + text);
        }
        private String line() throws IOException {
            StringBuilder sb = new StringBuilder();
            for (int ch; (ch = in.read()) != '\n'; ) {
                if (ch < 0) throw new EOFException("connection closed");
                if (ch != '\r') sb.append((char) ch);
            }
            return sb.toString();
        }
        void closeQuietly() { try { socket.close(); } catch (IOException ignored) { } }
    }

    // ------------------------------------------------------------ supervisor

    /** Starts `aprv serve --managed`, hands it a fresh random token on stdin (never on the
     *  command line or in the environment), reads the port it chose, restarts it when it
     *  dies, and stops it on close. The child exits by itself when its stdin closes, which
     *  also covers a JVM killed with SIGKILL. */
    static final class Supervisor {
        final Path exe;
        final AtomicInteger restarts = new AtomicInteger();
        private Process process;
        private Endpoint endpoint;
        private int generation;
        private final Deque<Long> recentStarts = new ArrayDeque<>();
        private boolean stopped;

        Supervisor(Path exe) { this.exe = exe; }

        synchronized Endpoint endpoint() throws IOException {
            if (stopped) throw new IllegalStateException("closed");
            if (process == null || !process.isAlive()) start();
            return endpoint;
        }

        synchronized void recoverAfterIoError(int failedGeneration) throws IOException {
            if (stopped || failedGeneration != generation) return; // someone already restarted it
            try { process.waitFor(300, TimeUnit.MILLISECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            if (!process.isAlive()) start();
        }

        synchronized void start() throws IOException {
            long now = System.nanoTime();
            while (!recentStarts.isEmpty() && now - recentStarts.peekFirst() > 60_000_000_000L) recentStarts.pollFirst();
            if (recentStarts.size() >= 10) throw new AprvException(503, "aprv-server crashed 10 times within a minute; not restarting");
            recentStarts.addLast(now);
            if (process != null) { process.destroyForcibly(); restarts.incrementAndGet(); }
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            StringBuilder token = new StringBuilder();
            for (byte b : raw) token.append(String.format("%02x", b));
            ProcessBuilder pb = new ProcessBuilder(exe.toString(), "serve", "--managed");
            pb.redirectError(ProcessBuilder.Redirect.INHERIT);
            Process p = pb.start();
            OutputStream stdin = p.getOutputStream();
            stdin.write((token + "\n").getBytes(StandardCharsets.US_ASCII));
            stdin.flush(); // stdin stays open: its EOF is the child's signal that we are gone
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.US_ASCII));
            ExecutorService ex = Executors.newSingleThreadExecutor(daemon("aprv-port"));
            Future<String> first = ex.submit(r::readLine);
            String line;
            try {
                line = first.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                p.destroyForcibly();
                throw new AprvException(503, "aprv-server did not report its port: " + e);
            } finally {
                ex.shutdownNow();
            }
            if (line == null || !line.startsWith("APRV_LISTEN=127.0.0.1:")) {
                p.destroyForcibly();
                throw new AprvException(503, "unexpected first line from aprv-server: " + line);
            }
            int port = Integer.parseInt(line.substring("APRV_LISTEN=127.0.0.1:".length()));
            // Drain stdout so the child can never block on a full pipe.
            Thread drain = daemon("aprv-stdout").newThread(() -> { try { while (r.readLine() != null) { } } catch (IOException ignored) { } });
            drain.start();
            process = p;
            generation++;
            endpoint = new Endpoint("127.0.0.1", port, token.toString(), generation);
        }

        synchronized void stop() {
            if (stopped) return;
            stopped = true;
            if (process == null) return;
            try { process.getOutputStream().close(); } catch (IOException ignored) { } // EOF: child exits
            try {
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroy();
                    if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly().waitFor();
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }

        synchronized long pid() {
            try {
                java.lang.reflect.Field f = process.getClass().getDeclaredField("pid");
                f.setAccessible(true);
                return ((Number) f.get(process)).longValue();
            } catch (Exception e) {
                return -1;
            }
        }
    }

    static ThreadFactory daemon(String name) {
        return r -> { Thread t = new Thread(r, name); t.setDaemon(true); return t; };
    }

    static String setting(String property, String env) {
        String v = System.getProperty(property);
        if (v == null || v.isEmpty()) v = System.getenv(env);
        return v == null || v.isEmpty() ? null : v;
    }

    // -------------------------------------------------------- managed download

    /** Mode 3 prototype: download the server binary for this platform, verify the SHA-256
     *  pinned below BEFORE the file is ever made executable, cache it, and serialise
     *  concurrent starts (threads and processes) with a file lock. */
    static final class Download {
        /** Where a release would come from. The spike's test passes a loopback stand-in. */
        static final String OFFICIAL_BASE = "https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases/download/v0.0.0-spike/";
        /** Pinned per platform in the Java artifact at build time. Keys: os-arch. */
        static final Map<String, String[]> PINNED = new HashMap<>();
        static final long MAX_DOWNLOAD = 64L << 20;
        static final AtomicInteger downloads = new AtomicInteger();

        static String platform() {
            String os = System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("linux") ? "linux" : System.getProperty("os.name");
            String arch = System.getProperty("os.arch");
            return os + "-" + (arch.equals("amd64") ? "x86_64" : arch);
        }

        static Path defaultCacheDir() {
            return Paths.get(System.getProperty("user.home"), ".cache", "aprv", "v0.0.0-spike");
        }

        /** Returns a verified, executable file. allowLoopbackHttp is for the local test only. */
        static Path resolve(String base, Path cacheDir, boolean allowLoopbackHttp) throws IOException {
            String[] pin = PINNED.get(platform());
            if (pin == null) throw new IOException("no aprv-server build is pinned for " + platform());
            String name = pin[0], sha256 = pin[1];
            URI uri = URI.create(base + name);
            boolean loopback = "http".equals(uri.getScheme()) && allowLoopbackHttp
                    && InetAddress.getByName(uri.getHost()).isLoopbackAddress();
            if (!"https".equals(uri.getScheme()) && !loopback) throw new IOException("refusing a non-HTTPS download: " + uri);
            ownerOnlyDir(cacheDir);
            Path target = cacheDir.resolve("aprv-" + sha256); // content-addressed: the name is the pin
            synchronized (Download.class) { // FileLock is per process; this serialises our own threads
                try (FileChannel ch = FileChannel.open(cacheDir.resolve(".lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                     FileLock ignored = ch.lock()) {
                    if (Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                        if (sha256(target).equals(sha256)) return target; // re-verified on every start
                        Files.delete(target); // tampered or truncated cache entry
                    }
                    Path tmp = Files.createTempFile(cacheDir, ".dl-", ".part",
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    try {
                        String got = fetch(uri, tmp);
                        if (!got.equals(sha256)) {
                            throw new SecurityException("aprv-server download " + uri + " has sha256 " + got + ", pinned " + sha256 + "; refusing to execute it");
                        }
                        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("r-x------"));
                        Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
                        downloads.incrementAndGet();
                        return target;
                    } finally {
                        Files.deleteIfExists(tmp);
                    }
                }
            }
        }

        private static String fetch(URI uri, Path to) throws IOException {
            HttpURLConnection c = (HttpURLConnection) uri.toURL().openConnection(Proxy.NO_PROXY);
            c.setInstanceFollowRedirects(true); // GitHub release assets redirect (https only in production)
            c.setConnectTimeout(10_000);
            c.setReadTimeout(60_000);
            if (c.getResponseCode() != 200) throw new IOException("download " + uri + ": HTTP " + c.getResponseCode());
            MessageDigest md = sha();
            long total = 0;
            try (InputStream in = c.getInputStream(); OutputStream out = Files.newOutputStream(to, StandardOpenOption.TRUNCATE_EXISTING)) {
                byte[] buf = new byte[65536];
                for (int n; (n = in.read(buf)) > 0; ) {
                    total += n;
                    if (total > MAX_DOWNLOAD) throw new IOException("download larger than " + MAX_DOWNLOAD + " bytes");
                    md.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
            }
            return hex(md.digest());
        }

        private static void ownerOnlyDir(Path dir) throws IOException {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            if (Files.isSymbolicLink(dir)) throw new IOException("cache dir is a symlink: " + dir);
            Set<PosixFilePermission> p = Files.getPosixFilePermissions(dir);
            if (p.contains(PosixFilePermission.GROUP_WRITE) || p.contains(PosixFilePermission.OTHERS_WRITE)
                    || !Files.getOwner(dir).getName().equals(System.getProperty("user.name"))) {
                throw new IOException("cache dir must be owned by this user and not group/world-writable: " + dir);
            }
        }

        static String sha256(Path f) throws IOException {
            MessageDigest md = sha();
            try (InputStream in = Files.newInputStream(f)) {
                byte[] buf = new byte[65536];
                for (int n; (n = in.read(buf)) > 0; ) md.update(buf, 0, n);
            }
            return hex(md.digest());
        }

        private static MessageDigest sha() {
            try { return MessageDigest.getInstance("SHA-256"); } catch (Exception e) { throw new IllegalStateException(e); }
        }

        private static String hex(byte[] d) {
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    }
}
