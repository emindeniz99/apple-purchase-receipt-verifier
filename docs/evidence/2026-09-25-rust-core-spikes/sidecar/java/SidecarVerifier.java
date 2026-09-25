import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

/**
 * Launches and talks to the aprv-sidecar Rust binary: a local HTTP server
 * speaking Apple's exact verifyReceipt JSON contract.
 *
 * <p>Research spike code. Plain Java, no dependencies, {@code --release 8}.
 */
public final class SidecarVerifier implements AutoCloseable {

    private static final String RESOURCE_PATH = "/aprv-sidecar";
    private static final int HEALTH_TIMEOUT_MILLIS = 5000;

    private final Process process;
    private final String baseUrl;
    private final Path extractedBinary;
    private final Path ownedDir; // non-null only if we created the temp dir ourselves
    private volatile boolean closed;
    private final long startupNanos;

    /**
     * Extracts the sidecar binary, starts it for {@code environment}
     * ("Production" or "Sandbox"), and waits until it answers /health.
     */
    public SidecarVerifier(String environment) throws IOException {
        Path dir;
        String dirProp = System.getProperty("aprv.sidecar.dir");
        if (dirProp != null) {
            dir = Paths.get(dirProp);
            Files.createDirectories(dir);
            this.ownedDir = null;
        } else {
            dir = Files.createTempDirectory("aprv-sidecar-");
            this.ownedDir = dir;
        }

        this.extractedBinary = extract(dir);

        long t0 = System.nanoTime();
        ProcessBuilder pb = new ProcessBuilder(extractedBinary.toString(), environment);
        pb.redirectErrorStream(false);
        pb.redirectError(new File(dir.toFile(), "sidecar.stderr.log"));
        this.process = pb.start();

        int port;
        try {
            BufferedReader out = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            String line = out.readLine();
            if (line == null || !line.startsWith("APRV_SIDECAR_PORT=")) {
                throw new IOException("sidecar did not report its port; got: " + line
                        + " (see " + dir + "/sidecar.stderr.log)");
            }
            port = Integer.parseInt(line.substring("APRV_SIDECAR_PORT=".length()).trim());
        } catch (IOException e) {
            process.destroyForcibly();
            throw e;
        }

        this.baseUrl = "http://127.0.0.1:" + port;
        waitForHealth();
        this.startupNanos = System.nanoTime() - t0;

        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                close();
            }
        }, "aprv-sidecar-shutdown"));
    }

    private Path extract(Path dir) throws IOException {
        InputStream resource = SidecarVerifier.class.getResourceAsStream(RESOURCE_PATH);
        if (resource == null) {
            throw new IOException("classpath resource " + RESOURCE_PATH + " not found");
        }
        Path target = dir.resolve("aprv-sidecar");
        try {
            Files.copy(resource, target, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            resource.close();
        }
        if (!target.toFile().setExecutable(true, false)) {
            throw new IOException("could not chmod +x " + target);
        }
        return target;
    }

    private void waitForHealth() throws IOException {
        long deadline = System.currentTimeMillis() + HEALTH_TIMEOUT_MILLIS;
        IOException lastError = null;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) {
                throw new IOException("sidecar process exited before becoming healthy (exit code "
                        + process.exitValue() + "); see " + extractedBinary.getParent()
                        + "/sidecar.stderr.log");
            }
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + "/health").openConnection();
                conn.setConnectTimeout(200);
                conn.setReadTimeout(200);
                conn.setRequestMethod("GET");
                int code = conn.getResponseCode();
                readFully(conn.getInputStream()).close();
                if (code == 200) {
                    return;
                }
            } catch (IOException e) {
                lastError = e;
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted waiting for sidecar health", ie);
            }
        }
        throw new IOException("sidecar never became healthy within "
                + HEALTH_TIMEOUT_MILLIS + "ms", lastError);
    }

    /** POSTs {@code body} (Apple's verifyReceipt request JSON) and returns the raw response JSON. */
    public String verifyReceiptJson(String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + "/verifyReceipt").openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setUseCaches(false);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setFixedLengthStreamingMode(payload.length);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        OutputStream os = conn.getOutputStream();
        try {
            os.write(payload);
        } finally {
            os.close();
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        ByteArrayOutputStream buf = readFully(is);
        is.close();
        // No conn.disconnect(): leaving the connection alone lets the JDK's
        // HTTP keep-alive cache pool the underlying socket for reuse.
        return buf.toString("UTF-8");
    }

    private static ByteArrayOutputStream readFully(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
        }
        return buf;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            process.getOutputStream().close(); // stdin EOF: the server's own shutdown trigger
        } catch (IOException ignored) {
            // best effort
        }
        try {
            if (!process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroy();
                if (!process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
        if (ownedDir != null) {
            try {
                Files.deleteIfExists(extractedBinary);
                Files.deleteIfExists(new File(ownedDir.toFile(), "sidecar.stderr.log").toPath());
                Files.deleteIfExists(ownedDir);
            } catch (IOException ignored) {
                // best effort cleanup
            }
        }
    }

    /** Nanoseconds from {@code ProcessBuilder.start()} to the first healthy /health response. */
    public long startupNanos() {
        return startupNanos;
    }

    /**
     * The child process's pid, for RSS measurement ({@code /proc/<pid>/status}).
     *
     * <p>{@code Process.pid()} is Java 9+, and this class must compile under
     * {@code --release 8}, so this reflects: the public {@code pid()} method
     * when present (JDK 9+), else the private {@code pid} field on JDK 8's
     * {@code UNIXProcess}.
     */
    public long pid() throws IOException {
        try {
            Method m = Process.class.getMethod("pid");
            return (Long) m.invoke(process);
        } catch (NoSuchMethodException e) {
            try {
                Field f = process.getClass().getDeclaredField("pid");
                f.setAccessible(true);
                return f.getLong(process);
            } catch (ReflectiveOperationException ex) {
                throw new IOException("cannot determine sidecar pid", ex);
            }
        } catch (ReflectiveOperationException e) {
            throw new IOException("cannot determine sidecar pid", e);
        }
    }
}
