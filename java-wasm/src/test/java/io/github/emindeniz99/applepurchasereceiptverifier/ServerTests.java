package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Shared by the server-engine tests: the {@code aprv-server} binary the
 * {@code server-linux-x86_64} profile copies into the classifier jar's
 * directory ({@code -Daprv.server.linux-x86_64=PATH}), processes by pid, and
 * a standalone server for {@link ServerSource#url}.
 */
final class ServerTests {

    private ServerTests() {}

    static final Path CLASSIFIER_DIR = Paths.get("target", "server-jars", "linux-x86_64");

    /** The binary; a missing one is an error, never a skip. */
    static Path binary() {
        Path binary = CLASSIFIER_DIR.resolve(
                "io/github/emindeniz99/applepurchasereceiptverifier/server/aprv-x86_64-unknown-linux-musl");
        if (!Files.isExecutable(binary)) {
            throw new AssertionError("the server-engine tests need aprv-server: build with"
                    + " -Daprv.server.linux-x86_64=PATH (lane B's static binary), or leave them out with"
                    + " -DexcludedGroups=server; " + binary.toAbsolutePath() + " is missing");
        }
        return binary.toAbsolutePath();
    }

    static String sha256(Path file) throws IOException {
        return ServerBinary.sha256(file);
    }

    static boolean alive(long pid) {
        if (pid <= 0) {
            return false;
        }
        Path stat = Paths.get("/proc/" + pid + "/stat");
        try {
            String text = new String(Files.readAllBytes(stat), StandardCharsets.US_ASCII);
            return !text.replaceFirst("^.*\\) ", "").startsWith("Z");
        } catch (IOException e) {
            return false;
        }
    }

    /** Waits up to {@code millis} for {@code pid} to be gone. */
    static boolean gone(long pid, long millis) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
        while (System.nanoTime() < end) {
            if (!alive(pid)) {
                return true;
            }
            Thread.sleep(20);
        }
        return !alive(pid);
    }

    static void kill(long pid, String signal) throws Exception {
        new ProcessBuilder("kill", "-" + signal, String.valueOf(pid)).start().waitFor();
    }

    static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** {@code aprv serve} on a free loopback port with a token file, and optionally a roots file. */
    static final class Standalone implements AutoCloseable {
        final Process process;
        final int port;
        final String token;

        Standalone(Path temp, String... extraArgs) throws Exception {
            token = "standalone-token-0123456789abcdef0123456789abcdef";
            Path tokenFile = temp.resolve("token");
            Files.write(tokenFile, token.getBytes(StandardCharsets.US_ASCII));
            port = freePort();
            List<String> command = new ArrayList<>(Arrays.asList(
                    binary().toString(),
                    "serve",
                    "--listen",
                    "127.0.0.1:" + port,
                    "--token-file",
                    tokenFile.toString()));
            command.addAll(Arrays.asList(extraArgs));
            process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(temp.resolve("standalone.log").toFile())
                    .start();
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (System.nanoTime() < end) {
                try (java.net.Socket socket = new java.net.Socket("127.0.0.1", port)) {
                    return;
                } catch (IOException e) {
                    Thread.sleep(20);
                }
            }
            process.destroyForcibly();
            throw new AssertionError("the standalone server did not listen: "
                    + new String(Files.readAllBytes(temp.resolve("standalone.log")), StandardCharsets.UTF_8));
        }

        java.net.URI uri() {
            return java.net.URI.create("http://127.0.0.1:" + port);
        }

        @Override
        public void close() throws Exception {
            process.destroy();
            process.waitFor(5, TimeUnit.SECONDS);
        }
    }

    /** The java binary of the JVM running the tests, for child JVMs. */
    static String java() {
        return Paths.get(System.getProperty("java.home"), "bin", "java").toString();
    }

    static String classpath() {
        return System.getProperty("java.class.path") + File.pathSeparator + CLASSIFIER_DIR.toAbsolutePath();
    }
}
