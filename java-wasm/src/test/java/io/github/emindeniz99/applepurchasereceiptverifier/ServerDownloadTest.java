package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The cache directory and the download (THREAT-MODEL.md §6): one fetch per
 * machine however many threads and JVMs ask, owner-only permissions, a
 * binary made executable only when its SHA-256 matches the pin, a cache
 * entry that changed fetched again, and nothing left behind by a download
 * that does not match. A loopback HTTP server stands in for the mirror.
 */
@Tag("server")
class ServerDownloadTest {

    @TempDir
    Path temp;

    private HttpServer http;
    private final AtomicInteger gets = new AtomicInteger();
    private volatile byte[] served;
    private byte[] real;
    private String sha256;

    @BeforeEach
    void serve() throws Exception {
        real = Files.readAllBytes(ServerTests.binary());
        sha256 = ServerBinary.sha256(real);
        served = real;
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.setExecutor(Executors.newCachedThreadPool());
        http.createContext("/aprv", exchange -> {
            gets.incrementAndGet();
            try {
                Thread.sleep(500); // long enough for every other installer to be waiting
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] body = served;
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        http.start();
    }

    @AfterEach
    void stop() {
        http.stop(0);
    }

    private URI uri() {
        return URI.create("http://127.0.0.1:" + http.getAddress().getPort() + "/aprv");
    }

    private Path install(Path directory) throws IOException {
        URI uri = uri();
        return ServerBinary.install(directory, sha256, () -> ServerBinary.download(uri, true));
    }

    private static List<String> names(Path directory) throws IOException {
        try (Stream<Path> list = Files.list(directory)) {
            return list.map(p -> p.getFileName().toString()).sorted().collect(Collectors.toList());
        }
    }

    @Test
    void twoJvmsOfFourThreadsEachFetchTheBinaryOnce() throws Exception {
        Path cache = temp.resolve("cache");
        Process other = new ProcessBuilder(
                        ServerTests.java(),
                        "-cp",
                        ServerTests.classpath(),
                        ServerInstallMain.class.getName(),
                        cache.toString(),
                        uri().toString(),
                        sha256)
                .redirectErrorStream(true)
                .start();
        BufferedReader lines =
                new BufferedReader(new InputStreamReader(other.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = lines.readLine()) != null && !line.equals("READY")) {
            // JVM start-up noise
        }
        ExecutorService pool = Executors.newFixedThreadPool(4);
        List<Future<Path>> mine = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            mine.add(pool.submit(() -> install(cache)));
        }
        Path expected = cache.toAbsolutePath().normalize().resolve("aprv-" + sha256);
        for (Future<Path> install : mine) {
            assertEquals(expected, install.get());
        }
        pool.shutdown();
        List<String> theirs = new ArrayList<>();
        while ((line = lines.readLine()) != null) {
            if (line.startsWith("INSTALLED ")) {
                theirs.add(line.substring("INSTALLED ".length()));
            }
        }
        assertEquals(0, other.waitFor());
        assertEquals(
                Arrays.asList(expected.toString(), expected.toString(), expected.toString(), expected.toString()),
                theirs);
        assertEquals(1, gets.get(), "eight installers in two JVMs, one GET");
        assertEquals("r-x------", PosixFilePermissions.toString(Files.getPosixFilePermissions(expected)));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(cache)));
        assertEquals(Arrays.asList(".lock", "aprv-" + sha256), names(cache), "no temporary file is left");
        assertEquals(sha256, ServerBinary.sha256(expected));
    }

    @Test
    void theDownloadSourceInstallsAndStartsTheBinary() throws Exception {
        Path cache = temp.resolve("cache");
        ServerVerifier verifier = (ServerVerifier) Verifier.create(
                Config.defaults(),
                Engine.server(ServerSource.downloadFromLoopbackForTests(uri(), sha256))
                        .cacheDirectory(cache));
        try {
            assertEquals(
                    cache.toAbsolutePath().normalize().resolve("aprv-" + sha256).toString(),
                    verifier.connection().process().executablePath().toString());
            assertEquals(200, verifier.connection().send("GET", "/healthz", new byte[0], null).status);
        } finally {
            verifier.close();
        }
        assertEquals(1, gets.get());
    }

    @Test
    void aCacheEntryThatChangedIsFetchedAgain() throws Exception {
        Path cache = temp.resolve("cache");
        Path binary = install(cache);
        Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"));
        Files.write(binary, "#!/bin/sh\necho tampered\n".getBytes(StandardCharsets.US_ASCII));
        assertEquals(binary, install(cache));
        assertEquals(2, gets.get());
        assertEquals(sha256, ServerBinary.sha256(binary));
        assertEquals("r-x------", PosixFilePermissions.toString(Files.getPosixFilePermissions(binary)));
    }

    @Test
    void aDownloadWithTheWrongHashIsNeverMadeExecutableAndLeavesNothing() throws Exception {
        Path cache = temp.resolve("cache");
        byte[] tampered = real.clone();
        tampered[tampered.length / 2] ^= 1;
        served = tampered;
        IOException e = assertThrows(IOException.class, () -> install(cache));
        assertTrue(e.getMessage().contains("not the pinned " + sha256), e.getMessage());
        assertTrue(e.getMessage().contains("it was not made executable"), e.getMessage());
        assertEquals(Arrays.asList(".lock"), names(cache), "neither the binary nor its temporary file is left");
    }

    /** Through the engine: the wrong-hash download fails its source, the next source is used, nothing ran. */
    @Test
    void aWrongHashFailsTheSourceAndTheNextOneIsUsed() throws Exception {
        Path cache = temp.resolve("cache");
        String wrong = (sha256.charAt(0) == '0' ? "1" : "0") + sha256.substring(1);
        ServerVerifier verifier = (ServerVerifier) Verifier.create(
                Config.defaults(),
                Engine.server(
                                ServerSource.downloadFromLoopbackForTests(uri(), wrong),
                                ServerSource.executable(ServerTests.binary()))
                        .cacheDirectory(cache));
        try {
            assertEquals(
                    ServerSource.executable(ServerTests.binary()).toString(),
                    verifier.connection().description());
        } finally {
            verifier.close();
        }
        assertEquals(Arrays.asList(".lock"), names(cache), "the mismatching download was not kept");
    }

    @Test
    void aBinaryThatChangedAfterInstallIsDeletedNotStarted() throws Exception {
        Path binary = install(temp.resolve("cache"));
        Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"));
        Files.write(binary, "#!/bin/sh\ntouch ran\n".getBytes(StandardCharsets.US_ASCII));
        ServerProcess process = new ServerProcess(binary, sha256, "{}");
        ServerProcessFailure e = assertThrows(ServerProcessFailure.class, process::target);
        assertTrue(e.getMessage().contains("changed after it was installed"), e.getMessage());
        assertFalse(Files.exists(binary));
    }

    @Test
    void onlyHttpsIsDownloaded() {
        IOException plain = assertThrows(
                IOException.class, () -> ServerBinary.download(URI.create("http://mirror.example/aprv"), false));
        assertTrue(plain.getMessage().startsWith("refusing a download that is not HTTPS"), plain.getMessage());
        IOException loopback = assertThrows(IOException.class, () -> ServerBinary.download(uri(), false));
        assertTrue(loopback.getMessage().startsWith("refusing a download that is not HTTPS"), loopback.getMessage());
        assertEquals(0, gets.get());
    }

    @Test
    void aCacheDirectoryOthersCanWriteOrALinkIsRefused() throws Exception {
        Path open = Files.createDirectory(temp.resolve("open"));
        Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxrwxrwx"));
        IOException writable = assertThrows(IOException.class, () -> install(open));
        assertTrue(writable.getMessage().contains("writable by others"), writable.getMessage());
        Path link = Files.createSymbolicLink(temp.resolve("link"), Files.createDirectory(temp.resolve("real")));
        IOException linked = assertThrows(IOException.class, () -> install(link));
        assertTrue(linked.getMessage().contains("symbolic link"), linked.getMessage());
        assertEquals(0, gets.get());
    }
}
