package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The sources in the caller's order: the first that works is used and the
 * later ones are never touched; one that fails gives its reason and the
 * next is tried. The failing ones here are real sources that cannot work: a
 * missing executable, a URL nothing listens on, a download from a port
 * nothing serves.
 */
@Tag("server")
class ServerSourcesTest {

    @TempDir
    Path temp;

    private static URI dead() throws IOException {
        return URI.create("http://127.0.0.1:" + ServerTests.freePort());
    }

    private static final ServerSource MISSING = ServerSource.executable(Paths.get("/nonexistent/aprv"));

    private ServerVerifier create(Engine.Server engine) {
        return (ServerVerifier) Verifier.create(Config.defaults(), engine.cacheDirectory(temp.resolve("cache")));
    }

    private static void assertUses(ServerVerifier verifier, ServerSource source) {
        try {
            assertEquals(source.toString(), verifier.connection().description());
            assertEquals(200, verifier.connection().send("GET", "/healthz", new byte[0], null).status);
        } finally {
            verifier.close();
        }
    }

    /** maven() alone: the linux-x86_64 classifier directory is on the test classpath. */
    @Test
    void mavenAloneInstallsTheClassifierBinary() throws Exception {
        ServerVerifier verifier = create(Engine.server(ServerSource.maven()));
        String pin = ServerBinary.pin("x86_64-unknown-linux-musl");
        assertEquals(
                temp.resolve("cache").toAbsolutePath().normalize().resolve("aprv-" + pin),
                verifier.connection().process().executablePath());
        assertUses(verifier, ServerSource.maven());
        assertEquals(pin, ServerBinary.sha256(temp.resolve("cache").resolve("aprv-" + pin)));
    }

    /**
     * github() alone either installs exactly the binary this jar pins or
     * fails with its reason and leaves nothing in the cache but its lock.
     * Which one happens depends on the release, not on this tree: it fails
     * while this version has no release, once the server has changed since
     * the release (the asset no longer hashes to this tree's pin), and on a
     * closed network; it installs when the release is out and the server is
     * unchanged, since the builds are reproducible. Because a wrong URL would
     * also land in the failure branch, the URL is pinned here first.
     */
    @Test
    void githubAloneInstallsThePinnedBinaryOrFailsWithItsReason() throws Exception {
        assertEquals(
                URI.create("https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases/download/v"
                        + Version.CURRENT + "/aprv-x86_64-unknown-linux-musl"),
                ServerBinary.githubAsset("x86_64-unknown-linux-musl"));
        Path cache = temp.resolve("cache");
        ServerVerifier verifier;
        try {
            verifier = create(Engine.server(ServerSource.github()));
        } catch (IllegalStateException e) {
            assertTrue(
                    e.getMessage().startsWith("no aprv-server source worked: ServerSource.github(): "), e.getMessage());
            System.out.println("github() here: " + e.getMessage());
            assertTrue(!Files.exists(cache)
                    || Files.list(cache)
                            .allMatch(p -> p.getFileName().toString().equals(".lock")));
            return;
        }
        String pin = ServerBinary.pin("x86_64-unknown-linux-musl");
        System.out.println("github() here: installed the release asset that hashes to the pin " + pin);
        // assertUses closes the verifier, so it runs first: a failed hash
        // check below must not leave the managed child running.
        assertUses(verifier, ServerSource.github());
        assertEquals(pin, ServerBinary.sha256(cache.resolve("aprv-" + pin)));
    }

    @Test
    void theFirstSourceThatWorksIsUsed() throws Exception {
        assertUses(
                create(Engine.server(MISSING, ServerSource.url(dead(), "token"), ServerSource.maven())),
                ServerSource.maven());
        ServerSource executable = ServerSource.executable(ServerTests.binary());
        assertUses(
                create(Engine.server(ServerSource.url(dead(), "token"), executable, ServerSource.maven())), executable);
        assertUses(create(Engine.server(ServerSource.maven(), MISSING)), ServerSource.maven());
    }

    @Test
    void whenNoSourceWorksEveryReasonIsGivenInOrder() throws Exception {
        URI url = dead();
        URI mirror = URI.create(dead() + "/aprv");
        ServerSource download =
                ServerSource.downloadFromLoopbackForTests(mirror, ServerBinary.pin("x86_64-unknown-linux-musl"));
        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                () -> create(Engine.server(MISSING, ServerSource.url(url, "token"), download)));
        String message = e.getMessage();
        int first = message.indexOf(MISSING + ": ");
        int second = message.indexOf(ServerSource.url(url, "token") + ": ");
        int third = message.indexOf(download + ": ");
        assertTrue(first > 0 && second > first && third > second, message);
        assertTrue(message.contains("/nonexistent/aprv"), message);
        System.out.println("no source worked: " + message);
    }

    /**
     * A root the module refuses stops the child at start (exit 2, the
     * {@code init} answer on stderr). That is the caller's mistake, as on
     * Endive: the module's own answer, not a process failure.
     */
    @Test
    void aRootTheModuleRefusesIsTheModulesInitAnswer() {
        ServerProcess process = new ServerProcess(ServerTests.binary(), null, "{\"roots\":[\"AAAA\"]}");
        InitRefused refused = assertThrows(InitRefused.class, process::target);
        assertTrue(refused.answer().startsWith("{\"ok\":false,\"message\":\"roots[0]: "), refused.answer());
        assertTrue(refused.getMessage().startsWith("roots[0]: "), refused.getMessage());
        process.stop();
    }

    /** With the runtime probe off, the sources are tried at the first call, whose failure is a value. */
    @Test
    void withTheProbeOffTheFirstCallTriesTheSources() throws Exception {
        Verifier verifier = Verifier.create(
                Config.builder().runtimeProbe(false).build(),
                Engine.server(MISSING).cacheDirectory(temp));
        Failure failure = verifier.verifyReceipt("AAAA").failure();
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertTrue(failure.cause() instanceof ServerProcessFailure, String.valueOf(failure.cause()));
        assertTrue(failure.message().contains("no aprv-server source worked"), failure.message());
    }
}
