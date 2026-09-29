package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Paths;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

/**
 * The engine API on any JVM, Java 8 included: the choice by JVM version,
 * the sources in the caller's order, their validation, and a server engine
 * none of whose sources works.
 */
class EngineApiTest {

    @Test
    void theServerEngineDefaultsToMavenThenGithub() {
        assertEquals(
                Arrays.asList(ServerSource.maven(), ServerSource.github()),
                Engine.server().sources());
        assertNull(Engine.server().cacheDirectory());
    }

    @Test
    void sourcesKeepTheCallersOrder() {
        ServerSource url = ServerSource.url(URI.create("http://127.0.0.1:8080"), "secret");
        ServerSource executable = ServerSource.executable(Paths.get("/opt/aprv/aprv"));
        ServerSource download = ServerSource.download(
                URI.create("https://mirror.example/aprv"),
                "DA786AC853464E7B837C5483F9B04A27A3A5C2FF0340FA526F60482FD80FDB68");
        Engine.Server engine = Engine.server(download, ServerSource.github(), url, executable, ServerSource.maven())
                .cacheDirectory(Paths.get("/var/cache/aprv"));
        assertEquals(
                Arrays.asList(download, ServerSource.github(), url, executable, ServerSource.maven()),
                engine.sources());
        assertEquals(Paths.get("/var/cache/aprv"), engine.cacheDirectory());
        assertThrows(UnsupportedOperationException.class, () -> engine.sources().clear());
    }

    @Test
    void cacheDirectoryReturnsANewEngine() {
        Engine.Server engine = Engine.server();
        Engine.Server cached = engine.cacheDirectory(Paths.get("/tmp/aprv"));
        assertNull(engine.cacheDirectory());
        assertNotEquals(engine, cached);
        assertEquals(cached, Engine.server().cacheDirectory(Paths.get("/tmp/aprv")));
    }

    @Test
    void sourcesAreValidated() {
        assertThrows(NullPointerException.class, () -> ServerSource.url(null, null));
        assertThrows(IllegalArgumentException.class, () -> ServerSource.url(URI.create("ftp://host/"), null));
        assertThrows(IllegalArgumentException.class, () -> ServerSource.url(URI.create("/relative"), null));
        assertThrows(IllegalArgumentException.class, () -> ServerSource.url(URI.create("http://h:1"), ""));
        assertThrows(NullPointerException.class, () -> ServerSource.executable(null));
        String hash = "da786ac853464e7b837c5483f9b04a27a3a5c2ff0340fa526f60482fd80fdb68";
        assertThrows(
                IllegalArgumentException.class, () -> ServerSource.download(URI.create("http://mirror/aprv"), hash));
        assertThrows(
                IllegalArgumentException.class,
                () -> ServerSource.download(URI.create("https://mirror/aprv"), hash.substring(1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> ServerSource.download(URI.create("https://mirror/aprv"), hash.replace('a', 'g')));
        assertThrows(NullPointerException.class, () -> Engine.server((ServerSource) null));
        assertThrows(NullPointerException.class, () -> Engine.server().cacheDirectory(null));
    }

    @Test
    void toStringNeverShowsTheToken() {
        String shown = ServerSource.url(URI.create("http://127.0.0.1:1"), "s3cr3t-token")
                .toString();
        assertFalse(shown.contains("s3cr3t"), shown);
        assertTrue(shown.contains("<token>"), shown);
        assertFalse(Engine.server(ServerSource.url(URI.create("http://127.0.0.1:1"), "s3cr3t-token"))
                .toString()
                .contains("s3cr3t"));
    }

    /** No source works: create names every source and its reason, in order. */
    @Test
    void aServerEngineWhoseSourcesAllFailThrowsWithEveryReason() {
        Engine.Server engine = Engine.server(
                ServerSource.executable(Paths.get("/nonexistent/aprv-a")),
                ServerSource.url(URI.create("http://127.0.0.1:1"), "token"));
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> Verifier.create(Config.defaults(), engine));
        String message = e.getMessage();
        assertTrue(message.startsWith("no aprv-server source worked: "), message);
        int executable = message.indexOf("ServerSource.executable(");
        int url = message.indexOf("ServerSource.url(");
        assertTrue(executable > 0 && url > executable, message);
        assertTrue(message.contains("/nonexistent/aprv-a"), message);
    }

    /** The checks every engine shares come first, in 0.7's order. */
    @Test
    void theSharedChecksComeBeforeTheEngine() {
        assertThrows(NullPointerException.class, () -> Verifier.create(null, Engine.server()));
        assertThrows(NullPointerException.class, () -> Verifier.create(Config.defaults(), null));
        assertThrows(NullPointerException.class, () -> Verifier.create(null));
        IllegalArgumentException empty = assertThrows(
                IllegalArgumentException.class,
                () -> Verifier.create(Config.builder().roots(Arrays.asList()).build(), Engine.server()));
        assertEquals("trustedRoots must not be empty", empty.getMessage());
    }

    @Test
    void theEngineIsChosenByTheJvmVersionAlone() {
        int feature = Engine.javaFeatureVersion();
        assertEquals(JRE.currentVersionNumber(), feature);
        if (feature >= 11) {
            assertSame(Engine.endive(), Engine.forThisJvm());
        } else {
            assertEquals(Engine.server(), Engine.forThisJvm());
        }
    }

    /**
     * The whole default path on Java 8: maven() installs the classifier
     * jar's binary into the user cache directory and starts it. Needs the
     * linux-x86_64 classifier directory on the classpath (tag "server").
     */
    @Test
    @Tag("server")
    @EnabledForJreRange(max = JRE.JAVA_10)
    void onJava8TheDefaultIsTheServerEngine() {
        Verifier verifier = Verifier.create(Config.defaults());
        try {
            assertTrue(verifier instanceof ServerVerifier, verifier.getClass().getName());
            assertTrue(((ServerVerifier) verifier).connection().process() != null, "maven() started a child");
        } finally {
            if (verifier instanceof ServerVerifier) {
                ((ServerVerifier) verifier).close();
            }
        }
    }

    @Test
    @EnabledForJreRange(max = JRE.JAVA_10)
    void onJava8TheEndiveEngineFailsAtCreateWithAClearMessage() {
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> Verifier.create(Config.defaults(), Engine.endive()));
        assertTrue(e.getMessage().contains("needs Java 11 or later"), e.getMessage());
        assertTrue(e.getMessage().contains("Engine.server("), e.getMessage());
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_11)
    void onJava11AndLaterTheDefaultIsEndive() {
        Verifier verifier = Verifier.create(Config.defaults());
        assertTrue(verifier instanceof WasmVerifier, verifier.getClass().getName());
    }
}
