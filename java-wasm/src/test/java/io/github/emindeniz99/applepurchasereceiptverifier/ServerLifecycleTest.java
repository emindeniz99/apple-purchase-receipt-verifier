package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * No orphan however the JVM ends (the spike's two checks, plus the reaper):
 * {@code System.exit} without {@code close()} stops the child through the
 * shutdown hook; {@code kill -9} of the JVM, where no hook runs, stops it
 * through the child's stdin EOF; and a verifier that becomes unreachable
 * stops its child without the JVM ending.
 */
@Tag("server")
class ServerLifecycleTest {

    private static Process hold(String mode) throws Exception {
        return new ProcessBuilder(
                        ServerTests.java(),
                        "-cp",
                        ServerTests.classpath(),
                        ServerHoldMain.class.getName(),
                        ServerTests.binary().toString(),
                        mode)
                .redirectErrorStream(true)
                .start();
    }

    private static long childPid(BufferedReader out) throws Exception {
        String line;
        while ((line = out.readLine()) != null) {
            if (line.startsWith("CHILD ")) {
                return Long.parseLong(line.substring(6).trim());
            }
        }
        throw new AssertionError("the holding JVM printed no CHILD line");
    }

    @Test
    void systemExitWithoutCloseStopsTheChild() throws Exception {
        Process jvm = hold("exit");
        BufferedReader out = new BufferedReader(new InputStreamReader(jvm.getInputStream(), StandardCharsets.UTF_8));
        long child = childPid(out);
        assertTrue(jvm.waitFor(20, TimeUnit.SECONDS), "the holding JVM exited");
        assertTrue(ServerTests.gone(child, 5000), "child " + child + " gone after System.exit");
    }

    @Test
    void killingTheJvmWithSigkillStopsTheChild() throws Exception {
        Process jvm = hold("sleep");
        BufferedReader out = new BufferedReader(new InputStreamReader(jvm.getInputStream(), StandardCharsets.UTF_8));
        long child = childPid(out);
        assertTrue(ServerTests.alive(child));
        jvm.destroyForcibly(); // SIGKILL: no shutdown hook runs
        jvm.waitFor(10, TimeUnit.SECONDS);
        assertTrue(ServerTests.gone(child, 5000), "child " + child + " gone after kill -9 of the JVM");
    }

    @Test
    void anUnreachableVerifierStopsItsChild() throws Exception {
        Process jvm = hold("gc");
        BufferedReader out = new BufferedReader(new InputStreamReader(jvm.getInputStream(), StandardCharsets.UTF_8));
        long child = childPid(out);
        String line;
        while ((line = out.readLine()) != null && !line.equals("COLLECTED")) {
            // wait
        }
        try {
            assertTrue(ServerTests.gone(child, 5000), "child " + child + " gone after its verifier was collected");
        } finally {
            jvm.destroyForcibly();
        }
    }
}
