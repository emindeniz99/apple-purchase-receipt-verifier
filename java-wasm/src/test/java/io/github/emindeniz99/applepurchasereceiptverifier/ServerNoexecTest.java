package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A binary on a {@code noexec} mount, on a real one: the test mounts a
 * {@code noexec} tmpfs, which needs root. Where it cannot, it is reported as
 * skipped with the reason, and {@link ServerProblemTest} still checks the
 * mountinfo parser the detection rests on.
 */
@Tag("server")
class ServerNoexecTest {

    @TempDir
    Path temp;

    private static String run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = process.getInputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
        }
        int exit = process.waitFor();
        return exit == 0 ? null : "exit " + exit + ": " + new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
    }

    @Test
    void aBinaryOnANoexecMountIsReportedWithWhatToDo() throws Exception {
        Path mount = Files.createDirectory(temp.resolve("noexec"));
        String refused = run("mount", "-t", "tmpfs", "-o", "noexec,size=48m", "tmpfs", mount.toString());
        Assumptions.assumeTrue(refused == null, "cannot mount a noexec tmpfs here (" + refused + ")");
        try {
            assertTrue(ServerBinary.noexec(mount.resolve("anything")));
            IllegalStateException cache = assertThrows(
                    IllegalStateException.class,
                    () -> Verifier.create(
                            Config.defaults(),
                            Engine.server(ServerSource.maven()).cacheDirectory(mount.resolve("cache"))));
            assertTrue(cache.getMessage().contains(ServerBinary.NOEXEC_ADVICE), cache.getMessage());
            System.out.println("noexec cache directory: " + cache.getMessage());

            Path copy = mount.resolve("aprv");
            Files.copy(ServerTests.binary(), copy);
            Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rwx------"));
            IllegalStateException executable = assertThrows(
                    IllegalStateException.class,
                    () -> Verifier.create(Config.defaults(), Engine.server(ServerSource.executable(copy))));
            assertTrue(executable.getMessage().contains(ServerBinary.NOEXEC_ADVICE), executable.getMessage());

            // Without the check before the start, the kernel's EACCES gets the same explanation.
            IOException denied = assertThrows(IOException.class, () -> new ProcessBuilder(copy.toString()).start());
            assertTrue(ServerBinary.explainStartFailure(copy, denied).endsWith(ServerBinary.NOEXEC_ADVICE));
        } finally {
            String left = run("umount", mount.toString());
            assertTrue(left == null, "umount " + mount + ": " + left);
        }
    }
}
