package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The host's {@code java.security} policy does not change a verdict.
 *
 * <p>Why it matters: the JDK's PKIX code obeys
 * {@code jdk.certpath.disabledAlgorithms}, and RHEL, Fedora and many
 * hardened images disable SHA-1 there. Apple signs every legacy receipt chain
 * with SHA-1, so while chains were built with the JDK's PKIX code each genuine
 * legacy receipt failed on such a host as INVALID_CHAIN, as if it were forged.
 * The library now builds and validates chains with its own BouncyCastle
 * instance, which does not read that property.</p>
 */
class HostPolicyTest {

    private static final String HARDENED = "jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1, RSA keySize < 1024\n";

    /**
     * The control for the premise the child checks: on this JVM the JDK's
     * own PKIX code builds the legacy chain, so a refusal in the child is the
     * policy's doing and not a wrong date or a missing certificate.
     */
    @Test
    void theJdkBuildsTheLegacyChainUnderThisJvmsPolicy() throws Exception {
        byte[] legacy = HostPolicyProbe.publicReceipt("receipt-sandbox-legacy");
        AppReceipt receipt = ReceiptVerifier.verifyReceiptCore(legacy, AppleRootCerts.receiptRoots());
        String refusal = HostPolicyProbe.jdkRefusal(legacy, receipt.creationDate());
        assumeTrue(
                refusal == null,
                "this JVM's own policy refuses the legacy chain, so it cannot be the control: " + refusal);
    }

    /**
     * A JVM whose policy disables SHA-1 outright, as RHEL and Fedora system
     * crypto policies do. Run in a child JVM because
     * {@code java.security.properties} is read once, at startup.
     */
    @Test
    void aHostPolicyThatDisablesSha1MovesNoVerdict(@TempDir Path tmp) throws Exception {
        Path policy = tmp.resolve("hardened.properties");
        Files.write(policy, HARDENED.getBytes(StandardCharsets.US_ASCII));
        List<String> command = new ArrayList<String>();
        command.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Djava.security.properties=" + policy.toAbsolutePath());
        command.add("-D" + TestFixtures.PROPERTY + "=" + TestFixtures.root().toAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(HostPolicyProbe.class.getName());
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        // Either variable can carry a -Djava.security.properties of its own.
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().remove("_JAVA_OPTIONS");
        Process child = builder.start();
        String output = new String(readAll(child.getInputStream()), StandardCharsets.UTF_8);
        assertTrue(child.waitFor(2, TimeUnit.MINUTES), output);
        assertEquals(0, child.exitValue(), output);

        assertTrue(output.contains(HostPolicyProbe.JDK_REFUSES), output);
        assertTrue(output.contains(HostPolicyProbe.LEGACY + ": com.nutcall.alert"), output);
        assertTrue(output.contains(HostPolicyProbe.CURRENT), output);
        assertTrue(output.contains(HostPolicyProbe.JWS), output);
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
