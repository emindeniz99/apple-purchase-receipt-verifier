package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The chain signature algorithms a verifier accepts, and the constructor's
 * check that this JVM can validate each of them.
 *
 * <p>Why it matters: the JDK's PKIX code obeys
 * {@code jdk.certpath.disabledAlgorithms}, and RHEL, Fedora and many
 * hardened images disable SHA-1 there. Apple signs every legacy receipt chain
 * with SHA-1, so on such a host each genuine legacy receipt used to fail as
 * INVALID_CHAIN, as if it were forged, and nothing told the operator why.</p>
 */
class ChainAlgorithmsTest {

    private static final Path PUBLIC = Paths.get("..", "fixtures", "public-receipts");
    private static final Path GENERATED = Paths.get("..", "fixtures", "generated");

    private static byte[] publicReceipt(String name) throws Exception {
        return Base64.getMimeDecoder()
                .decode(new String(Files.readAllBytes(PUBLIC.resolve(name + ".b64")), StandardCharsets.US_ASCII));
    }

    private static X509Certificate root(String name) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(GENERATED.resolve(name))));
    }

    @Test
    void theDefaultsCoverEveryChainAppleSigns() throws Exception {
        // Legacy (SHA-1) and current (SHA-256) receipts, and a JWS: each
        // verifies with the defaults, so leaving one out below is the only
        // thing that can refuse it.
        assertNotNull(ReceiptVerifier.verifyReceiptCore(
                publicReceipt("receipt-sandbox-legacy"), AppleRootCerts.receiptRoots()));
        assertNotNull(
                ReceiptVerifier.verifyReceiptCore(publicReceipt("receipt-sandbox-g5"), AppleRootCerts.receiptRoots()));
        assertEquals(
                EnumSet.of(SignatureAlgorithm.SHA1_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA),
                ReceiptVerifier.DEFAULT_CHAIN_ALGORITHMS);
        assertEquals(
                EnumSet.of(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA),
                JwsVerifier.DEFAULT_CHAIN_ALGORITHMS);
    }

    @Test
    void leavingOutSha1RefusesLegacyReceiptsAsInvalidChainAndKeepsCurrentOnes() throws Exception {
        // What the constructor javadoc promises a caller who drops SHA-1:
        // genuine legacy receipts become INVALID_CHAIN, current ones still verify.
        VerificationException legacy = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(
                        publicReceipt("receipt-sandbox-legacy"),
                        AppleRootCerts.receiptRoots(),
                        EnumSet.of(SignatureAlgorithm.SHA256_WITH_RSA)));
        assertEquals(VerificationException.Reason.INVALID_CHAIN, legacy.reason());
        assertTrue(legacy.getMessage().contains("SHA1withRSA"), legacy.getMessage());

        assertNotNull(ReceiptVerifier.verifyReceiptCore(
                publicReceipt("receipt-sandbox-g5"),
                AppleRootCerts.receiptRoots(),
                EnumSet.of(SignatureAlgorithm.SHA256_WITH_RSA)));
    }

    @Test
    void aJwsChainOutsideTheSetIsInvalidChain() throws Exception {
        // The generated JWS chain is ECDSA-SHA256 throughout.
        JwsVerifier verifier = new JwsVerifier(
                Collections.singleton(root("jws-root.der")),
                "com.example.app",
                EnumSet.of(Environment.SANDBOX),
                null,
                null,
                null,
                EnumSet.of(SignatureAlgorithm.SHA384_WITH_ECDSA));
        String jws =
                new String(Files.readAllBytes(GENERATED.resolve("transaction.jws")), StandardCharsets.UTF_8).trim();
        VerificationException e = assertThrows(VerificationException.class, () -> verifier.verifyTransaction(jws));
        assertEquals(VerificationException.Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void anEmptySetIsRefused() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ReceiptVerifier(
                        AppleRootCerts.receiptRoots(), "com.example.app", EnumSet.noneOf(SignatureAlgorithm.class)));
    }

    /**
     * A JVM whose policy disables SHA-1 outright, which RHEL and Fedora
     * system crypto policies do. Run in a child JVM, because
     * {@code java.security.properties} is read once at startup; the child is
     * {@link HostPolicyProbe}, and it reports what each constructor did.
     */
    @Test
    void aHostThatDisablesSha1FailsTheDefaultConstructorAndNamesTheFix() throws Exception {
        File policy = File.createTempFile("hardened", ".properties");
        policy.deleteOnExit();
        Files.write(
                policy.toPath(),
                "jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1, RSA keySize < 1024\n"
                        .getBytes(StandardCharsets.US_ASCII));
        List<String> command = new ArrayList<String>();
        command.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Djava.security.properties=" + policy.getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(HostPolicyProbe.class.getName());
        Process child = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(readAll(child), StandardCharsets.UTF_8);
        assertTrue(child.waitFor(120, TimeUnit.SECONDS), output);
        assertEquals(0, child.exitValue(), output);

        // The default constructor refuses to start, and says which algorithm,
        // which setting, and what leaving it out costs.
        assertTrue(output.contains("default: IllegalStateException"), output);
        assertTrue(output.contains("SHA1withRSA"), output);
        assertTrue(output.contains("jdk.certpath.disabledAlgorithms"), output);
        assertTrue(output.contains("legacy receipts then fail with INVALID_CHAIN"), output);
        // Leaving SHA-1 out starts, and current receipts still verify.
        assertTrue(output.contains("without SHA-1: current receipt verifies"), output);
        assertTrue(output.contains("without SHA-1: legacy receipt INVALID_CHAIN"), output);
        // The JWS defaults do not use SHA-1, so that verifier is unaffected.
        assertTrue(output.contains("jws default: constructed"), output);
    }

    private static byte[] readAll(Process process) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = process.getInputStream().read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
