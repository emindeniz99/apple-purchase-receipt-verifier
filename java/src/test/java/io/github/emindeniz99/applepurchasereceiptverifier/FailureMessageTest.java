package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** A failure message never quotes the input, so it can go into a log line as is. */
class FailureMessageTest {

    private static final Path FIXTURES = TestFixtures.generated();

    /**
     * {@code alg} is attacker-controlled and read before any signature
     * check; it once went into the message whole, so a 100 KB claim made a
     * 100 KB message and a newline in it forged the next log line.
     */
    @Test
    void aHostileAlgorithmClaimCannotSetTheSizeOrTheShapeOfTheMessage() throws Exception {
        String alg = repeat('A', 100000) + "\nWARN forged";
        String header = "{\"alg\":\"" + alg + "\",\"x5c\":[\"a\",\"b\",\"c\"]}";
        String jws = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + ".e30.AA";

        VerificationException thrown =
                assertThrows(VerificationException.class, () -> Checks.signedData(verifier(), jws));
        assertTrue(
                thrown.getMessage().length() < 200,
                "the message is " + thrown.getMessage().length() + " characters");
        assertFalse(thrown.getMessage().contains("\n"), thrown.getMessage());
    }

    /**
     * A path validator's refusal can quote a distinguished name out of the
     * x5c chain, which the attacker chose, so it stays in the cause. Here the
     * leaf names an issuer carrying a CR LF, signed by the genuine
     * intermediate so it gets as far as the name check.
     */
    @Test
    void aHostileNameInTheChainCannotForgeALogLineThroughTheValidatorsMessage() throws Exception {
        TestPki pki = TestPki.jws();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        X509Certificate hostileLeaf = TestPki.cert(
                "CN=Fake App Store Signing",
                ec.generateKeyPair(),
                "CN=Fake Apple WWDR CA\r\nWARN forged log line",
                pki.intermediateKey,
                false,
                "1.2.840.113635.100.6.11.1",
                pki.leaf.getNotBefore(),
                pki.leaf.getNotAfter(),
                "SHA256withECDSA");
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(hostileLeaf.getEncoded()) + "\",\""
                + TestPki.b64(pki.intermediate.getEncoded()) + "\",\"" + TestPki.b64(pki.root.getEncoded()) + "\"]}";
        // The chain is judged before the signature, so the signature need not be real.
        String payload = "{\"signedDate\":" + System.currentTimeMillis() + "}";
        final String jws = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(payload.getBytes(StandardCharsets.UTF_8))
                + "." + TestPki.b64url(new byte[64]);
        Verifier verifier = Checks.verifier(pki);

        VerificationException thrown =
                assertThrows(VerificationException.class, () -> Checks.signedData(verifier, jws));
        assertEquals(Reason.UNTRUSTED_CHAIN, thrown.reason(), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("WARN forged"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("\n"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("\r"), thrown.getMessage());
    }

    private static Verifier verifier() throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve("jws-root.der"));
        X509Certificate root = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        return Checks.verifier(root);
    }

    /** Java 8 has no {@code String.repeat}, and the artifact's floor is 8. */
    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }
}
