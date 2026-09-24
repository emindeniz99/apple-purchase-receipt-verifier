package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.internal.SafeText;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;

/**
 * What an exception message is allowed to say about the input that caused it.
 *
 * <p>Two things went wrong when it said everything. A 2 MB {@code alg} claim
 * produced a 2 MB message, so an input the library correctly refused still
 * cost the caller the memory it was refusing to spend, once in the exception
 * and again in every log line written from it. And a newline inside a claim ended
 * the log record and began a new one, so the attacker wrote the next line of
 * the log.
 */
class SafeTextTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");

    @Test
    void shortInputIsQuotedUnchanged() {
        assertEquals("ES256", SafeText.quote("ES256"));
    }

    @Test
    void nullIsQuotedTheWayConcatenationWouldRenderIt() {
        assertEquals("null", SafeText.quote((String) null));
    }

    @Test
    void longInputIsTruncatedAndStatesItsOriginalLength() {
        String quoted = SafeText.quote(repeat('A', 5000));
        assertTrue(quoted.length() < 100, "the quoted value is still " + quoted.length() + " characters");
        assertTrue(quoted.startsWith(repeat('A', 64)), quoted);
        // Stated rather than silently cut: a truncated value that does not say
        // so reads as the whole value, and "5000" is what makes the difference
        // visible in a log.
        assertTrue(quoted.contains("5000 characters"), quoted);
    }

    @Test
    void controlCharactersCannotReachALogLineAsThemselves() {
        String quoted = SafeText.quote("ES256\nWARN forged log line\r\tand a \u007f delete");
        assertFalse(quoted.contains("\n"), quoted);
        assertFalse(quoted.contains("\r"), quoted);
        assertFalse(quoted.contains("\t"), quoted);
        assertFalse(quoted.contains("\u007f"), quoted);
        assertTrue(quoted.contains("\uFFFD"), quoted);
        // The readable text survives; only the characters that would forge a
        // record are replaced.
        assertTrue(quoted.contains("WARN forged log line"), quoted);
    }

    /**
     * The end-to-end form of both rules, at the site the finding was raised
     * on: {@code alg} is attacker-controlled, is read before any signature
     * check, and used to be concatenated into the message whole.
     */
    @Test
    void aHostileAlgorithmClaimCannotSetTheSizeOrTheShapeOfTheMessage() throws Exception {
        String alg = repeat('A', 100000) + "\nWARN forged";
        String header = "{\"alg\":\"" + alg + "\",\"x5c\":[\"a\",\"b\",\"c\"]}";
        String jws = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + ".e30.AA";

        VerificationException thrown =
                assertThrows(VerificationException.class, () -> verifier().verifyTransaction(jws));
        assertTrue(
                thrown.getMessage().length() < 200,
                "the message is " + thrown.getMessage().length() + " characters");
        assertFalse(thrown.getMessage().contains("\n"), thrown.getMessage());
    }

    /**
     * The same rule where the text comes from BouncyCastle rather than from
     * this library: a path validator's refusal can quote a distinguished name
     * out of the x5c chain, which the attacker chose. Here the leaf names an
     * issuer carrying a CR LF, signed by the genuine intermediate so it gets
     * as far as the name check, whose message quotes both names.
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
        JwsVerifier verifier =
                new JwsVerifier(Collections.singleton(pki.root), "com.example.app", EnumSet.of(Environment.SANDBOX));

        VerificationException thrown = assertThrows(VerificationException.class, () -> verifier.verifyRaw(jws));
        assertEquals(VerificationException.Reason.INVALID_CHAIN, thrown.reason(), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("WARN forged log line"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("\n"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("\r"), thrown.getMessage());
    }

    private static JwsVerifier verifier() throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve("jws-root.der"));
        X509Certificate root = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        return new JwsVerifier(Collections.singleton(root), "com.example.app", EnumSet.of(Environment.SANDBOX));
    }

    /** Java 8 has no {@code String.repeat}, and the artifact's floor is 8. */
    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }
}
