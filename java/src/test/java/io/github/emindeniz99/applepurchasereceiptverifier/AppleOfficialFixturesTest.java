package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Cross-library parity: verify the exact fixture bytes Apple's own
 * app-store-server-library test suite uses (vendored under
 * {@code fixtures/apple-official/} — see its README for provenance).
 * The mock signed data anchors at Apple's test CA; the Xcode artifacts
 * must be REJECTED against real Apple roots, proving anchor pinning.
 */
class AppleOfficialFixturesTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "apple-official");
    private static final String BUNDLE = "com.example";
    private static final String XCODE_BUNDLE = "com.example.naturelab.backyardbirds.example";

    private static String read(String first, String second) throws Exception {
        return new String(Files.readAllBytes(FIXTURES.resolve(first).resolve(second)),
                StandardCharsets.UTF_8).trim();
    }

    private static JwsVerifier appleTestCaVerifier() throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve("certs").resolve("testCA.der"));
        X509Certificate testCa = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        return new JwsVerifier(Collections.singleton(testCa), BUNDLE,
                EnumSet.of(Environment.SANDBOX));
    }

    @Test
    void verifiesAppleTransactionInfoFixture() throws Exception {
        TransactionPayload payload = appleTestCaVerifier()
                .verifyTransaction(read("mock_signed_data", "transactionInfo"));
        assertEquals(BUNDLE, payload.bundleId());
        assertEquals("Sandbox", payload.environment());
        assertEquals(Long.valueOf(1672956154000L), payload.signedDate());
    }

    @Test
    void verifiesAppleRenewalInfoFixture() throws Exception {
        Map<String, Object> claims = appleTestCaVerifier()
                .verifyRaw(read("mock_signed_data", "renewalInfo"));
        assertEquals("Sandbox", claims.get("environment"));
    }

    @Test
    void verifiesAppleNotificationFixture() throws Exception {
        Map<String, Object> claims = appleTestCaVerifier()
                .verifyRaw(read("mock_signed_data", "testNotification"));
        assertEquals("TEST", claims.get("notificationType"));
    }

    @Test
    void rejectsAppleWrongBundleIdFixture() throws Exception {
        JwsVerifier verifier = appleTestCaVerifier();
        String jws = read("mock_signed_data", "wrongBundleId");
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verifyTransaction(jws));
        assertEquals(Reason.WRONG_BUNDLE_ID, e.reason());
    }

    @Test
    void rejectsAppleMissingX5cFixture() throws Exception {
        JwsVerifier verifier = appleTestCaVerifier();
        String jws = read("mock_signed_data", "missingX5CHeaderClaim");
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verifyTransaction(jws));
        assertEquals(Reason.INVALID_JWS_FORMAT, e.reason());
    }

    /** Xcode signs with a single local cert (x5c length 1) — never trustable. */
    @Test
    void rejectsXcodeSignedTransactionAgainstAppleTestCa() throws Exception {
        JwsVerifier verifier = appleTestCaVerifier();
        String jws = read("xcode", "xcode-signed-transaction");
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verifyTransaction(jws));
        assertEquals(Reason.INVALID_JWS_FORMAT, e.reason());
    }

    /** A genuine Xcode receipt must not verify against the real Apple root. */
    @Test
    void rejectsXcodeReceiptAgainstRealAppleRoots() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), XCODE_BUNDLE);
        String base64Receipt = read("xcode", "xcode-app-receipt-empty");
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verify(base64Receipt));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }
}
