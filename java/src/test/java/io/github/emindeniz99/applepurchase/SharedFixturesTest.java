package io.github.emindeniz99.applepurchase;

import io.github.emindeniz99.applepurchase.VerificationException.Reason;
import io.github.emindeniz99.applepurchase.jws.AppTransactionPayload;
import io.github.emindeniz99.applepurchase.jws.JwsVerifier;
import io.github.emindeniz99.applepurchase.jws.TransactionPayload;
import io.github.emindeniz99.applepurchase.receipt.AppReceipt;
import io.github.emindeniz99.applepurchase.receipt.ReceiptVerifier;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Locks the checked-in cross-language fixture set ({@code fixtures/generated/},
 * written by {@link FixtureGeneratorTest}): Java must verify the exact bytes
 * the Node/Python/Swift suites verify. If this test breaks, either the
 * fixtures were regenerated (re-run every language's suite) or behavior
 * changed (fix the code, not the fixtures).
 */
class SharedFixturesTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");
    private static final String BUNDLE = "com.example.app";

    private static byte[] bytes(String name) throws Exception {
        return Files.readAllBytes(FIXTURES.resolve(name));
    }

    private static String text(String name) throws Exception {
        return new String(bytes(name), StandardCharsets.US_ASCII).trim();
    }

    private static X509Certificate cert(String name) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(bytes(name)));
    }

    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    @Test
    void verifiesSharedTransactionFixture() throws Exception {
        JwsVerifier verifier = new JwsVerifier(Collections.singleton(cert("jws-root.der")),
                BUNDLE, EnumSet.of(Environment.SANDBOX));
        TransactionPayload payload = verifier.verifyTransaction(text("transaction.jws"));
        assertEquals(BUNDLE + ".pro", payload.productId());
        assertEquals("2000000000000001", payload.transactionId());
        assertEquals(Long.valueOf(1722945600000L), payload.signedDate());
    }

    @Test
    void verifiesSharedAppTransactionFixture() throws Exception {
        JwsVerifier verifier = new JwsVerifier(Collections.singleton(cert("jws-root.der")),
                BUNDLE, EnumSet.of(Environment.SANDBOX), 123456789L, null);
        AppTransactionPayload payload = verifier.verifyAppTransaction(text("app-transaction.jws"));
        assertEquals(Long.valueOf(123456789L), payload.appAppleId());
        assertEquals("1.2.3", payload.applicationVersion());
    }

    @Test
    void sharedExpiredChainFixturesBehaveAsManifested() throws Exception {
        JwsVerifier verifier = new JwsVerifier(Collections.singleton(cert("jws-expired-root.der")),
                BUNDLE, EnumSet.of(Environment.SANDBOX));
        assertEquals(Long.valueOf(1590969600000L),
                verifier.verifyTransaction(text("expired-cert-historical.jws")).signedDate());
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verifyTransaction(text("expired-cert-fresh.jws")));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void verifiesSharedReceiptFixture() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(Collections.singleton(cert("receipt-root.der")), BUNDLE);
        AppReceipt receipt = verifier.verify(bytes("receipt.der"), unhex(text("device-guid.hex")));
        assertEquals("1.2.3", receipt.appVersion());
        assertEquals(Instant.parse("2024-08-06T12:00:00Z"), receipt.creationDate());
        assertEquals(2, receipt.inAppPurchases().size());
    }

    @Test
    void unwrapsDoubleWrappedReceiptPayload() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(Collections.singleton(cert("receipt-root.der")), BUNDLE);
        AppReceipt receipt = verifier.verify(bytes("receipt-double-wrapped.der"));
        assertEquals("1.2.3", receipt.appVersion());
    }

    @Test
    void rejectsSharedForeignReceiptFixture() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(Collections.singleton(cert("receipt-root.der")), BUNDLE);
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verify(bytes("receipt-foreign.der")));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }
}
