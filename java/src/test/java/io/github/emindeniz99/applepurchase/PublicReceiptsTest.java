package io.github.emindeniz99.applepurchase;

import io.github.emindeniz99.applepurchase.VerificationException.Reason;
import io.github.emindeniz99.applepurchase.receipt.AppReceipt;
import io.github.emindeniz99.applepurchase.receipt.ReceiptVerifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The strongest fixture tier: genuine Apple-signed receipts (vendored from
 * MIT-licensed public test suites — see fixtures/public-receipts/README.md)
 * verified against the REAL pinned Apple Inc. Root CA.
 */
class PublicReceiptsTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "public-receipts");

    private static String receipt(String name) throws Exception {
        return new String(Files.readAllBytes(FIXTURES.resolve(name + ".b64")),
                StandardCharsets.US_ASCII).trim();
    }

    @Test
    void verifiesGenuineSandboxReceiptAgainstRealAppleRoot() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(
                AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app");
        AppReceipt receipt = verifier.verify(receipt("receipt-sandbox-g5"));
        assertEquals("ProductionSandbox", receipt.receiptType());
        assertEquals(2, receipt.inAppPurchases().size());
    }

    @Test
    void verifiesGenuineLegacySha1ChainReceipt() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(
                AppleRootCerts.receiptRoots(), "com.nutcall.alert");
        AppReceipt receipt = verifier.verify(receipt("receipt-sandbox-legacy"));
        assertEquals(187, receipt.inAppPurchases().size());
    }

    @Test
    void rejectsXcodeSignedPublicReceipt() throws Exception {
        ReceiptVerifier verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "*");
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier.verify(receipt("receipt-xcode-with-purchases")));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }
}
