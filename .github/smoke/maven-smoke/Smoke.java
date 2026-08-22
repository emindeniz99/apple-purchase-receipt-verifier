import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Smoke-tests the jar as published to Maven Central. Everything it touches —
 * the verifier, the exception type, the bundled root certificates — comes from
 * the resolved artifact, so a jar missing its resources fails here rather than
 * in a user's build.
 */
public final class Smoke {
    public static void main(String[] args) throws Exception {
        String receiptB64 = Files.readString(Path.of("receipt-sandbox-g5.b64"), StandardCharsets.US_ASCII).trim();

        // A real Apple-signed receipt against the real pinned root: exercises
        // the packaged certs, the DER reader, the chain build and the signature.
        AppReceipt receipt = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app")
                .verify(receiptB64);
        if (!"ProductionSandbox".equals(receipt.receiptType())) {
            throw new AssertionError("receiptType was " + receipt.receiptType());
        }
        if (!"dev.bonzer.weeka.app".equals(receipt.bundleId())) {
            throw new AssertionError("bundleId was " + receipt.bundleId());
        }

        // And the negative direction, so a verifier that accepted everything
        // would fail here too.
        boolean rejected = false;
        try {
            new ReceiptVerifier(AppleRootCerts.receiptRoots(), "com.other.app").verify(receiptB64);
        } catch (VerificationException e) {
            rejected = e.reason() == VerificationException.Reason.WRONG_BUNDLE_ID;
        }
        if (!rejected) {
            throw new AssertionError("a receipt for another bundle id was not rejected");
        }

        System.out.printf("maven: published jar verified a genuine Apple receipt (%s, %d purchases)"
                + " and rejected a foreign bundle id%n", receipt.bundleId(), receipt.inAppPurchases().size());
    }
}
