package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;

/**
 * The legacy PKCS#7 receipt path end to end, on raw DER: BouncyCastle's CMS
 * reader, the hand-written attribute walk, the PKIX chain build against the
 * pinned anchors, and the CMS signature check.
 *
 * <p>Anchors are Apple's three receipt roots plus the fixture receipt root, so
 * every seed under {@code fixtures/generated/} and both public Apple receipts
 * pass the chain check and the fuzzer's mutations land on the code beyond it.
 */
public final class FuzzReceiptDer {

    private FuzzReceiptDer() {}

    public static void fuzzerTestOneInput(byte[] data) {
        AppReceipt receipt = Harness.attempt(
                "verifyReceiptCore", () -> ReceiptVerifier.verifyReceiptCore(data, Harness.RECEIPT_ANCHORS));
        if (receipt == null) {
            return;
        }
        Harness.touch(receipt);

        // ANCHOR-SET INVARIANT. Without it an input that verifies tells you
        // nothing about why it verified: a chain build that ignored its
        // anchors, or a signature check that accepted any signer, would look
        // exactly like a run that found nothing.
        AppReceipt underUnrelated = Harness.attempt(
                "verifyReceiptCore(unrelated anchors)",
                () -> ReceiptVerifier.verifyReceiptCore(data, Harness.UNRELATED_RECEIPT_ANCHORS));
        if (underUnrelated != null) {
            throw new AssertionError("a receipt accepted under the receipt anchors was also accepted under the "
                    + "fixture JWS root, which signed no receipt here");
        }
    }
}
