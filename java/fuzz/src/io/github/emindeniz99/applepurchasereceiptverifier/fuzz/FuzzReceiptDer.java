package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import java.util.Base64;

/**
 * The legacy PKCS#7 receipt path end to end, on raw DER (base64-encoded on
 * the way in, since 0.7 takes only the string): BouncyCastle's CMS reader,
 * the attribute walk, the PKIX chain build against the pinned anchors, and
 * the CMS signature check.
 *
 * <p>Anchors are Apple's three roots plus the fixture receipt root, so both
 * public Apple receipts pass the chain check and the fuzzer's mutations land
 * on the code beyond it.
 */
public final class FuzzReceiptDer {

    private FuzzReceiptDer() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String base64 = Base64.getEncoder().encodeToString(data);
        ReceiptPayload receipt = Harness.attempt("verifyReceipt(DER)", () -> Harness.RECEIPTS.verifyReceipt(base64));
        if (receipt == null) {
            return;
        }
        Harness.touch(receipt);

        // ANCHOR-SET INVARIANT. Without it an input that verifies tells you
        // nothing about why it verified: a chain build that ignored its
        // anchors, or a signature check that accepted any signer, would look
        // exactly like a run that found nothing.
        ReceiptPayload underUnrelated = Harness.attempt(
                "verifyReceipt(DER, unrelated anchors)", () -> Harness.UNRELATED_RECEIPTS.verifyReceipt(base64));
        if (underUnrelated != null) {
            throw new AssertionError("a receipt accepted under the receipt anchors was also accepted under the "
                    + "fixture JWS root, which signed no receipt here");
        }
    }
}
