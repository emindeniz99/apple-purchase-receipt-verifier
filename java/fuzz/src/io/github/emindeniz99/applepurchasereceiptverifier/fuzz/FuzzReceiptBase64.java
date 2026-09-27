package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import java.nio.charset.StandardCharsets;

/**
 * The string a client actually sends: {@code Verifier.verifyReceipt}, and
 * therefore the size cap and {@code ReceiptBase64} in front of the whole DER
 * path.
 *
 * <p>Bytes are read as ISO-8859-1 rather than UTF-8 on purpose: the mapping is
 * bijective, so libFuzzer's byte mutations reach every {@code char} value below
 * 256, including the ones {@code ReceiptBase64} must reject, instead of
 * collapsing invalid UTF-8 onto U+FFFD, which would make most of the alphabet
 * unreachable and half the corpus indistinguishable.
 */
public final class FuzzReceiptBase64 {

    private FuzzReceiptBase64() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);

        ReceiptPayload receipt = Harness.attempt("verifyReceipt", () -> Harness.RECEIPTS.verifyReceipt(text));
        if (receipt == null) {
            return;
        }
        Harness.touch(receipt);
        Harness.sink(receipt.toJson());

        // ANCHOR-SET INVARIANT, as in FuzzReceiptDer: same string, an anchor
        // set that signed nothing here.
        ReceiptPayload underUnrelated = Harness.attempt(
                "verifyReceipt(unrelated anchors)", () -> Harness.UNRELATED_RECEIPTS.verifyReceipt(text));
        if (underUnrelated != null) {
            throw new AssertionError("a base64 receipt accepted under the receipt anchors was also accepted under "
                    + "the fixture JWS root, which signed no receipt here");
        }
    }
}
