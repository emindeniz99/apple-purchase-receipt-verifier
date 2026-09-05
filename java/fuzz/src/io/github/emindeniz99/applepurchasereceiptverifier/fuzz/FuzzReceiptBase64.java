package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import java.nio.charset.StandardCharsets;

/**
 * The string a client actually sends: {@code ReceiptVerifier.verify(String)},
 * its device-GUID overload, and therefore {@code ReceiptBase64} in front of the
 * whole DER path.
 *
 * <p>The verifier is bound to {@code Harness.RECEIPT_BUNDLE_ID}, the bundle id
 * the seed corpus actually carries, so seeds reach acceptance and the
 * anchor-set invariant below has something to bite on. See that constant for
 * what binding it to the generated fixtures' bundle id costs.
 *
 * <p>Bytes are read as ISO-8859-1 rather than UTF-8 on purpose: the mapping is
 * bijective, so libFuzzer's byte mutations reach every {@code char} value below
 * 256 — including the ones {@code ReceiptBase64} must reject — instead of
 * collapsing invalid UTF-8 onto U+FFFD, which would make most of the alphabet
 * unreachable and half the corpus indistinguishable.
 */
public final class FuzzReceiptBase64 {

    private FuzzReceiptBase64() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);

        // The device-GUID overload first: it runs the same decode and chain
        // work and then the SHA-1 binding, which nothing else here reaches.
        Harness.attempt("verify(String, byte[])", () -> Harness.RECEIPT_VERIFIER.verify(text, Harness.DEVICE_GUID));

        AppReceipt receipt = Harness.attempt("verify(String)", () -> Harness.RECEIPT_VERIFIER.verify(text));
        if (receipt == null) {
            return;
        }
        Harness.touch(receipt);

        // ANCHOR-SET INVARIANT, as in FuzzReceiptDer: same bundle id, same
        // string, an anchor set that signed nothing here.
        AppReceipt underUnrelated = Harness.attempt(
                "verify(String) unrelated anchors", () -> Harness.UNRELATED_RECEIPT_VERIFIER.verify(text));
        if (underUnrelated != null) {
            throw new AssertionError("a base64 receipt accepted under the receipt anchors was also accepted under "
                    + "the fixture JWS root, which signed no receipt here");
        }
    }
}
