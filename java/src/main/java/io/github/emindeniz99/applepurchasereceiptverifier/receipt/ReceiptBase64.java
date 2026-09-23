package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.util.Base64;
import org.jspecify.annotations.Nullable;

/**
 * Decodes the base64 text a client sends as {@code receipt-data} by the rule
 * Apple's verifyReceipt applies (measured 2026-09-23, see
 * {@code docs/evidence/2026-09-23-verifyreceipt-base64.md}): non-empty,
 * standard alphabet ({@code [A-Za-z0-9+/]}), exactly the canonical {@code =}
 * padding for the data length, and nothing else. Whitespace anywhere,
 * base64url, omitted or extra padding and anything after the padding are
 * {@link Reason#INVALID_RECEIPT_FORMAT}. Unused low bits in the last data
 * character are accepted, as Apple accepts them.
 *
 * <p>{@link Base64#getDecoder()} enforces all of that except two things: it
 * accepts omitted padding and decodes {@code ""} to nothing. Both are refused
 * by requiring a non-empty length that is a multiple of four first. The MIME
 * decoder is not an option: it skips every character it does not know.</p>
 */
final class ReceiptBase64 {

    private ReceiptBase64() {}

    static byte[] decode(@Nullable String receipt) throws VerificationException {
        if (receipt == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        if (receipt.isEmpty() || receipt.length() % 4 != 0) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "receipt is not canonically padded standard base64");
        }
        try {
            return Base64.getDecoder().decode(receipt);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "receipt is not canonically padded standard base64", e);
        }
    }
}
