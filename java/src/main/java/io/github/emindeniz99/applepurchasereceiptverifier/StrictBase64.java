package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Base64;

/**
 * Standard base64 with exactly the canonical {@code =} padding, the one
 * spelling both {@code receipt-data} (as Apple's verifyReceipt accepts it,
 * measured 2026-09-23) and an {@code x5c} entry (RFC 7515 4.1.6) allow.
 * Unused low bits in the last character are accepted, as Apple accepts them.
 */
final class StrictBase64 {

    private StrictBase64() {}

    /** {@code text} decoded, or a {@code reason} failure naming {@code what}. */
    static byte[] decode(String text, Reason reason, String what) throws VerificationException {
        // The basic decoder accepts omitted padding and decodes "" to nothing;
        // the MIME decoder would skip illegal characters.
        if (text.isEmpty() || text.length() % 4 != 0) {
            throw new VerificationException(reason, what + " is not canonically padded standard base64");
        }
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(reason, what + " is not canonically padded standard base64", e);
        }
    }
}
