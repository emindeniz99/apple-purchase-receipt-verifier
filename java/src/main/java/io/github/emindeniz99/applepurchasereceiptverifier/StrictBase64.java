package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Base64;

/**
 * The library's one base64 decoder, in its two strict spellings. Standard
 * base64 takes exactly the canonical {@code =} padding, the one spelling both
 * {@code receipt-data} (as Apple's verifyReceipt accepts it, measured
 * 2026-09-23) and an {@code x5c} entry (RFC 7515 4.1.6) allow; unused low bits
 * in the last character are accepted, as Apple accepts them. A JWS segment is
 * base64url (RFC 7515 2): no padding, and zero unused bits.
 */
final class StrictBase64 {

    private StrictBase64() {}

    /** {@code text} as padded standard base64, or a {@code reason} failure naming {@code what}. */
    static byte[] standard(String text, Reason reason, String what) throws VerificationException {
        return decode(text, false, reason, what);
    }

    /** {@code text} as unpadded base64url, or a {@code reason} failure naming {@code what}. */
    static byte[] url(String text, Reason reason, String what) throws VerificationException {
        return decode(text, true, reason, what);
    }

    private static byte[] decode(String text, boolean url, Reason reason, String what) throws VerificationException {
        String problem = what + (url ? " is not canonical base64url" : " is not canonically padded standard base64");
        // The basic decoder accepts omitted padding and decodes "" to nothing;
        // the MIME decoder would skip illegal characters.
        if (!url && (text.isEmpty() || text.length() % 4 != 0)) {
            throw new VerificationException(reason, problem);
        }
        byte[] decoded;
        try {
            decoded = (url ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(text);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(reason, problem, e);
        }
        // The URL decoder tolerates padding and non-zero unused bits; the
        // re-encoded text refuses both.
        if (url && !text.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded))) {
            throw new VerificationException(reason, problem);
        }
        return decoded;
    }
}
