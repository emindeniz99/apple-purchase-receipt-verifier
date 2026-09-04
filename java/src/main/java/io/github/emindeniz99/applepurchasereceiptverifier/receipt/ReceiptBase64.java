package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.util.Base64;

/**
 * Decodes the base64 text a client actually sends as {@code receipt-data},
 * per Apple's contract: RFC 4648 Base64, standard ("+/") or base64url
 * ("-_") alphabet, padding present or omitted, CR/LF/space/tab anywhere.
 * Rejected as {@link Reason#INVALID_RECEIPT_FORMAT}: any other character,
 * both alphabets in one string, anything but whitespace after the padding,
 * a stripped length congruent to 1 mod 4, and an empty or whitespace-only
 * string. No canonical-trailing-bits check.
 *
 * <p>{@link Base64#getMimeDecoder()} — used at both call sites before this
 * class existed — is wrong in two opposite directions: it silently DROPS
 * {@code -}/{@code _} instead of treating them as base64url, so base64url
 * input (which Foundation's {@code base64EncodedString(options:)} can emit)
 * decodes to corrupt DER and is misreported as
 * {@code INVALID_RECEIPT_FORMAT}; and it silently drops any other illegal
 * character instead of rejecting the receipt.</p>
 */
final class ReceiptBase64 {

    private ReceiptBase64() {}

    static byte[] decode(String receipt) throws VerificationException {
        if (receipt == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        StringBuilder stripped = new StringBuilder(receipt.length());
        for (int i = 0; i < receipt.length(); i++) {
            char c = receipt.charAt(i);
            if (c != '\r' && c != '\n' && c != ' ' && c != '\t') {
                stripped.append(c);
            }
        }
        if (stripped.length() == 0) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is empty or whitespace-only");
        }

        // Split into the data run and the (optional, trailing-only) padding
        // run, mapping base64url characters onto their standard twins as we
        // go and remembering which alphabet(s) were used.
        StringBuilder data = new StringBuilder(stripped.length());
        boolean sawStandard = false;
        boolean sawUrlSafe = false;
        int padStart = stripped.length();
        for (int i = 0; i < stripped.length(); i++) {
            char c = stripped.charAt(i);
            if (c == '=') {
                padStart = i;
                break;
            } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                data.append(c);
            } else if (c == '+' || c == '/') {
                sawStandard = true;
                data.append(c);
            } else if (c == '-' || c == '_') {
                sawUrlSafe = true;
                data.append(c == '-' ? '+' : '/');
            } else {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT, "receipt has an invalid base64 character: '" + c + "'");
            }
        }
        for (int i = padStart; i < stripped.length(); i++) {
            if (stripped.charAt(i) != '=') {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT, "receipt has a character after base64 padding");
            }
        }
        if (sawStandard && sawUrlSafe) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "receipt mixes the standard and base64url alphabets");
        }
        if (data.length() == 0) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt has no base64 data");
        }
        if (data.length() % 4 == 1) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt has an invalid base64 length");
        }

        // Padding is not trusted from the input (it may be present, absent,
        // or — since only its trailing-run shape was checked above — of a
        // count that does not match the data length); it is recomputed
        // canonically instead, so java.util.Base64's strict decoder always
        // sees a well-formed standard-alphabet string.
        int remainder = data.length() % 4;
        if (remainder == 2) {
            data.append("==");
        } else if (remainder == 3) {
            data.append("=");
        }
        try {
            return Base64.getDecoder().decode(data.toString());
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is not valid base64", e);
        }
    }
}
