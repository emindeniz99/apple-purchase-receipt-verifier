package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptBase64#decode} answers what Apple's verifyReceipt answered on
 * 2026-09-23 for the same spellings of genuine receipts
 * (docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple
 * decodes must decode here to the same bytes; a spelling Apple answers 21002
 * must be INVALID_RECEIPT_FORMAT here, or a receipt verifies in this library
 * that Apple itself refuses. The conformance cases pin the same rule on a real
 * receipt; this pins each shape on its own, including the ones where the JDK
 * decoder alone would have said yes.
 */
class ReceiptBase64Test {

    @Test
    void canonicalStandardBase64DecodesForEveryPaddingLength() throws Exception {
        assertArrayEquals(bytes("ABC"), ReceiptBase64.decode("QUJD"));
        assertArrayEquals(bytes("AB"), ReceiptBase64.decode("QUI="));
        assertArrayEquals(bytes("A"), ReceiptBase64.decode("QQ=="));
        assertArrayEquals(new byte[] {(byte) 0xfb, (byte) 0xff}, ReceiptBase64.decode("+/8="));
    }

    /** Apple accepts a last data character whose unused low bits are set, so this port does too. */
    @Test
    void nonCanonicalTrailingBitsAreAccepted() throws Exception {
        assertArrayEquals(bytes("A"), ReceiptBase64.decode("QR=="));
        assertArrayEquals(bytes("A"), ReceiptBase64.decode("Qf=="));
        assertArrayEquals(bytes("AB"), ReceiptBase64.decode("QUJ="));
    }

    /** Every spelling below got 21002 from Apple. */
    @Test
    void everySpellingAppleRefusesIsInvalidReceiptFormat() {
        String[] refused = {
            "", // empty
            "QQ", // padding omitted: Base64.getDecoder() alone accepts it
            "QUI", // padding omitted
            "QQ=", // under-padded
            "QQ===", // one '=' too many
            "QQ====", // two '=' too many
            "QUJD=", // padding after a full group
            "QUJD==",
            "QUJD====",
            "Q===", // impossible length, padded
            "QUJDR", // impossible length, unpadded
            "QQ==QUJD", // data after the padding
            "QQ==!!!!", // junk after the padding
            "QU!D", // junk inside
            "QUJD\n", // a single trailing line feed
            "QUJD\r\n", // a trailing CRLF
            "QUJD\nQUJD", // a line break inside
            " QUJD", // a leading space
            "QU JD", // a space inside
            "QU\tJD", // a tab inside
            "  QUJD  ", // leading and trailing whitespace
            "-_8=", // base64url
            "-_8", // base64url, unpadded
            "+_8=", // both alphabets
            "QUJé", // outside ASCII
        };
        for (String text : refused) {
            VerificationException thrown =
                    assertThrows(VerificationException.class, () -> ReceiptBase64.decode(text), text);
            assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason(), text);
        }
    }

    @Test
    void nullIsInvalidReceiptFormat() {
        VerificationException thrown = assertThrows(VerificationException.class, () -> ReceiptBase64.decode(null));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason());
    }

    private static byte[] bytes(String ascii) {
        return ascii.getBytes(StandardCharsets.US_ASCII);
    }
}
