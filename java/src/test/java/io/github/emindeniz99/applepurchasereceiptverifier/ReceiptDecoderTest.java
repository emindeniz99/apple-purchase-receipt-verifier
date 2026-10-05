package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

/**
 * The decoder on payloads written here, rather than signed: what a value that
 * does not decode costs. One attribute, never the receipt, so an app server
 * still sees every purchase Apple signed.
 */
class ReceiptDecoderTest {

    /** A UTF8String whose content is not UTF-8: a lead byte, then no continuation. */
    private static final byte[] NOT_UTF8 = {0x0C, 0x02, (byte) 0xC3, 0x28};

    @Test
    void aStringThatIsNotUtf8IsKeptRawTopLevelAndInApp() throws Exception {
        byte[] inApp = set(attribute(1702, NOT_UTF8), attribute(1703, new DERUTF8String("1000").getEncoded()));
        byte[] payload = set(attribute(3, NOT_UTF8), attribute(17, inApp));

        ReceiptPayload receipt = ReceiptDecoder.parse(payload);

        assertNull(receipt.applicationVersion());
        assertArrayEquals(NOT_UTF8, receipt.unknownAttributes().get(3).get(0));
        assertEquals(1, receipt.inApp().size());
        InAppPurchase purchase = receipt.inApp().get(0);
        assertNull(purchase.productId());
        assertArrayEquals(NOT_UTF8, purchase.unknownAttributes().get(1702).get(0));
        // The attribute next to it is untouched.
        assertEquals("1000", purchase.transactionId());
    }

    /** IA5 is seven-bit (owner, 2026-09-27, Q23): a byte from 0x80 up is not read as Latin-1. */
    @Test
    void anIa5StringWithAByteFrom0x80UpIsKeptRaw() throws Exception {
        byte[] notIa5 = {0x16, 0x04, 'c', 'a', 'f', (byte) 0xE9};
        byte[] inApp = set(attribute(1702, notIa5));
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(3, notIa5), attribute(17, inApp)));
        assertNull(receipt.applicationVersion());
        assertArrayEquals(notIa5, receipt.unknownAttributes().get(3).get(0));
        assertNull(receipt.inApp().get(0).productId());
        assertArrayEquals(
                notIa5, receipt.inApp().get(0).unknownAttributes().get(1702).get(0));
        // Seven-bit text, DEL included, still decodes.
        byte[] ascii = {0x16, 0x04, '1', '.', '0', 0x7F};
        assertEquals("1.0\u007f", ReceiptDecoder.parse(set(attribute(3, ascii))).applicationVersion());
    }

    /**
     * BouncyCastle refuses an INTEGER that is not minimally encoded with an
     * unchecked exception; that one attribute is kept raw, as a string that
     * does not decode is, for plain integers and flags alike.
     */
    @Test
    void anIntegerOrFlagThatIsNotMinimallyEncodedIsKeptRaw() throws Exception {
        byte[] padded = {0x02, 0x02, 0x00, 0x01};
        byte[] inApp = set(attribute(1713, padded), attribute(1701, padded));
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(1, padded), attribute(17, inApp)));
        assertNull(receipt.appItemId());
        assertArrayEquals(padded, receipt.unknownAttributes().get(1).get(0));
        InAppPurchase purchase = receipt.inApp().get(0);
        assertNull(purchase.isTrialPeriod());
        assertNull(purchase.quantity());
        assertArrayEquals(padded, purchase.unknownAttributes().get(1713).get(0));
        assertArrayEquals(padded, purchase.unknownAttributes().get(1701).get(0));
    }

    /**
     * An in-app SET that BouncyCastle refuses with an unchecked exception
     * costs that one purchase, kept raw, not the receipt. Here an
     * indefinite-length SET holds a BIT STRING claiming a pad bit with no
     * data byte, which BouncyCastle 1.86 rejects with an
     * IllegalArgumentException that its definite-length path would wrap.
     */
    @Test
    void anInAppSetThatBouncyCastleRefusesUncheckedIsKeptRaw() throws Exception {
        byte[] refused = {0x31, (byte) 0x80, 0x03, 0x01, 0x01, 0x00, 0x00};
        byte[] good = set(attribute(1703, new DERUTF8String("1000").getEncoded()));
        byte[] payload =
                set(attribute(3, new DERUTF8String("1.0").getEncoded()), attribute(17, refused), attribute(17, good));

        ReceiptPayload receipt = ReceiptDecoder.parse(payload);

        assertEquals("1.0", receipt.applicationVersion());
        assertEquals(1, receipt.inApp().size());
        assertEquals("1000", receipt.inApp().get(0).transactionId());
        assertEquals(1, receipt.unknownAttributes().get(17).size());
        assertArrayEquals(refused, receipt.unknownAttributes().get(17).get(0));
    }

    /** The receipt date grammar (owner, 2026-09-27, Q20a), at every edge of it. */
    @Test
    void aReceiptDateIsExactlyTheOneForm() {
        assertEquals(Long.valueOf(1_722_945_600_000L), ReceiptDecoder.parseDate("2024-08-06T12:00:00Z"));
        assertEquals(Long.valueOf(-62_167_219_200_000L), ReceiptDecoder.parseDate("0000-01-01T00:00:00Z"));
        assertEquals(Long.valueOf(253_402_300_799_000L), ReceiptDecoder.parseDate("9999-12-31T23:59:59Z"));
        assertNotNull(ReceiptDecoder.parseDate("2024-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("2000-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("0000-02-29T00:00:00Z"), "0000 is a leap year");
        String[] refused = {
            "2024-08-06t12:00:00Z",
            "2024-08-06T12:00:00z",
            "2024-08-06T12:00:00.000Z",
            "2024-08-06T12:00:00.5Z",
            "2024-08-06T12:00:00+00:00",
            "2024-08-06T12:00:00-07:00",
            "2024-08-06T12:00:00",
            "2024-08-06T12:00:60Z",
            "2024-08-06T12:60:00Z",
            "2024-08-06T24:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-00-06T12:00:00Z",
            "2024-13-06T12:00:00Z",
            "2024-08-00T12:00:00Z",
            "10000-01-01T00:00:00Z",
            "+2024-08-06T12:00:00Z",
            "+12024-08-06T12:00:00Z",
            "-0001-08-06T12:00:00Z",
            "2024-08-06 12:00:00Z",
            " 2024-08-06T12:00:00Z",
            "2024-08-06T12:00:00Z ",
            "2024-8-06T12:00:00Z",
            "2024-08-06T12:00:0\u0661Z",
            "",
        };
        for (String text : refused) {
            assertNull(ReceiptDecoder.parseDate(text), text);
        }
    }

    /** A date in any other form is kept raw, and does not set the chain instant either. */
    @Test
    void aDateInAnyOtherFormIsKeptRawAndDoesNotSetTheChainInstant() throws Exception {
        byte[] exact = new DERIA5String("2024-08-06T12:00:00Z").getEncoded();
        assertEquals(
                Long.valueOf(1_722_945_600_000L),
                ReceiptDecoder.parse(set(attribute(12, exact))).receiptCreationDateMs());
        for (String text : new String[] {"2024-08-06T12:00:00.000Z", "2024-08-06T12:00:00+00:00"}) {
            byte[] value = new DERIA5String(text).getEncoded();
            byte[] payload = set(attribute(12, value));
            ReceiptPayload receipt = ReceiptDecoder.parse(payload);
            assertNull(receipt.receiptCreationDateMs(), text);
            assertArrayEquals(value, receipt.unknownAttributes().get(12).get(0));
            assertNull(ReceiptDecoder.readTopLevel(payload).creationDate(), text);
        }
    }

    /**
     * The nesting bound is BouncyCastle's (64 by default; owner,
     * 2026-10-01). Past it the parser throws an IOException, which the
     * envelope maps to MALFORMED and signed content to UNREADABLE_PAYLOAD,
     * as for any other defect there, never an uncaught error.
     */
    @Test
    void asn1NestedPastBouncyCastlesBoundIsRefusedAsADefect() throws Exception {
        byte[] tooDeep = nestedSets(100);
        assertThrows(java.io.IOException.class, () -> ASN1Primitive.fromByteArray(tooDeep));
        VerificationException envelope = assertThrows(
                VerificationException.class,
                () -> ReceiptCore.verifyDer(tooDeep, Collections.<TrustAnchor>emptySet(), System.currentTimeMillis()));
        assertEquals(Reason.MALFORMED, envelope.reason());
        VerificationException content = assertThrows(VerificationException.class, () -> ReceiptDecoder.parse(tooDeep));
        assertEquals(Reason.UNREADABLE_PAYLOAD, content.reason());
    }

    /**
     * An attribute value is parsed on its own, and the creation date before
     * any signature, so a value is held to the same bound: one nested past
     * it is kept raw, and as a creation date it is no date.
     */
    @Test
    void anAttributeValueNestedPastTheBoundIsKeptRawAndIsNoCreationDate() throws Exception {
        byte[] tooDeep = nestedSets(100);
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(3, tooDeep), attribute(1, tooDeep)));
        assertNull(receipt.applicationVersion());
        assertNull(receipt.appItemId());
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(3).get(0));
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(1).get(0));
        assertNull(ReceiptDecoder.readTopLevel(set(attribute(12, tooDeep))).creationDate());
    }

    /** {@code levels} SETs inside one another, the innermost empty. */
    private static byte[] nestedSets(int levels) throws Exception {
        DERSet inner = new DERSet();
        for (int i = 1; i < levels; i++) {
            inner = new DERSet(inner);
        }
        return inner.getEncoded();
    }

    private static byte[] attribute(int type, byte[] value) throws Exception {
        return new DERSequence(
                        new ASN1Encodable[] {new ASN1Integer(type), new ASN1Integer(1), new DEROctetString(value)})
                .getEncoded();
    }

    private static byte[] set(byte[]... attributes) throws Exception {
        ASN1Encodable[] elements = new ASN1Encodable[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            elements[i] = DERSequence.getInstance(attributes[i]);
        }
        return new DERSet(elements).getEncoded();
    }
}
