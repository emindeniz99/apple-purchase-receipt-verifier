package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
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
            assertNull(ReceiptDecoder.readCreationDate(payload), text);
        }
    }

    /**
     * ASN.1 nests at most {@link Asn1Depth#MAX_DEPTH} constructed values
     * (owner, 2026-09-27, Q24). Beyond it the envelope is MALFORMED and
     * signed content UNREADABLE_PAYLOAD, as for any other defect there.
     */
    @Test
    void asn1NestsAtMost32ConstructedValues() throws Exception {
        assertEquals(32, Asn1Depth.MAX_DEPTH);
        assertFalse(Asn1Depth.exceeded(nestedSets(32)));
        assertTrue(Asn1Depth.exceeded(nestedSets(33)));
        // A primitive inside the innermost constructed value is not one more.
        assertFalse(Asn1Depth.exceeded(nested(32, new ASN1Integer(1)).getEncoded()));
        assertTrue(Asn1Depth.exceeded(nested(33, new ASN1Integer(1)).getEncoded()));
        // Indefinite lengths are counted the same way.
        byte[] indefinite = new byte[33 * 2 + 33 * 2];
        for (int i = 0; i < 33; i++) {
            indefinite[2 * i] = 0x30;
            indefinite[2 * i + 1] = (byte) 0x80;
        }
        assertTrue(Asn1Depth.exceeded(indefinite));
        assertFalse(Asn1Depth.exceeded(java.util.Arrays.copyOfRange(indefinite, 2, indefinite.length - 2)));
        // Why the bound is this library's: BouncyCastle's own is looser (64
        // by default, counted one level fewer), so 33 SETs parse there.
        ASN1Primitive.fromByteArray(nestedSets(33));

        byte[] tooDeep = nestedSets(33);
        VerificationException envelope = assertThrows(
                VerificationException.class,
                () -> ReceiptCore.verifyDer(tooDeep, Collections.<TrustAnchor>emptySet(), System.currentTimeMillis()));
        assertEquals(Reason.MALFORMED, envelope.reason());
        VerificationException content = assertThrows(VerificationException.class, () -> ReceiptDecoder.parse(tooDeep));
        assertEquals(Reason.UNREADABLE_PAYLOAD, content.reason());
    }

    /**
     * An attribute value is parsed on its own, and the creation date before
     * any signature, so a value is held to the same depth bound: one nested
     * past it is kept raw, and as a creation date it is no date.
     */
    @Test
    void anAttributeValueNestedPastTheBoundIsKeptRawAndIsNoCreationDate() throws Exception {
        byte[] tooDeep = nestedSets(33);
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(3, tooDeep), attribute(1, tooDeep)));
        assertNull(receipt.applicationVersion());
        assertNull(receipt.appItemId());
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(3).get(0));
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(1).get(0));
        assertNull(ReceiptDecoder.readCreationDate(set(attribute(12, tooDeep))));
    }

    /**
     * A value's chunks nest at most {@link Asn1Depth#MAX_STRING_NEST}
     * constructed levels, OpenSSL's bound, so every implementation reads
     * six and refuses seven. The value is signed, so the payload is
     * UNREADABLE_PAYLOAD, not the one attribute kept raw; the Xcode wrap is
     * held to the same bound.
     */
    @Test
    void aValueChunkedPastSixConstructedLevelsIsUnreadable() throws Exception {
        byte[] bundle = new DERUTF8String("com.example.app").getEncoded();
        assertEquals(
                "com.example.app",
                ReceiptDecoder.parse(chunkedValueSet(2, bundle, 6)).bundleId());
        VerificationException value =
                assertThrows(VerificationException.class, () -> ReceiptDecoder.parse(chunkedValueSet(2, bundle, 7)));
        assertEquals(Reason.UNREADABLE_PAYLOAD, value.reason());
        // Before any signature it is no creation date: the chain is judged at the clock.
        byte[] date = new DERIA5String("2024-01-15T12:00:00Z").getEncoded();
        assertNotNull(ReceiptDecoder.readCreationDate(chunkedValueSet(12, date, 6)));
        assertNull(ReceiptDecoder.readCreationDate(chunkedValueSet(12, date, 7)));

        byte[] payload = set(attribute(2, bundle));
        assertEquals(
                "com.example.app",
                ReceiptDecoder.parse(TestPki.chunked(payload, 6).getEncoded()).bundleId());
        VerificationException wrap = assertThrows(
                VerificationException.class,
                () -> ReceiptDecoder.parse(TestPki.chunked(payload, 7).getEncoded()));
        assertEquals(Reason.UNREADABLE_PAYLOAD, wrap.reason());

        // Why the bound is this library's: BouncyCastle joins seven levels.
        assertArrayEquals(
                bundle,
                ((ASN1OctetString) ASN1Primitive.fromByteArray(
                                TestPki.chunked(bundle, 7).getEncoded()))
                        .getOctets());
    }

    /**
     * The bound counts constructed levels in either length form, in any
     * universal constructed value but a SEQUENCE or a SET, at any depth:
     * OpenSSL refuses a seventh level wherever it decodes a string, and a
     * string one SEQUENCE deeper is still one it would decode alone.
     */
    @Test
    void constructedStringsNestAtMostSixLevelsAtAnyDepth() throws Exception {
        assertEquals(6, Asn1Depth.MAX_STRING_NEST);
        assertFalse(Asn1Depth.stringNestExceeded(definiteChunks(6)));
        assertTrue(Asn1Depth.stringNestExceeded(definiteChunks(7)));
        assertFalse(
                Asn1Depth.stringNestExceeded(TestPki.chunked(new byte[] {1}, 6).getEncoded()));
        assertTrue(
                Asn1Depth.stringNestExceeded(TestPki.chunked(new byte[] {1}, 7).getEncoded()));
        assertFalse(Asn1Depth.stringNestExceeded(nestedSets(7)));
        // Inside a SEQUENCE, and inside a SET inside that.
        assertTrue(Asn1Depth.stringNestExceeded(new BERSequence(TestPki.chunked(new byte[] {1}, 7)).getEncoded()));
        assertTrue(Asn1Depth.stringNestExceeded(
                new BERSequence(new BERSet(TestPki.chunked(new byte[] {1}, 7))).getEncoded()));
        assertFalse(Asn1Depth.stringNestExceeded(
                new BERSequence(new BERSet(TestPki.chunked(new byte[] {1}, 6))).getEncoded()));
        // A UTCTime counts its chunks the same way: 0x37 is a constructed UTCTime.
        byte[] utcTime = definiteChunks(7);
        utcTime[0] = 0x37;
        assertTrue(Asn1Depth.stringNestExceeded(utcTime));
        // A context-tagged value is no string, so nested ones are not levels.
        byte[] tagged = definiteChunks(7);
        tagged[0] = (byte) 0xA0;
        assertFalse(Asn1Depth.stringNestExceeded(tagged));
    }

    /**
     * A fourth field that is a SEQUENCE holding a string of seven levels is
     * refused, and the signed payload is unreadable; at six levels the
     * attribute reads, the field ignored as ever.
     */
    @Test
    void aFourthFieldHoldingAStringOfSevenLevelsIsUnreadable() throws Exception {
        byte[] bundle = new DERUTF8String("com.example.app").getEncoded();
        assertEquals(
                "com.example.app",
                ReceiptDecoder.parse(fourthFieldSet(
                                bundle,
                                sequence(TestPki.chunked(new byte[] {1}, 6).getEncoded())))
                        .bundleId());
        VerificationException e = assertThrows(
                VerificationException.class,
                () -> ReceiptDecoder.parse(fourthFieldSet(
                        bundle, sequence(TestPki.chunked(new byte[] {1}, 7).getEncoded()))));
        assertEquals(Reason.UNREADABLE_PAYLOAD, e.reason());
    }

    /**
     * BER sends a string of any type in chunks and OpenSSL joins them, so a
     * constructed UTCTime is a UTCTime: it reads when its joined octets are
     * one, and is refused when they are not, as the primitive would be. The
     * joining is Java's, since BouncyCastle builds no constructed UTCTime.
     */
    @Test
    void aConstructedUtcTimeIsReadAsItsJoinedOctets() throws Exception {
        byte[] bundle = new DERUTF8String("com.example.app").getEncoded();
        byte[] time = {
            0x37, 0x11, 0x04, 0x06, '2', '5', '0', '1', '0', '1', 0x04, 0x07, '0', '0', '0', '0', '0', '0', 'Z'
        };
        byte[] definite = fourthFieldSet(bundle, sequence(time));
        assertEquals("com.example.app", ReceiptDecoder.parse(definite).bundleId());
        // Without the join BouncyCastle refuses the payload outright.
        assertThrows(IOException.class, () -> ASN1Primitive.fromByteArray(definite));

        // Twelve joined octets are no UTCTime, constructed or not.
        byte[] shortTime = {
            0x37, 0x10, 0x04, 0x06, '2', '5', '0', '1', '0', '1', 0x04, 0x06, '0', '0', '0', '0', '0', '0'
        };
        VerificationException e = assertThrows(
                VerificationException.class, () -> ReceiptDecoder.parse(fourthFieldSet(bundle, sequence(shortTime))));
        assertEquals(Reason.UNREADABLE_PAYLOAD, e.reason());
    }

    /**
     * The join rewrites only the strings BouncyCastle cannot build and the
     * lengths around them, in either length form; an encoding without one
     * is handed back as it is.
     */
    @Test
    void theJoinRewritesOnlyWhatBouncyCastleCannotBuild() throws Exception {
        byte[] plain = set(attribute(2, new DERUTF8String("com.example.app").getEncoded()));
        assertSame(plain, ConstructedStrings.joined(plain));
        byte[] octets = TestPki.chunked(new byte[] {1, 2}, 3).getEncoded();
        assertSame(octets, ConstructedStrings.joined(octets));

        // SEQUENCE { constructed UTF8String "ab" in two chunks }, definite and indefinite.
        byte[] definite = {0x30, 0x08, 0x2C, 0x06, 0x04, 0x01, 'a', 0x04, 0x01, 'b'};
        assertArrayEquals(new byte[] {0x30, 0x04, 0x0C, 0x02, 'a', 'b'}, ConstructedStrings.joined(definite));
        byte[] indefinite = {0x30, (byte) 0x80, 0x2C, (byte) 0x80, 0x04, 0x01, 'a', 0x04, 0x01, 'b', 0, 0, 0, 0};
        assertArrayEquals(
                new byte[] {0x30, (byte) 0x80, 0x0C, 0x02, 'a', 'b', 0, 0}, ConstructedStrings.joined(indefinite));
        // A string with no chunks keeps its size and is still rewritten.
        assertArrayEquals(
                new byte[] {0x30, 0x02, 0x0C, 0x00}, ConstructedStrings.joined(new byte[] {0x30, 0x02, 0x2C, 0x00}));
        // Bytes after the value stay, for BouncyCastle to refuse.
        assertArrayEquals(
                new byte[] {0x0C, 0x01, 'a', 0x05},
                ConstructedStrings.joined(new byte[] {0x2C, 0x03, 0x04, 0x01, 'a', 0x05}));
        // An end-of-contents inside a definite string is left for BouncyCastle, as are types that must be primitive.
        byte[] endOfContents = {0x2C, 0x05, 0x04, 0x01, 'a', 0x00, 0x00};
        assertSame(endOfContents, ConstructedStrings.joined(endOfContents));
        byte[] integer = {0x22, 0x03, 0x02, 0x01, 0x01};
        assertSame(integer, ConstructedStrings.joined(integer));
    }

    /**
     * A value whose length takes more than four octets is kept raw, as 0.7
     * kept it and the payload being DER requires; up to four octets, minimal
     * or not, it is read, as OpenSSL reads it.
     */
    @Test
    void aValueWhoseLengthTakesFiveOctetsIsKeptRaw() throws Exception {
        byte[] fiveString = {0x0C, (byte) 0x85, 0, 0, 0, 0, 0x03, 'a', 'p', 'p'};
        byte[] fiveInteger = {0x02, (byte) 0x85, 0, 0, 0, 0, 0x01, 0x05};
        ReceiptPayload raw = ReceiptDecoder.parse(set(attribute(2, fiveString), attribute(1, fiveInteger)));
        assertNull(raw.bundleId());
        assertArrayEquals(fiveString, raw.bundleIdBytes());
        assertNull(raw.appItemId());
        assertArrayEquals(fiveInteger, raw.unknownAttributes().get(1).get(0));

        byte[] fourString = {0x0C, (byte) 0x84, 0, 0, 0, 0x03, 'a', 'p', 'p'};
        byte[] fourInteger = {0x02, (byte) 0x84, 0, 0, 0, 0x01, 0x05};
        ReceiptPayload read = ReceiptDecoder.parse(set(attribute(2, fourString), attribute(1, fourInteger)));
        assertEquals("app", read.bundleId());
        assertEquals(5L, read.appItemId());

        // Why the rule is this library's: BouncyCastle reads the five-octet form.
        assertEquals("app", ((ASN1String) ASN1Primitive.fromByteArray(fiveString)).getString());
    }

    /** A payload SET of one attribute whose value is {@code value} in {@code levels} constructed levels. */
    private static byte[] chunkedValueSet(int type, byte[] value, int levels) throws Exception {
        return new BERSet(new BERSequence(
                        new ASN1Encodable[] {new ASN1Integer(type), new ASN1Integer(1), TestPki.chunked(value, levels)
                        }))
                .getEncoded();
    }

    /** A one-octet OCTET STRING in {@code levels} constructed levels, every length definite. */
    private static byte[] definiteChunks(int levels) {
        byte[] encoding = {0x04, 0x01, 0x41};
        for (int i = 0; i < levels; i++) {
            byte[] outer = new byte[encoding.length + 2];
            outer[0] = 0x24;
            outer[1] = (byte) encoding.length;
            System.arraycopy(encoding, 0, outer, 2, encoding.length);
            encoding = outer;
        }
        return encoding;
    }

    /**
     * A payload SET of one bundle id attribute carrying {@code fourth}, an
     * encoding BouncyCastle need not be able to parse, as a fourth field.
     */
    private static byte[] fourthFieldSet(byte[] bundle, byte[] fourth) throws Exception {
        byte[] fields = concat(
                new ASN1Integer(2).getEncoded(),
                new ASN1Integer(1).getEncoded(),
                new DEROctetString(bundle).getEncoded(),
                fourth);
        return tlv(0x31, tlv(0x30, fields));
    }

    /** A SEQUENCE holding {@code content} as it is. */
    private static byte[] sequence(byte[] content) {
        return tlv(0x30, content);
    }

    /** One value of tag {@code tag} and content {@code content}, its length in short or one-octet long form. */
    private static byte[] tlv(int tag, byte[] content) {
        int head = content.length < 0x80 ? 2 : 3;
        byte[] value = new byte[head + content.length];
        value[0] = (byte) tag;
        if (head == 2) {
            value[1] = (byte) content.length;
        } else {
            value[1] = (byte) 0x81;
            value[2] = (byte) content.length;
        }
        System.arraycopy(content, 0, value, head, content.length);
        return value;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    /** {@code levels} SETs inside one another, the innermost empty. */
    private static byte[] nestedSets(int levels) throws Exception {
        return nested(levels, null).getEncoded();
    }

    /** {@code levels} SETs inside one another, the innermost holding {@code leaf} when there is one. */
    private static DERSet nested(int levels, ASN1Encodable leaf) {
        DERSet inner = leaf == null ? new DERSet() : new DERSet(leaf);
        for (int i = 1; i < levels; i++) {
            inner = new DERSet(inner);
        }
        return inner;
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
