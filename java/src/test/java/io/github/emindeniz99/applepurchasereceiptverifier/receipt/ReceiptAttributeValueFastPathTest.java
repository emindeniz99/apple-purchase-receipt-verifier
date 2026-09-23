package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptVerifier#decodeString} and {@link ReceiptVerifier#decodeInteger}
 * read the common attribute shapes without BouncyCastle's parser. That is
 * only safe if no value, and no rejection, changes: a value the shortcut
 * decoded differently would be a receipt field that differs from the other
 * ports, and a value it accepted that the parser refuses would let a malformed
 * receipt through. So both are compared with the full parse on every
 * attribute value of the receipt fixtures and on seeded values of every
 * shape: the fast-path tags with right and wrong lengths, long-form and
 * indefinite lengths, other tags, constructed encodings, invalid UTF-8, and
 * non-minimal and negative integers.
 */
class ReceiptAttributeValueFastPathTest {

    private static final long SEED = 0xA77B_5EEDL;
    private static final int GENERATED = 50_000;
    private static final int[] TAGS = {0x02, 0x0C, 0x16, 0x13, 0x1A, 0x1E, 0x04, 0x05, 0x22, 0x2C, 0x36, 0x00, 0xA0};

    @Test
    void decodesEveryValueAsTheFullParseDoes() throws IOException {
        List<byte[]> values = fixtureValues();
        int fromFixtures = values.size();
        Random random = new Random(SEED);
        for (int i = 0; i < GENERATED; i++) {
            values.add(generate(random));
        }
        int shortStrings = 0;
        int shortIntegers = 0;
        int parsed = 0;
        for (byte[] value : values) {
            assertEquals(
                    outcome(() -> ReceiptVerifier.decodeStringParsed(value)),
                    outcome(() -> ReceiptVerifier.decodeString(value)),
                    "decodeString differs for " + hex(value));
            assertEquals(
                    outcome(() -> ReceiptVerifier.decodeIntegerParsed(value)),
                    outcome(() -> ReceiptVerifier.decodeInteger(value)),
                    "decodeInteger differs for " + hex(value));
            if (shortcutReadsString(value)) {
                shortStrings++;
            } else if (ReceiptDer.shortNonNegativeInteger(value) >= 0) {
                shortIntegers++;
            } else {
                parsed++;
            }
        }
        assertTrue(fromFixtures > 3_000, "fixtures gave only " + fromFixtures + " values");
        assertTrue(shortStrings > 5_000, "shortcut decoded only " + shortStrings + " strings");
        assertTrue(shortIntegers > 5_000, "shortcut decoded only " + shortIntegers + " integers");
        assertTrue(parsed > 10_000, "only " + parsed + " values took the full parse");
    }

    private static boolean shortcutReadsString(byte[] value) {
        try {
            return ReceiptDer.shortString(value) != null;
        } catch (IllegalArgumentException e) {
            return true; // invalid UTF-8, refused by the shortcut itself
        }
    }

    private interface Decode {
        Object run() throws VerificationException;
    }

    private static String outcome(Decode decode) {
        try {
            Object value = decode.run();
            return "value " + value.getClass().getName() + " " + value;
        } catch (VerificationException e) {
            return "rejected " + e.reason() + ": " + e.getMessage() + " cause " + describe(e.getCause());
        } catch (RuntimeException e) {
            return "threw " + describe(e);
        }
    }

    private static String describe(Throwable e) {
        StringBuilder out = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            out.append(t.getClass().getName())
                    .append(": ")
                    .append(t.getMessage())
                    .append(" <- ");
        }
        return out.toString();
    }

    /** Every attribute value (top level and in-app) of every receipt fixture. */
    private static List<byte[]> fixtureValues() throws IOException {
        List<byte[]> values = new ArrayList<byte[]>();
        for (byte[] receipt : ReceiptDerTest.corpusFixtures()) {
            byte[] payload;
            try {
                payload = (byte[]) new CMSSignedData(receipt).getSignedContent().getContent();
            } catch (Exception e) {
                continue;
            }
            collect(payload, values, 0);
        }
        return values;
    }

    private static void collect(byte[] set, List<byte[]> values, int depth) {
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(set);
            if (parsed instanceof ASN1OctetString) {
                parsed = ASN1Primitive.fromByteArray(((ASN1OctetString) parsed).getOctets());
            }
        } catch (Exception e) {
            return;
        }
        if (!(parsed instanceof ASN1Set)) {
            return;
        }
        for (ASN1Encodable element : (ASN1Set) parsed) {
            try {
                byte[] value = ASN1OctetString.getInstance(
                                ASN1Sequence.getInstance(element).getObjectAt(2))
                        .getOctets();
                values.add(value);
                if (depth == 0) {
                    collect(value, values, 1);
                }
            } catch (RuntimeException e) {
                // Not an attribute; the verifier rejects it before decoding.
            }
        }
    }

    private static byte[] generate(Random random) {
        int tag = TAGS[random.nextInt(TAGS.length)];
        int length = random.nextInt(4) == 0 ? random.nextInt(140) : random.nextInt(12);
        byte[] content = content(tag, length, random);
        byte[] header;
        switch (random.nextInt(8)) {
            case 0:
                // Long-form length, minimal or not.
                header = new byte[] {(byte) tag, (byte) 0x81, (byte) content.length};
                break;
            case 1:
                header = new byte[] {(byte) tag, (byte) 0x80};
                break;
            case 2:
                // A short-form length that disagrees with the array.
                header = new byte[] {(byte) tag, (byte) ((content.length + 1 + random.nextInt(3)) & 0x7F)};
                break;
            default:
                header = new byte[] {(byte) tag, (byte) content.length};
                break;
        }
        byte[] out = new byte[header.length + content.length + (random.nextInt(10) == 0 ? 1 : 0)];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(content, 0, out, header.length, content.length);
        return random.nextInt(50) == 0 ? new byte[random.nextInt(2)] : out;
    }

    private static byte[] content(int tag, int length, Random random) {
        byte[] content = new byte[length];
        if (tag == 0x02 && length > 0) {
            random.nextBytes(content);
            switch (random.nextInt(4)) {
                case 0:
                    content[0] = 0; // minimal only when the next byte is 0x80 or more
                    break;
                case 1:
                    content[0] = (byte) 0xFF;
                    break;
                case 2:
                    content[0] &= 0x7F;
                    break;
                default:
                    break;
            }
            return content;
        }
        if ((tag == 0x0C || tag == 0x16) && random.nextInt(3) != 0) {
            // Mostly text, sometimes with UTF-8 sequences, valid or broken.
            for (int i = 0; i < length; i++) {
                content[i] = (byte) (0x20 + random.nextInt(0x5F));
            }
            if (length > 1 && random.nextBoolean()) {
                int at = random.nextInt(length - 1);
                content[at] = (byte) (0xC0 | random.nextInt(0x20));
                content[at + 1] = (byte) (random.nextBoolean() ? 0x80 | random.nextInt(0x40) : random.nextInt(0x80));
            }
            return content;
        }
        random.nextBytes(content);
        return content;
    }

    private static String hex(byte[] input) {
        StringBuilder out = new StringBuilder();
        for (byte b : input) {
            out.append(String.format("%02x", b & 0xff));
        }
        return out.toString();
    }
}
