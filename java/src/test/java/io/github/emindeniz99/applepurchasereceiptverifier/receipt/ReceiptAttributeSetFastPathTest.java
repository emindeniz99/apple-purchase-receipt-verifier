package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
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
 * {@link ReceiptDer#simpleAttributes} reads a payload or in-app attribute
 * set without BouncyCastle when it is plain DER. Every field of a receipt
 * comes out of these sets, so the shortcut must never read a set differently
 * from the full parse, and must never accept one the full parse (or
 * {@code Attribute.of}) refuses, or a malformed receipt would verify in Java
 * alone. It is compared with the full parse, element by element up to the
 * first error, on every set in the receipt fixtures, seeded corruptions of
 * them, and generated sets in every shape it hands back to the parser:
 * non-minimal and long-form lengths, indefinite lengths, two and four
 * fields, negative, oversized and non-minimal types, versions that are not
 * minimal INTEGERs, constructed values, trailing bytes and the Xcode double
 * wrap.
 */
class ReceiptAttributeSetFastPathTest {

    private static final long SEED = 0x5E7_5EEDL;
    private static final int MUTATIONS_PER_SET = 20;
    private static final int GENERATED = 20_000;

    @Test
    void readsEverySetAsTheFullParseDoes() throws IOException {
        List<byte[]> sets = fixtureSets();
        int fromFixtures = sets.size();
        Random random = new Random(SEED);
        for (int i = 0; i < fromFixtures; i++) {
            for (int j = 0; j < MUTATIONS_PER_SET; j++) {
                sets.add(mutate(sets.get(i), random));
            }
        }
        for (int i = 0; i < GENERATED; i++) {
            sets.add(generate(random));
        }
        int shortcut = 0;
        int parsedOk = 0;
        int refused = 0;
        for (byte[] set : sets) {
            String expected = outcome(set, false);
            assertEquals(expected, outcome(set, true), "attributes differ for " + hex(set));
            if (ReceiptDer.simpleAttributes(set) != null) {
                shortcut++;
            } else if (expected.endsWith("end")) {
                parsedOk++;
            } else {
                refused++;
            }
        }
        assertTrue(fromFixtures > 300, "fixtures gave only " + fromFixtures + " sets");
        assertTrue(shortcut > 3_000, "shortcut read only " + shortcut);
        assertTrue(parsedOk > 1_000, "full parse read only " + parsedOk);
        assertTrue(refused > 3_000, "refused only " + refused);
    }

    /** The attributes as the payload loop sees them, up to the first error. */
    private static String outcome(byte[] set, boolean withShortcut) {
        StringBuilder out = new StringBuilder();
        try {
            ReceiptVerifier.Attributes attributes = withShortcut
                    ? ReceiptVerifier.attributes(set, "set")
                    : ReceiptVerifier.parsedAttributes(set, "set");
            for (int i = 0; i < attributes.size(); i++) {
                ReceiptVerifier.Attribute attribute = attributes.get(i);
                out.append(attribute.type)
                        .append('=')
                        .append(java.util.Base64.getEncoder().encodeToString(attribute.value))
                        .append(' ');
            }
            return out.append("end").toString();
        } catch (VerificationException e) {
            return out.append("rejected ")
                    .append(e.reason())
                    .append(": ")
                    .append(e.getMessage())
                    .append(" cause ")
                    .append(e.getCause() == null ? null : e.getCause().toString())
                    .toString();
        } catch (RuntimeException e) {
            return out.append("threw ").append(e).toString();
        }
    }

    /** Every payload and in-app set in the receipt fixtures. */
    private static List<byte[]> fixtureSets() throws IOException {
        List<byte[]> sets = new ArrayList<byte[]>();
        for (byte[] receipt : ReceiptDerTest.corpusFixtures()) {
            byte[] payload;
            try {
                payload = (byte[]) new CMSSignedData(receipt).getSignedContent().getContent();
            } catch (Exception e) {
                continue;
            }
            sets.add(payload);
            try {
                ASN1Primitive parsed = ASN1Primitive.fromByteArray(payload);
                if (parsed instanceof ASN1OctetString) {
                    parsed = ASN1Primitive.fromByteArray(((ASN1OctetString) parsed).getOctets());
                }
                for (ASN1Encodable element : (ASN1Set) parsed) {
                    ASN1Sequence attribute = ASN1Sequence.getInstance(element);
                    if (attribute.size() >= 3
                            && ((org.bouncycastle.asn1.ASN1Integer) attribute.getObjectAt(0)).hasValue(17)) {
                        sets.add(((ASN1OctetString) attribute.getObjectAt(2)).getOctets());
                    }
                }
            } catch (Exception e) {
                // A fixture whose payload is deliberately malformed.
            }
        }
        return sets;
    }

    private static byte[] mutate(byte[] set, Random random) {
        if (set.length == 0) {
            return new byte[] {(byte) random.nextInt(256)};
        }
        byte[] out;
        switch (random.nextInt(4)) {
            case 0:
                return Arrays.copyOf(set, random.nextInt(set.length + 1));
            case 1:
                out = set.clone();
                out[random.nextInt(out.length)] ^= (byte) (1 << random.nextInt(8));
                return out;
            case 2:
                return Arrays.copyOf(set, set.length + 1);
            default:
                out = set.clone();
                out[random.nextInt(out.length)] =
                        (byte) new int[] {0x02, 0x04, 0x30, 0x31, 0x24, 0x80, 0x81, 0x00}[random.nextInt(8)];
                return out;
        }
    }

    private static byte[] generate(Random random) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        int count = random.nextInt(6);
        for (int i = 0; i < count; i++) {
            ByteArrayOutputStream fields = new ByteArrayOutputStream();
            int fieldCount = random.nextInt(12) == 0 ? 2 + random.nextInt(2) * 2 : 3;
            for (int f = 0; f < fieldCount; f++) {
                if (f < 2) {
                    int tag = random.nextInt(15) == 0 ? 0x04 : 0x02;
                    write(fields, tag, integer(random), random);
                } else {
                    byte[] value = new byte[random.nextInt(4) == 0 ? 120 + random.nextInt(300) : random.nextInt(8)];
                    random.nextBytes(value);
                    write(fields, random.nextInt(20) == 0 ? 0x24 : 0x04, value, random);
                }
            }
            write(content, 0x30, fields.toByteArray(), random);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, random.nextInt(25) == 0 ? 0x30 : 0x31, content.toByteArray(), random);
        byte[] set = out.toByteArray();
        if (random.nextInt(25) == 0) {
            ByteArrayOutputStream wrapped = new ByteArrayOutputStream();
            write(wrapped, 0x04, set, random);
            set = wrapped.toByteArray();
        }
        if (random.nextInt(25) == 0) {
            set = Arrays.copyOf(set, set.length + 1);
        }
        return set;
    }

    private static byte[] integer(Random random) {
        switch (random.nextInt(8)) {
            case 0:
                return new byte[0];
            case 1:
                return new byte[] {0, (byte) random.nextInt(0x80)}; // non-minimal
            case 2:
                return new byte[] {(byte) (0x80 | random.nextInt(0x80))}; // negative
            case 3:
                return new byte[] {0x7F, 1, 2, 3, 4}; // five octets
            case 4:
                return new byte[] {0, (byte) 0x80, 0, 0}; // minimal, four octets
            default:
                byte[] value = new byte[1 + random.nextInt(3)];
                random.nextBytes(value);
                value[0] &= 0x7F;
                if (value.length > 1 && value[0] == 0) {
                    value[0] = 1;
                }
                return value;
        }
    }

    /** One element, with its length usually minimal and sometimes not. */
    private static void write(ByteArrayOutputStream out, int tag, byte[] content, Random random) {
        out.write(tag);
        int length = content.length;
        switch (random.nextInt(20)) {
            case 0:
                out.write(0x81); // long form even when short would do
                out.write(length & 0xFF);
                break;
            case 1:
                out.write(0x82);
                out.write((length >> 8) & 0xFF);
                out.write(length & 0xFF);
                break;
            case 2:
                if ((tag & 0x20) != 0) {
                    out.write(0x80); // indefinite
                    out.write(content, 0, content.length);
                    out.write(0);
                    out.write(0);
                    return;
                }
            // fall through: primitives cannot be indefinite
            default:
                if (length < 0x80) {
                    out.write(length);
                } else if (length < 0x100) {
                    out.write(0x81);
                    out.write(length);
                } else {
                    out.write(0x82);
                    out.write(length >> 8);
                    out.write(length & 0xFF);
                }
                break;
        }
        out.write(content, 0, content.length);
    }

    private static String hex(byte[] input) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(input.length, 64); i++) {
            out.append(String.format("%02x", input[i] & 0xff));
        }
        return out + (input.length > 64 ? "...(" + input.length + ")" : "");
    }
}
