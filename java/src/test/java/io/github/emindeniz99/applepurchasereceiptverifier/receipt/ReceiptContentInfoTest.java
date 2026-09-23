package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptVerifier#contentInfo} builds the CMS from the tree the
 * trailing-bytes check already parsed, instead of letting
 * {@code new CMSSignedData(byte[])} parse the whole receipt a second time. If
 * it ever built, rejected or explained a rejection differently from that
 * constructor, a hostile receipt could get a different verdict or message. So
 * the two are compared on every receipt fixture and on seeded corruptions of
 * them: truncations, bit flips, appended bytes and overwritten length octets.
 */
class ReceiptContentInfoTest {

    private static final long SEED = 0xDE_7L;
    private static final int MUTATIONS_PER_FIXTURE = 200;

    @Test
    void buildsTheSameCmsAsTheByteArrayConstructor() throws IOException {
        int built = 0;
        int refused = 0;
        for (byte[] input : corpus()) {
            ASN1Primitive tree;
            try {
                tree = ASN1Primitive.fromByteArray(input);
            } catch (Exception e) {
                // Refused before the CMS is built, on either path.
                continue;
            }
            String expected = cmsOutcome(() -> new CMSSignedData(input));
            String actual = cmsOutcome(() -> new CMSSignedData(ReceiptVerifier.contentInfo(tree)));
            assertEquals(expected, actual, "CMS outcome differs for " + hex(input));
            if (expected.startsWith("ok ")) {
                built++;
            } else {
                refused++;
            }
        }
        assertTrue(built > 100, "built only " + built);
        assertTrue(refused > 100, "refused only " + refused);
    }

    private interface CmsBuild {
        CMSSignedData build() throws Exception;
    }

    private static String cmsOutcome(CmsBuild build) {
        try {
            return "ok " + Base64.getEncoder().encodeToString(build.build().getEncoded());
        } catch (Exception e) {
            return describe(e);
        }
    }

    private static String describe(Throwable e) {
        if (e == null) {
            return "no error";
        }
        StringBuilder out = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            out.append(t.getClass().getName()).append(": ");
            // HotSpot replaces an implicit exception it has thrown often from
            // compiled code with a preallocated one that has no message
            // (OmitStackTraceInFastThrow), so the same input can carry the
            // message on one path and null on the other depending only on
            // JIT state. The class still has to match.
            if (!isJvmImplicit(t)) {
                out.append(t.getMessage());
            }
            out.append(" <- ");
        }
        return out.toString();
    }

    private static boolean isJvmImplicit(Throwable t) {
        return t instanceof ClassCastException
                || t instanceof NullPointerException
                || t instanceof ArrayIndexOutOfBoundsException
                || t instanceof ArithmeticException
                || t instanceof ArrayStoreException;
    }

    /** Every receipt fixture, and seeded corruptions of each. */
    static List<byte[]> corpus() throws IOException {
        List<byte[]> fixtures = new ArrayList<byte[]>();
        Path generated = Paths.get("..", "fixtures", "generated");
        DirectoryStream<Path> files = Files.newDirectoryStream(generated, "receipt*.der");
        try {
            for (Path file : files) {
                fixtures.add(Files.readAllBytes(file));
            }
        } finally {
            files.close();
        }
        Path publicReceipts = Paths.get("..", "fixtures", "public-receipts");
        for (String name :
                new String[] {"receipt-sandbox-g5.b64", "receipt-sandbox-legacy.b64", "receipt-xcode-with-purchases.b64"
                }) {
            String text = new String(Files.readAllBytes(publicReceipts.resolve(name)), StandardCharsets.US_ASCII);
            fixtures.add(Base64.getMimeDecoder().decode(text));
        }
        assertTrue(fixtures.size() > 30, "found only " + fixtures.size() + " receipt fixtures");

        Random random = new Random(SEED);
        List<byte[]> corpus = new ArrayList<byte[]>(fixtures);
        for (byte[] fixture : fixtures) {
            for (int i = 0; i < MUTATIONS_PER_FIXTURE; i++) {
                corpus.add(mutate(fixture, random));
            }
        }
        corpus.add(new byte[0]);
        corpus.add(new byte[] {0});
        corpus.add(new byte[] {0, 0});
        corpus.add(new byte[] {0x30, (byte) 0x80, 0, 0});
        corpus.add(new byte[] {0x04, (byte) 0x80, 0, 0});
        corpus.add(new byte[] {0x30, (byte) 0x85, 1, 1, 1, 1, 1});
        return corpus;
    }

    private static byte[] mutate(byte[] fixture, Random random) {
        byte[] out;
        switch (random.nextInt(5)) {
            case 0:
                return Arrays.copyOf(fixture, random.nextInt(fixture.length));
            case 1:
                out = fixture.clone();
                out[random.nextInt(out.length)] ^= (byte) (1 << random.nextInt(8));
                return out;
            case 2:
                out = Arrays.copyOf(fixture, fixture.length + 1 + random.nextInt(3));
                return out;
            case 3:
                // Mostly lands on the tag and length octets near the front,
                // where the structure (not a signature) is decided.
                out = fixture.clone();
                out[random.nextInt(Math.min(out.length, 64))] = (byte) random.nextInt(256);
                return out;
            default:
                out = fixture.clone();
                int at = random.nextInt(out.length);
                out[at] = (byte) (0x80 | random.nextInt(6));
                return out;
        }
    }

    private static String hex(byte[] input) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(input.length, 24); i++) {
            out.append(String.format("%02x", input[i] & 0xff));
        }
        return out + (input.length > 24 ? "... (" + input.length + " bytes)" : "");
    }
}
