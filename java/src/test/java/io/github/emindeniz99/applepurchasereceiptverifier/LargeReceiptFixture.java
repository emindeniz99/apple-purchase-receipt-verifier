package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Writes the two receipts that pin the contract's normative resource floor
 * into {@code fixtures/generated/} (ROADMAP "Before 1.0" item 1). The floor
 * has two numbers — 1,048,576 bytes of DER and 20,000 nodes in any single
 * ASN.1 parse — and one receipt cannot pin both: sitting under both at once
 * leaves a port free to lower either cap to just above whatever that one
 * receipt happens to use. So there is one receipt per number, each within 2%
 * of the limit it pins and each well clear of the other.
 *
 * <p><b>receipt-byte-floor</b> is 2,300 in-app purchases whose product ids
 * are padded out to {@link #PRODUCT_ID_LENGTH} characters: the bytes go into
 * the value of a MODELLED attribute, so a port has to decode and return every
 * one of them — none of this is filler a parser may skip. Its payload holds
 * about 9,200 nodes, under half the node budget, so accepting it says
 * something about bytes alone.
 *
 * <p><b>receipt-node-floor</b> is a small receipt with a real handful of
 * in-app purchases and {@link #NODE_FLOOR_ATTRIBUTES} further attributes of
 * three bytes each, carrying types this library does not model. That is what
 * makes it 60 KB rather than 700 KB, and it is the honest shape for this
 * number: a node budget is spent per TLV walked, whatever the TLV means, and
 * an attribute the library does not model is still walked, still counted and
 * still recorded under {@code unknownAttributes}. Building the same node
 * count out of in-app purchases would cost a megabyte of repository for a
 * fixture whose whole subject is the count.
 *
 * <p>Both receipts are well-formed and correctly signed, and both MUST be
 * accepted. {@link #main} checks each lands inside its band before writing,
 * so a regeneration cannot quietly drift off the boundary it exists to hold.
 *
 * <p>Same technique as {@link PortDivergenceFixtures} and a {@code main} for
 * the same reason. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.LargeReceiptFixture \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 */
public final class LargeReceiptFixture {

    private static final String BUNDLE = "com.example.app";
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    /** The floor itself: what every port must accept. */
    private static final int BYTE_FLOOR = 1024 * 1024;

    private static final int NODE_FLOOR = 20000;

    /** Each receipt must land within 2% below the number it pins. */
    private static final double BAND = 0.02;

    /** Tuned to land receipt-byte-floor inside the band; see main. */
    private static final int BYTE_FLOOR_PURCHASES = 2300;

    private static final int PRODUCT_ID_LENGTH = 262;

    /** Tuned the same way, for the node count of the payload attribute set. */
    private static final int NODE_FLOOR_PURCHASES = 10;

    private static final int NODE_FLOOR_ATTRIBUTES = 4955;

    /**
     * The first unknown attribute type the node-floor receipt uses. Above
     * every type any port models, and low enough that all of them encode in
     * two INTEGER octets, so the receipt stays as small as it can be.
     */
    private static final int UNKNOWN_TYPE_BASE = 20000;

    private static final byte[] GUID = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        (byte) 0x88,
        (byte) 0x99,
        (byte) 0xaa,
        (byte) 0xbb,
        (byte) 0xcc,
        (byte) 0xdd,
        (byte) 0xee,
        (byte) 0xff,
        0x00
    };
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private LargeReceiptFixture() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        TestPki pki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "large-receipt-root.der", pki.root.getEncoded());

        writeByteFloor(out, pki);
        writeNodeFloor(out, pki);
    }

    /** Near 1 MiB of DER, at well under half the node budget. */
    private static void writeByteFloor(Path out, TestPki pki) throws Exception {
        List<byte[]> inApps = new ArrayList<byte[]>(BYTE_FLOOR_PURCHASES);
        for (int i = 0; i < BYTE_FLOOR_PURCHASES; i++) {
            // Ids are unique per purchase, as a real receipt's are, so no port
            // can collapse them and report a smaller collection. The first and
            // last keep a short product id so a case can select them by it;
            // every other product id is padded, which is where the bytes are.
            String transactionId = String.valueOf(70000000000000L + i);
            boolean selectable = i == 0 || i == BYTE_FLOOR_PURCHASES - 1;
            inApps.add(TestPki.inAppPurchase(
                    1,
                    selectable ? BUNDLE + ".coins" + i : pad(BUNDLE + ".coins" + i),
                    transactionId,
                    transactionId,
                    "2024-01-15T12:00:00Z",
                    i == BYTE_FLOOR_PURCHASES - 1 ? "2030-02-01T09:30:00Z" : null));
        }
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", OPAQUE, TestPki.deviceHash(GUID, OPAQUE, BUNDLE), CREATION_DATE, inApps);
        byte[] receipt = pki.signReceipt(payload, new Date(SIGNED_DATE));
        int nodes = nodes(payload);
        System.out.println("byte-floor payload " + payload.length + " bytes, " + nodes + " nodes");
        requireInBand("receipt-byte-floor bytes", receipt.length, BYTE_FLOOR);
        requireBelow("receipt-byte-floor nodes", nodes, NODE_FLOOR / 2);
        write(out, "receipt-byte-floor.der", receipt);
    }

    /** Near 20,000 nodes in one parse, at a small fraction of the byte floor. */
    private static void writeNodeFloor(Path out, TestPki pki) throws Exception {
        List<byte[]> inApps = new ArrayList<byte[]>(NODE_FLOOR_PURCHASES);
        for (int i = 0; i < NODE_FLOOR_PURCHASES; i++) {
            String transactionId = String.valueOf(80000000000000L + i);
            inApps.add(TestPki.inAppPurchase(
                    1, BUNDLE + ".coins" + i, transactionId, transactionId, "2024-01-15T12:00:00Z", null));
        }
        List<ASN1Encodable> extras = new ArrayList<ASN1Encodable>(NODE_FLOOR_ATTRIBUTES);
        for (int i = 0; i < NODE_FLOOR_ATTRIBUTES; i++) {
            // Each is four nodes — the SEQUENCE and its three children — and
            // fourteen bytes. Distinct types, so a port keying them by type
            // records every one instead of collapsing them.
            extras.add(TestPki.attribute(UNKNOWN_TYPE_BASE + i, new byte[] {1, 2, 3}));
        }
        byte[] payload = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                inApps,
                true,
                (BigInteger) null,
                null,
                extras);
        byte[] receipt = pki.signReceipt(payload, new Date(SIGNED_DATE));
        int nodes = nodes(payload);
        System.out.println("node-floor payload " + payload.length + " bytes, " + nodes + " nodes");
        requireInBand("receipt-node-floor nodes", nodes, NODE_FLOOR);
        requireBelow("receipt-node-floor bytes", receipt.length, BYTE_FLOOR / 4);
        write(out, "receipt-node-floor.der", receipt);
    }

    /** A product id padded to {@link #PRODUCT_ID_LENGTH} characters. */
    private static String pad(String productId) {
        StringBuilder padded = new StringBuilder(productId);
        while (padded.length() < PRODUCT_ID_LENGTH) {
            padded.append('x');
        }
        return padded.toString();
    }

    /** Inside the band the fixture exists to hold: (1 - BAND) * limit .. limit. */
    private static void requireInBand(String what, int actual, int limit) {
        if (actual > limit || actual < (int) ((1 - BAND) * limit)) {
            throw new IllegalStateException(what + " is " + actual + ", outside the band (" + (int) ((1 - BAND) * limit)
                    + ".." + limit + ") — retune the constants");
        }
    }

    /** Clear of the OTHER floor, so each fixture pins one number alone. */
    private static void requireBelow(String what, int actual, int ceiling) {
        if (actual >= ceiling) {
            throw new IllegalStateException(
                    what + " is " + actual + ", not clear of " + ceiling + " — retune the constants");
        }
    }

    /**
     * The node count the ports' budgets are spent in: one TLV per node,
     * descending into constructed values only — which is what every port that
     * carries a budget does, since a primitive OCTET STRING's contents are a
     * separate parse with a separate budget.
     */
    private static int nodes(byte[] der) {
        return nodes(der, 0, der.length);
    }

    private static int nodes(byte[] der, int from, int to) {
        int count = 0;
        int position = from;
        while (position < to) {
            int tag = der[position] & 0xff;
            int length = der[position + 1] & 0xff;
            int header = 2;
            if (length > 0x80) {
                int octets = length & 0x7f;
                length = 0;
                for (int i = 0; i < octets; i++) {
                    length = (length << 8) | (der[position + 2 + i] & 0xff);
                }
                header = 2 + octets;
            }
            count++;
            if ((tag & 0x20) != 0) {
                count += nodes(der, position + header, position + header + length);
            }
            position += header + length;
        }
        return count;
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
