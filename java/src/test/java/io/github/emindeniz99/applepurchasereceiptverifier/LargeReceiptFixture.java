package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Writes the receipt that pins the contract's normative resource floor into
 * {@code fixtures/generated/} (ROADMAP "Before 1.0" item 1): a well-formed,
 * correctly signed legacy receipt sitting just under 1 MiB of DER and just
 * under a 20,000-node ASN.1 parse, which every port must accept.
 *
 * <p>The size comes from in-app purchases and nothing else — no padding
 * attribute, no inflated value — because a port's budgets are spent on the
 * shape a real receipt has, and a receipt that got large some other way would
 * not tell us whether a large REAL one is accepted. {@link #IN_APP_PURCHASES}
 * is 4,000: 21× the largest genuine receipt in the corpus (187 purchases in
 * 79 KB), and it lands the receipt at 809,069 bytes against the smallest byte
 * cap any port carries (Go's 1 MiB) and the payload's attribute set at 16,037
 * nodes against the smallest node budget any port carries (PHP's 20,000).
 * Both sit close enough to the floor to prove it and far enough from it that
 * a port counting a node or a wrapper differently still passes.</p>
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

    /** See the class javadoc for why this number and not a rounder one. */
    private static final int IN_APP_PURCHASES = 4000;

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

        List<byte[]> inApps = new ArrayList<byte[]>(IN_APP_PURCHASES);
        for (int i = 0; i < IN_APP_PURCHASES; i++) {
            // Ids are unique per purchase, as a real receipt's are, so no port
            // can collapse them and report a smaller collection.
            String transactionId = String.valueOf(70000000000000L + i);
            inApps.add(TestPki.inAppPurchase(
                    1,
                    BUNDLE + ".coins" + i,
                    transactionId,
                    transactionId,
                    "2024-01-15T12:00:00Z",
                    i == IN_APP_PURCHASES - 1 ? "2030-02-01T09:30:00Z" : null));
        }
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", OPAQUE, TestPki.deviceHash(GUID, OPAQUE, BUNDLE), CREATION_DATE, inApps);
        System.out.println("payload " + payload.length + " bytes, " + nodes(payload) + " nodes");
        write(out, "receipt-large.der", pki.signReceipt(payload, new Date(SIGNED_DATE)));
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
