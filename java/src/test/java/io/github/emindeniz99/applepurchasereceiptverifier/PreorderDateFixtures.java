package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Writes the inputs of the shared cases for receipt attribute 32, the
 * pre-order date, and for the receipt that carries no attribute 15 (download
 * id), into the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code preorder-},
 * and {@code preorder-receipt-root.der} is the root they chain to.
 *
 * <p>Attribute 32 is an IA5String holding an RFC 3339 date, like attributes
 * 12 and 18, and sits at the receipt level. The core and the BouncyCastle
 * implementation answer it as {@code preorder_date_ms} in the receipt JSON
 * and as Apple's {@code preorder_date} triplet at the endpoint; Apple's
 * answer also writes {@code "download_id": null} when attribute 15 is
 * missing. Both were compared against production receipts and Apple's
 * verifyReceipt answers on 2026-10-07; those receipts are not committed, and
 * nothing here is derived from one: every value is made up.</p>
 *
 * <ul>
 *   <li>{@code preorder-receipt-with-date.der} carries 15 and a well-formed
 *       32, so a port that crossed the two fails rather than coincides.</li>
 *   <li>{@code preorder-receipt-without-download-id.der} carries 1 and 16
 *       but neither 15 nor 32.</li>
 *   <li>{@code preorder-receipt-bad-date.der} carries a 32 that is not an
 *       RFC 3339 date-time (a space where the {@code T} goes), which is kept
 *       raw as a bad attribute 18 is.</li>
 * </ul>
 *
 * <p>A {@code main} rather than a {@code @Test}, like the other generators.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.PreorderDateFixtures \
 *      fixtures/generated-0.7
 * node tools/lint-cases.mjs   # every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte and every
 * {@code contentSha256} that records one.</p>
 */
public final class PreorderDateFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other receipt generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    /** A made-up pre-order date, 2024-07-02T09:45:20Z (1719913520000 ms). */
    private static final String PREORDER_DATE = "2024-07-02T09:45:20Z";

    /** Not RFC 3339: a space where the T goes. */
    private static final String PREORDER_DATE_NOT_RFC3339 = "2024-07-02 09:45:20Z";

    // Made-up ids at distinct widths.
    private static final long DOWNLOAD_ID = 123456789012345678L;
    private static final long APP_ITEM_ID = 1234567890L;
    private static final long VERSION_EXTERNAL_IDENTIFIER = 456789012L;

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

    private PreorderDateFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);

        TestPki pki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "preorder-receipt-root.der", pki.root.getEncoded());

        write(
                out,
                "preorder-receipt-with-date.der",
                sign(pki, Arrays.asList(integerAttribute(15, DOWNLOAD_ID), TestPki.attribute(32, ia5(PREORDER_DATE)))));
        write(
                out,
                "preorder-receipt-without-download-id.der",
                sign(
                        pki,
                        Arrays.asList(
                                integerAttribute(1, APP_ITEM_ID), integerAttribute(16, VERSION_EXTERNAL_IDENTIFIER))));
        write(
                out,
                "preorder-receipt-bad-date.der",
                sign(
                        pki,
                        Arrays.asList(
                                integerAttribute(15, DOWNLOAD_ID),
                                TestPki.attribute(32, ia5(PREORDER_DATE_NOT_RFC3339)))));
    }

    /** One consumable purchase and the given receipt-level attributes after it. */
    private static byte[] sign(TestPki pki, List<ASN1Encodable> extras) throws Exception {
        byte[] payload = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Collections.singletonList(TestPki.inAppPurchase(
                        1, BUNDLE + ".coins100", "70000000000401", "70000000000401", "2024-01-15T12:00:00Z", null)),
                true,
                null,
                new byte[] {1, 2, 3},
                extras);
        return pki.signReceipt(payload, new Date(SIGNED_DATE));
    }

    private static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }

    private static byte[] ia5(String text) throws Exception {
        return new DERIA5String(text).getEncoded();
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
