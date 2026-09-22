package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

/**
 * Writes the receipt that carries the four legacy attributes this library
 * used to leave in {@code unknownAttributes} into {@code fixtures/generated/}:
 * app-level 1 (app item id, echoed as {@code adam_id} and {@code app_item_id}),
 * 15 ({@code download_id}) and 16 ({@code version_external_identifier}), and
 * in-app 1713 ({@code is_trial_period}).
 *
 * <p>None of the four is on Apple's archived "Receipt Fields" chapter. They
 * were established by decoding a genuine production receipt and lining its
 * attributes up against the answer Apple's verifyReceipt endpoint gives for
 * the same receipt (measured 2026-09-21).</p>
 *
 * <p>The two in-app purchases carry 1713 on both sides of the boolean, so a
 * port cannot pass by rendering one constant: the consumable is 0 and the
 * subscription is 1, which the endpoint answers as the strings "false" and
 * "true". The three app-level ids are distinct, distinctly sized numbers, so
 * a port that crossed two of them fails rather than coincides.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.ReceiptIdsFixture \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of the
 * receipt and the {@code contentSha256} that records it. The root is emitted
 * beside it — this generator cannot borrow {@code receipt-root.der}, whose
 * private key was deliberately not kept — and the private keys are not kept
 * here either.</p>
 */
public final class ReceiptIdsFixture {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other receipt generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    // Made-up ids, chosen at three different widths so no two can be
    // confused for one another in a port's output.
    private static final long APP_ITEM_ID = 1234567890L;

    /**
     * 2^63 - 1: a nineteen-digit, eight-byte integer that an IEEE-754 double
     * rounds to 2^63, so a port that carries receipt integers as a
     * JavaScript number answers 9223372036854775808 here, or refuses the
     * receipt. Apple's real {@code download_id} values run to eighteen
     * digits, so the exact digits are the contract rather than an edge case.
     */
    private static final long DOWNLOAD_ID = 9223372036854775807L;

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

    private ReceiptIdsFixture() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        TestPki pki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "receipt-ids-root.der", pki.root.getEncoded());

        byte[] payload = TestPki.receiptPayload(
                "Production",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Arrays.asList(
                        TestPki.inAppPurchase(
                                1,
                                BUNDLE + ".coins100",
                                "70000000000011",
                                "70000000000011",
                                "2024-01-15T12:00:00Z",
                                null,
                                Arrays.asList(integerAttribute(1713, 0L))),
                        TestPki.inAppPurchase(
                                1,
                                BUNDLE + ".vip",
                                "70000000000012",
                                "70000000000012",
                                "2024-02-01T09:30:00Z",
                                "2030-02-01T09:30:00Z",
                                Arrays.asList(integerAttribute(1713, 1L)))),
                true,
                null,
                new byte[] {1, 2, 3},
                Arrays.asList(
                        integerAttribute(1, APP_ITEM_ID),
                        integerAttribute(15, DOWNLOAD_ID),
                        integerAttribute(16, VERSION_EXTERNAL_IDENTIFIER)));

        write(out, "receipt-ids.der", pki.signReceipt(payload, new Date(SIGNED_DATE)));
    }

    /** One receipt attribute whose value is the DER of {@code value}. */
    private static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
