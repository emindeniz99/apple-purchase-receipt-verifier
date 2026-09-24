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
import org.bouncycastle.asn1.DERSequence;

/**
 * Writes the receipts that pin the legacy verification order into
 * {@code fixtures/generated/}: only the creation date is read before trust
 * is established, the chain is judged at "now" whenever that date is not
 * usable, and content that cannot be read after the chain and the signature
 * passed is {@code INTERNAL_ERROR}.
 *
 * <p>Three PKIs, all minted here:</p>
 * <ul>
 *   <li>the trusted one, valid 2024-01-01 to 2050-01-01, emitted as
 *       {@code verification-order-root.der}. "Now" falls inside it until
 *       2050, which is what makes the "judged at now" vectors
 *       deterministic;</li>
 *   <li>a foreign one with the same subjects and window, never trusted;</li>
 *   <li>a trusted one that expired: valid 2020-01-01 to 2021-01-01, emitted as
 *       {@code verification-order-expired-root.der}. Every creation date
 *       these receipts state lies inside that window, so a port that took
 *       one of them as the chain instant would accept; judged at now, the
 *       chain has expired.</li>
 * </ul>
 *
 * <p>A {@code main} rather than a {@code @Test}, like the other generators.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.VerificationOrderFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files. The private keys are not kept.</p>
 */
public final class VerificationOrderFixtures {

    private static final String BUNDLE = "com.example.app";

    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long OLD_NOT_BEFORE = 1577836800000L; // 2020-01-01
    private static final long OLD_NOT_AFTER = 1609459200000L; // 2021-01-01

    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String OLD_CREATION_DATE = "2020-06-01T00:00:00Z";
    private static final long OLD_SIGNED_DATE = 1590969600000L; // 2020-06-01

    /** Not RFC 3339, so the creation date cannot be read. */
    private static final String UNREADABLE_DATE = "not-a-date";

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

    private VerificationOrderFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.generated();
        Files.createDirectories(out);

        TestPki trusted = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        TestPki foreign = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        TestPki expired = TestPki.receipt(new Date(OLD_NOT_BEFORE), new Date(OLD_NOT_AFTER));
        write(out, "verification-order-root.der", trusted.root.getEncoded());
        write(out, "verification-order-expired-root.der", expired.root.getEncoded());

        // (a) The creation date is unreadable, so the chain is judged at now.
        // Under the trusted chain that passes, the signature passes, and the
        // full parse then fails on the same date: INTERNAL_ERROR.
        byte[] unreadableDate = payload(CREATION_DATE, date(UNREADABLE_DATE));
        write(out, "receipt-unreadable-creation-date.der", trusted.signReceipt(unreadableDate, new Date(SIGNED_DATE)));

        // (b) The same payload under a chain nobody trusts: the chain answers
        // first, and the unreadable date cannot turn that into a format error.
        write(
                out,
                "receipt-unreadable-creation-date-foreign-chain.der",
                foreign.signReceipt(unreadableDate, new Date(SIGNED_DATE)));

        // (a') The same unreadable date under the chain that expired in 2021:
        // judged at now, the chain is expired, so INVALID_CHAIN. Proves the
        // fallback instant is now rather than no validity check at all.
        write(
                out,
                "receipt-unreadable-creation-date-expired-chain.der",
                expired.signReceipt(payload(OLD_CREATION_DATE, date(UNREADABLE_DATE)), new Date(OLD_SIGNED_DATE)));

        // (c) A readable creation date and an in-app purchase whose value is
        // not an attribute SET. Everything before step 5 passes.
        byte[] garbageInApp =
                payload(CREATION_DATE, date(CREATION_DATE), TestPki.attribute(17, new byte[] {0x04, 0x02, 0x13, 0x37}));
        write(out, "receipt-garbage-in-app-purchase.der", trusted.signReceipt(garbageInApp, new Date(SIGNED_DATE)));

        // (d) Attribute 12 twice, both inside the expired chain's window.
        // Two dates are no usable date: judged at now, INVALID_CHAIN. A port
        // that took either one would accept.
        write(
                out,
                "receipt-creation-date-twice-expired-chain.der",
                expired.signReceipt(
                        payload(OLD_CREATION_DATE, date(OLD_CREATION_DATE), date(OLD_CREATION_DATE)),
                        new Date(OLD_SIGNED_DATE)));

        // (e) A readable creation date beside a top-level entry that is not
        // SEQUENCE { INTEGER, INTEGER, OCTET STRING }. The walk fails as a
        // whole, so the date is not used: judged at now.
        ASN1Encodable brokenEntry = new DERSequence(new ASN1Integer(7));
        write(
                out,
                "receipt-unreadable-entry-expired-chain.der",
                expired.signReceipt(
                        payload(OLD_CREATION_DATE, date(OLD_CREATION_DATE), brokenEntry), new Date(OLD_SIGNED_DATE)));
        write(
                out,
                "receipt-unreadable-entry.der",
                trusted.signReceipt(payload(CREATION_DATE, date(CREATION_DATE), brokenEntry), new Date(SIGNED_DATE)));
    }

    /** Attribute 12 carrying {@code text} as an IA5String. */
    private static ASN1Encodable date(String text) throws Exception {
        return TestPki.attribute(12, new DERIA5String(text).getEncoded());
    }

    /**
     * The standard receipt payload without its own attribute 12, plus
     * {@code extra}. {@code originalPurchaseDate} fills attribute 18, which
     * the standard payload always carries.
     */
    private static byte[] payload(String originalPurchaseDate, ASN1Encodable... extra) throws Exception {
        List<ASN1Encodable> extras = Arrays.asList(extra);
        return TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                originalPurchaseDate,
                Collections.<byte[]>emptyList(),
                false,
                null,
                new byte[0],
                extras);
    }

    private static void write(Path dir, String name, byte[] bytes) throws Exception {
        Files.write(dir.resolve(name), bytes);
    }
}
