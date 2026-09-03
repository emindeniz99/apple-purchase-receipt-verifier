package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Writes the fixtures that pin the four cross-port divergences into
 * {@code fixtures/generated/} — the receipt carrying an attribute type above
 * 2^31-1, and the dated-nothing receipts and payloads whose certificate
 * validity therefore falls back to "current time".
 *
 * <p>Same technique as {@link FixtureGeneratorTest}: a fake Apple PKI from
 * {@link TestPki}, fixed epoch instants so nothing depends on generation
 * time, bytes written under {@code fixtures/generated/} and registered in
 * {@code fixtures/cases.json} with the SHA-256 of their decoded content.
 * It is a {@code main} rather than a {@code @Test} for one reason: a
 * generation-gated test is a permanently skipped test, and this suite is
 * meant to run with zero skips. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.PortDivergenceFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. Both roots that
 * anchor these fixtures are emitted alongside them for that reason — the
 * private keys are deliberately not kept, so a fixture can never be
 * re-signed under an already-published root.</p>
 */
public final class PortDivergenceFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants FixtureGeneratorTest uses, so these fixtures
    // sit in the same timeline as the ones they are read beside.
    private static final long SIGNED_DATE = 1722945600000L;          // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long CHAIN_NOT_BEFORE = 1704067200000L;     // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L;      // 2050-01-01
    private static final long OLD_NOT_BEFORE = 1577836800000L;       // 2020-01-01
    private static final long OLD_NOT_AFTER = 1609459200000L;        // 2021-01-01
    private static final long OLD_SIGNED_DATE = 1590969600000L;      // 2020-06-01
    private static final String OLD_CREATION_DATE = "2020-06-01T00:00:00Z";

    /** 2^31 — one past the largest type any port can represent. */
    private static final BigInteger OVERSIZED_ATTRIBUTE_TYPE = BigInteger.valueOf(2147483648L);

    private static final byte[] GUID = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
            (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee,
            (byte) 0xff, 0x00};
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private PortDivergenceFixtures() {
    }

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);
        byte[] deviceHash = TestPki.deviceHash(GUID, OPAQUE, BUNDLE);

        // --- Receipts under a currently-valid chain ----------------------
        TestPki receiptPki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "divergence-receipt-root.der", receiptPki.root.getEncoded());

        // Well-formed in every other way — signed by a trusted chain, correct
        // device hash, real bundle id — so the only thing a verifier can
        // object to is the attribute type. Whether a port parses before or
        // after it checks the signature, the answer is the same.
        byte[] oversized = TestPki.receiptPayload("ProductionSandbox", BUNDLE, "1.2.3", OPAQUE,
                deviceHash, CREATION_DATE, Arrays.<byte[]>asList(), true, OVERSIZED_ATTRIBUTE_TYPE);
        write(out, "receipt-attribute-type-overflow.der",
                receiptPki.signReceipt(oversized, new Date(SIGNED_DATE)));

        // No attribute 12, so PLAN.md 2.2 step 2's "else current time" is the
        // only anchor left for certificate validity.
        byte[] dateless = TestPki.receiptPayload("ProductionSandbox", BUNDLE, "1.2.3", OPAQUE,
                deviceHash, CREATION_DATE, Arrays.<byte[]>asList(), false, null);
        write(out, "receipt-no-creation-date.der",
                receiptPki.signReceipt(dateless, new Date(SIGNED_DATE)));

        // --- The same dateless receipt under a long-expired chain --------
        TestPki expiredReceiptPki =
                TestPki.receipt(new Date(OLD_NOT_BEFORE), new Date(OLD_NOT_AFTER));
        write(out, "divergence-receipt-expired-root.der", expiredReceiptPki.root.getEncoded());
        byte[] oldDateless = TestPki.receiptPayload("ProductionSandbox", BUNDLE, "1.2.3", OPAQUE,
                deviceHash, OLD_CREATION_DATE, Arrays.<byte[]>asList(), false, null);
        write(out, "receipt-expired-no-creation-date.der",
                expiredReceiptPki.signReceipt(oldDateless, new Date(OLD_SIGNED_DATE)));

        // --- JWS payloads carrying no signing time -----------------------
        Map<String, Object> transaction = TestPki.claims(
                "bundleId", BUNDLE,
                "environment", "Sandbox",
                "purchaseDate", SIGNED_DATE,
                "originalPurchaseDate", SIGNED_DATE,
                "productId", BUNDLE + ".pro",
                "transactionId", "2000000000000001",
                "originalTransactionId", "2000000000000001",
                "quantity", 1,
                "type", "Non-Consumable",
                "inAppOwnershipType", "PURCHASED");

        TestPki jwsPki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "divergence-jws-root.der", jwsPki.root.getEncoded());
        write(out, "transaction-no-signed-date.jws",
                jwsPki.signJws(transaction).getBytes(StandardCharsets.US_ASCII));

        TestPki oldJwsPki = TestPki.jws(true, true, new Date(OLD_NOT_BEFORE), new Date(OLD_NOT_AFTER));
        write(out, "divergence-jws-expired-root.der", oldJwsPki.root.getEncoded());
        Map<String, Object> historical = new LinkedHashMap<String, Object>(transaction);
        historical.put("purchaseDate", OLD_SIGNED_DATE);
        historical.put("originalPurchaseDate", OLD_SIGNED_DATE);
        write(out, "transaction-expired-chain-no-signed-date.jws",
                oldJwsPki.signJws(historical).getBytes(StandardCharsets.US_ASCII));
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
