package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.DERUTF8String;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
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

    /**
     * 2^32 + 2. The 2^31 vector pins one point of the attribute-type
     * ceiling; a port could sit its own anywhere from there up to 2^53 and
     * no vector would notice. This value lands inside that band, and it is
     * chosen rather than picked: truncated to 32 bits it becomes 2, the
     * bundle id attribute, so a port that wrapped instead of rejecting
     * would read the attribute rather than refuse the receipt.
     */
    private static final BigInteger TRUNCATING_ATTRIBUTE_TYPE = BigInteger.valueOf(4294967298L);

    /**
     * The DER of the attribute every generated receipt payload carries for
     * type 9999 — {@code SEQUENCE { INTEGER 9999, INTEGER 1, OCTET STRING
     * 01 02 03 }}. A CMS receipt embeds its payload verbatim, so this locates
     * the one byte {@link #tamperOneByte} alters: it belongs to an attribute
     * no port models, so altering it changes no claim, only the digest the
     * signature covers.
     */
    private static final byte[] UNKNOWN_ATTRIBUTE_DER = {
            0x30, 0x0c, 0x02, 0x02, 0x27, 0x0f, 0x02, 0x01, 0x01, 0x04, 0x03, 0x01, 0x02, 0x03};

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

        // --- The two verdicts no vector pinned ---------------------------
        // INVALID_SIGNATURE and INVALID_CERTIFICATE were the only reasons in
        // the vocabulary that fixtures/cases.json never reached, because both
        // are usually produced by mutating bytes at run time and a case's
        // input is a fixture id. These are those mutations, checked in: each
        // carries exactly ONE defect and is anchored to a root emitted beside
        // it, so nothing earlier in the pipeline can claim the verdict first.

        TestPki gapsReceiptPki =
                TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "gaps-receipt-root.der", gapsReceiptPki.root.getEncoded());

        // Signed intact, then one byte of the signed payload flipped. The
        // byte belongs to attribute 9999, which no port models: the receipt
        // still parses, still names the right bundle id and creation date,
        // and its chain still validates — the CMS digest is the only thing
        // that no longer matches.
        byte[] intact = TestPki.receiptPayload("ProductionSandbox", BUNDLE, "1.2.3", OPAQUE,
                deviceHash, CREATION_DATE, Arrays.<byte[]>asList(), true, null);
        write(out, "receipt-tampered-payload.der",
                tamperOneByte(gapsReceiptPki.signReceipt(intact, new Date(SIGNED_DATE))));

        // A second point on the attribute-type ceiling (see
        // TRUNCATING_ATTRIBUTE_TYPE), carrying a value a truncating parser
        // would happily read as a bundle id.
        byte[] truncating = TestPki.receiptPayload("ProductionSandbox", BUNDLE, "1.2.3", OPAQUE,
                deviceHash, CREATION_DATE, Arrays.<byte[]>asList(), true,
                TRUNCATING_ATTRIBUTE_TYPE,
                new DERUTF8String("com.attacker.app").getEncoded());
        write(out, "receipt-attribute-type-truncates-to-bundle-id.der",
                gapsReceiptPki.signReceipt(truncating, new Date(SIGNED_DATE)));

        TestPki gapsJwsPki =
                TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "gaps-jws-root.der", gapsJwsPki.root.getEncoded());

        Map<String, Object> signedClaims = new LinkedHashMap<String, Object>(transaction);
        signedClaims.put("signedDate", SIGNED_DATE);

        // The payload segment is replaced AFTER signing with one that differs
        // in a single character of productId. Same length, still valid
        // base64url, still valid JSON, still the right bundle id and
        // environment and signedDate — so every check a port makes before the
        // signature passes, and the ES256 check is genuinely the first thing
        // that fails.
        Map<String, Object> servedClaims = new LinkedHashMap<String, Object>(signedClaims);
        servedClaims.put("productId", BUNDLE + ".prq");
        write(out, "transaction-tampered-payload.jws",
                swapPayloadAfterSigning(gapsJwsPki, jwsHeader(gapsJwsPki.x5c()),
                        signedClaims, servedClaims));

        // x5c[0] holds base64 of "not a certificate". The JWS is then signed
        // over that header, so the signature is a real ES256 signature over
        // the bytes served and the unparseable leaf is the only defect. x5c[1]
        // would do as well; x5c[2] would NOT — Java parses the third entry and
        // the other eight ports do not, and that divergence is deliberately
        // not something a shared vector may depend on.
        List<String> brokenX5c = new ArrayList<String>(gapsJwsPki.x5c());
        brokenX5c.set(0, TestPki.b64("not a certificate".getBytes(StandardCharsets.US_ASCII)));
        write(out, "transaction-x5c-leaf-not-a-certificate.jws",
                gapsJwsPki.signJwsWithHeader(jwsHeader(brokenX5c),
                                MAPPER.writeValueAsString(signedClaims))
                        .getBytes(StandardCharsets.US_ASCII));
    }

    /** {@code {"alg":"ES256","x5c":[...]}} — the header every fixture here uses. */
    private static String jwsHeader(List<String> x5c) throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", x5c);
        return MAPPER.writeValueAsString(header);
    }

    /**
     * Signs {@code signed}, then serves {@code served} in the payload segment
     * instead. Both must encode to the same length and differ in exactly one
     * byte, so the fixture cannot quietly become a multi-fault input.
     */
    private static byte[] swapPayloadAfterSigning(TestPki pki, String headerJson,
                                                  Map<String, ?> signed, Map<String, ?> served)
            throws Exception {
        byte[] signedJson = MAPPER.writeValueAsString(signed).getBytes(StandardCharsets.UTF_8);
        byte[] servedJson = MAPPER.writeValueAsString(served).getBytes(StandardCharsets.UTF_8);
        requireOneByteApart(signedJson, servedJson);
        String[] parts = pki.signJwsWithHeader(headerJson,
                new String(signedJson, StandardCharsets.UTF_8)).split("\\.", -1);
        return (parts[0] + "." + TestPki.b64url(servedJson) + "." + parts[2])
                .getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Flips one bit of the payload's unknown attribute 9999 inside an
     * already-signed CMS receipt. The payload is encapsulated verbatim, so
     * the attribute's DER appears in the receipt exactly once — asserted,
     * because each run mints fresh keys and a coincidental second occurrence
     * elsewhere in the blob would silently tamper with the wrong bytes.
     */
    private static byte[] tamperOneByte(byte[] cms) {
        int at = -1;
        for (int i = 0; i + UNKNOWN_ATTRIBUTE_DER.length <= cms.length; i++) {
            boolean matches = true;
            for (int j = 0; matches && j < UNKNOWN_ATTRIBUTE_DER.length; j++) {
                matches = cms[i + j] == UNKNOWN_ATTRIBUTE_DER[j];
            }
            if (!matches) {
                continue;
            }
            if (at >= 0) {
                throw new IllegalStateException("attribute 9999 occurs more than once in the CMS");
            }
            at = i;
        }
        if (at < 0) {
            throw new IllegalStateException("attribute 9999 not found in the CMS");
        }
        byte[] tampered = cms.clone();
        int last = at + UNKNOWN_ATTRIBUTE_DER.length - 1;
        tampered[last] ^= 0x01;
        return tampered;
    }

    private static void requireOneByteApart(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalStateException("payload swap changed the length");
        }
        int differences = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                differences++;
            }
        }
        if (differences != 1) {
            throw new IllegalStateException("payload swap altered " + differences + " bytes, not 1");
        }
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
