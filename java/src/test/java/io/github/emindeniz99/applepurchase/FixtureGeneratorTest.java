package io.github.emindeniz99.applepurchase;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Writes the shared cross-language fixture set to {@code fixtures/generated/}
 * (PLAN.md milestone 6). Not a test of behavior — it only runs when
 * regeneration is explicitly requested:
 *
 * <pre>mvn test -Dtest=FixtureGeneratorTest -Dfixtures.generate=true</pre>
 *
 * Fixtures are checked in and treated as stable bytes; every language's
 * suite (Java's {@code SharedFixturesTest}, Node, Python, Swift) must verify
 * the same files. Regenerating changes keys/bytes — do it only deliberately
 * and re-run every language's tests in the same change.
 */
class FixtureGeneratorTest {

    private static final Path OUT = Paths.get("..", "fixtures", "generated");
    private static final String BUNDLE = "com.example.app";

    // Fixed epoch instants so fixtures don't depend on generation time.
    private static final long SIGNED_DATE = 1722945600000L;          // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long CHAIN_NOT_BEFORE = 1704067200000L;     // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L;      // 2050-01-01
    private static final long OLD_NOT_BEFORE = 1577836800000L;       // 2020-01-01
    private static final long OLD_NOT_AFTER = 1609459200000L;        // 2021-01-01
    private static final long OLD_SIGNED_DATE = 1590969600000L;      // 2020-06-01
    private static final long FRESH_SIGNED_DATE = SIGNED_DATE;

    private static final byte[] GUID = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
            (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, 0x00};
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    @Test
    void generate() throws Exception {
        assumeTrue(System.getProperty("fixtures.generate") != null,
                "fixture generation only runs with -Dfixtures.generate=true");
        Files.createDirectories(OUT);

        // --- JWS: current chain ------------------------------------------
        TestPki jwsPki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write("jws-root.der", jwsPki.root.getEncoded());

        Map<String, Object> transaction = TestPki.claims(
                "bundleId", BUNDLE,
                "environment", "Sandbox",
                "signedDate", SIGNED_DATE,
                "purchaseDate", SIGNED_DATE,
                "originalPurchaseDate", SIGNED_DATE,
                "productId", BUNDLE + ".pro",
                "transactionId", "2000000000000001",
                "originalTransactionId", "2000000000000001",
                "quantity", 1,
                "type", "Non-Consumable",
                "inAppOwnershipType", "PURCHASED");
        write("transaction.jws", jwsPki.signJws(transaction).getBytes(StandardCharsets.US_ASCII));

        Map<String, Object> appTransaction = TestPki.claims(
                "bundleId", BUNDLE,
                "receiptType", "Sandbox",
                "appAppleId", 123456789L,
                "applicationVersion", "1.2.3",
                "originalApplicationVersion", "1.0",
                "receiptCreationDate", SIGNED_DATE);
        write("app-transaction.jws", jwsPki.signJws(appTransaction).getBytes(StandardCharsets.US_ASCII));

        // --- JWS: expired chain (historical passes, fresh fails) ---------
        TestPki oldPki = TestPki.jws(true, true, new Date(OLD_NOT_BEFORE), new Date(OLD_NOT_AFTER));
        write("jws-expired-root.der", oldPki.root.getEncoded());
        Map<String, Object> historical = new LinkedHashMap<String, Object>(transaction);
        historical.put("signedDate", OLD_SIGNED_DATE);
        historical.put("purchaseDate", OLD_SIGNED_DATE);
        historical.put("originalPurchaseDate", OLD_SIGNED_DATE);
        write("expired-cert-historical.jws", oldPki.signJws(historical).getBytes(StandardCharsets.US_ASCII));
        Map<String, Object> fresh = new LinkedHashMap<String, Object>(transaction);
        fresh.put("signedDate", FRESH_SIGNED_DATE);
        write("expired-cert-fresh.jws", oldPki.signJws(fresh).getBytes(StandardCharsets.US_ASCII));

        // --- Receipt ------------------------------------------------------
        TestPki receiptPki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write("receipt-root.der", receiptPki.root.getEncoded());
        byte[] hash = TestPki.deviceHash(GUID, OPAQUE, BUNDLE);
        byte[] payload = TestPki.receiptPayload(BUNDLE, "1.2.3", OPAQUE, hash, CREATION_DATE,
                Arrays.asList(
                        TestPki.inAppPurchase(1, BUNDLE + ".coins100", "70000000000001",
                                "70000000000001", "2024-01-15T12:00:00Z", null),
                        TestPki.inAppPurchase(1, BUNDLE + ".vip", "70000000000002",
                                "70000000000002", "2024-02-01T09:30:00Z", "2030-02-01T09:30:00Z")));
        write("receipt.der", receiptPki.signReceipt(payload, new Date(SIGNED_DATE)));
        write("device-guid.hex", hex(GUID).getBytes(StandardCharsets.US_ASCII));

        TestPki foreignPki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write("receipt-foreign.der", foreignPki.signReceipt(payload, new Date(SIGNED_DATE)));

        // --- Manifest -----------------------------------------------------
        Map<String, Object> manifest = TestPki.claims(
                "comment", "Shared cross-language fixtures. Regenerate only via "
                        + "FixtureGeneratorTest (-Dfixtures.generate=true); see file javadoc.",
                "bundleId", BUNDLE,
                "environment", "Sandbox",
                "appAppleId", 123456789L,
                "transaction", transaction,
                "appTransaction", appTransaction,
                "expiredChain", TestPki.claims(
                        "historicalSignedDate", OLD_SIGNED_DATE,
                        "freshSignedDate", FRESH_SIGNED_DATE,
                        "expectHistorical", "verifies",
                        "expectFresh", "INVALID_CHAIN"),
                "receipt", TestPki.claims(
                        "receiptType", "ProductionSandbox",
                        "bundleId", BUNDLE,
                        "appVersion", "1.2.3",
                        "originalAppVersion", "1.0",
                        "creationDate", CREATION_DATE,
                        "deviceGuidHex", hex(GUID),
                        "opaqueHex", hex(OPAQUE),
                        "inAppProductIds", Arrays.asList(BUNDLE + ".coins100", BUNDLE + ".vip"),
                        "vipExpiresDate", "2030-02-01T09:30:00Z",
                        "expectForeign", "INVALID_CHAIN"));
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        write("manifest.json", mapper.writeValueAsBytes(manifest));
    }

    private static void write(String name, byte[] bytes) throws Exception {
        Files.write(OUT.resolve(name), bytes);
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
