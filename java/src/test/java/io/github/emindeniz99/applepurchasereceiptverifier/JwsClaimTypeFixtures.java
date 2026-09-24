package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Writes the claim-type fixtures into {@code fixtures/generated/}: genuinely
 * signed JWS payloads in which one modelled claim has a JSON type the model
 * does not expect.
 *
 * <p>The chain and the signature are genuine, so a trusted signer produced
 * the claim. A typed read that cannot take it is the library's failure, not
 * the client's, and every port answers INTERNAL_ERROR rather than a reason a
 * caller reads as "deny". Six fixtures carry one wrong type each:</p>
 *
 * <ol>
 *   <li>{@code quantity} as the string {@code "1"};</li>
 *   <li>{@code productId} as the number {@code 42};</li>
 *   <li>{@code price} as {@code 1.5}, a number that is not an integer;</li>
 *   <li>{@code expiresDate} as a JSON object;</li>
 *   <li>{@code bundleId} as a number, which pins that the typed read comes
 *       before the bundle-id check;</li>
 *   <li>an AppTransaction whose {@code appAppleId} is a string.</li>
 * </ol>
 *
 * <p>A seventh has no defect: {@code quantity} is {@code 1.0}, two modelled
 * claims are JSON null and an unmodelled claim holds nested values. It must
 * verify, so a port cannot pass the six by refusing everything unusual.</p>
 *
 * <p>A {@code main} rather than a {@code @Test}, like the other generators.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.JwsClaimTypeFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files. The root is emitted beside them and the private keys are not kept.</p>
 */
public final class JwsClaimTypeFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwsClaimTypeFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.generated();
        Files.createDirectories(out);

        TestPki pki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "jws-claim-type-root.der", pki.root.getEncoded());

        write(out, "transaction-claim-quantity-string.jws", sign(pki, transaction("quantity", "1")));
        write(out, "transaction-claim-product-id-number.jws", sign(pki, transaction("productId", 42)));
        write(out, "transaction-claim-price-fractional.jws", sign(pki, transaction("price", 1.5)));
        Map<String, Object> object = new LinkedHashMap<String, Object>();
        object.put("ms", SIGNED_DATE);
        write(out, "transaction-claim-expires-date-object.jws", sign(pki, transaction("expiresDate", object)));
        write(out, "transaction-claim-bundle-id-number.jws", sign(pki, transaction("bundleId", 7)));

        Map<String, Object> appTransaction = TestPki.claims(
                "bundleId",
                BUNDLE,
                "receiptType",
                "Sandbox",
                "appAppleId",
                "123456789",
                "applicationVersion",
                "1.2.3",
                "originalApplicationVersion",
                "1.0",
                "receiptCreationDate",
                SIGNED_DATE);
        write(out, "app-transaction-claim-app-apple-id-string.jws", sign(pki, appTransaction));

        Map<String, Object> tolerated = transaction("quantity", 1.0);
        tolerated.put("expiresDate", null);
        tolerated.put("offerIdentifier", null);
        Map<String, Object> future = new LinkedHashMap<String, Object>();
        future.put("nested", Arrays.asList(1, "x", null));
        tolerated.put("futureClaim", future);
        write(out, "transaction-claims-null-and-unmodelled.jws", sign(pki, tolerated));
    }

    /** The shared transaction claims with {@code key} set to {@code value}. */
    private static Map<String, Object> transaction(String key, Object value) {
        Map<String, Object> claims = TestPki.claims(
                "bundleId",
                BUNDLE,
                "environment",
                "Sandbox",
                "signedDate",
                SIGNED_DATE,
                "purchaseDate",
                SIGNED_DATE,
                "originalPurchaseDate",
                SIGNED_DATE,
                "productId",
                BUNDLE + ".pro",
                "transactionId",
                "2000000000000001",
                "originalTransactionId",
                "2000000000000001",
                "quantity",
                1,
                "type",
                "Non-Consumable",
                "inAppOwnershipType",
                "PURCHASED");
        claims.put(key, value);
        return claims;
    }

    private static byte[] sign(TestPki pki, Map<String, Object> claims) throws Exception {
        return pki.signJws(claims).getBytes(StandardCharsets.US_ASCII);
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
