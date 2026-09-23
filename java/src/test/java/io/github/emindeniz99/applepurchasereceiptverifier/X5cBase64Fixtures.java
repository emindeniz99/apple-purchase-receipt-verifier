package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes the three x5c-spelling fixtures into {@code fixtures/generated/}.
 *
 * <p>RFC 7515 §4.1.6 makes every {@code x5c} entry base64 of a DER
 * certificate: the standard alphabet of RFC 4648 §4, not base64url, and
 * RFC 4648 §3.3 has a decoder reject characters outside that alphabet unless
 * the referring specification says otherwise, which RFC 7515 does not. Each
 * fixture keeps x5c[0]'s DER intact and changes only how it is spelled:</p>
 *
 * <ol>
 *   <li>one {@code !} inserted in the middle, which a skip-what-you-do-not-
 *       know decoder (Node's {@code Buffer.from(s, 'base64')}, Swift's
 *       {@code .ignoreUnknownCharacters}) drops, recovering the certificate;</li>
 *   <li>the whole entry in the base64url alphabet ({@code -} and {@code _}
 *       for {@code +} and {@code /}), which a decoder that accepts both
 *       alphabets reads as the same certificate;</li>
 *   <li>the entry wrapped at 64 columns with LF, as a PEM body is, which a
 *       decoder that tolerates whitespace reads as the same certificate.</li>
 * </ol>
 *
 * <p>All three are {@code INVALID_CERTIFICATE}. The header is signed in its
 * mutated state, so the ES256 signature covers exactly the bytes served and
 * the spelling is the only defect: a port that decodes the entry leniently
 * recovers a genuine chain and VERIFIES, rather than failing on a stale
 * signature and hiding the difference.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.X5cBase64Fixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. The root is
 * emitted beside them and the private keys are not kept.</p>
 */
public final class X5cBase64Fixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private X5cBase64Fixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        TestPki pki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "x5c-base64-jws-root.der", pki.root.getEncoded());

        Map<String, Object> transaction = TestPki.claims(
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
        String claimsJson = MAPPER.writeValueAsString(transaction);
        String leaf = pki.x5c().get(0);

        // --- 1. one character outside every base64 alphabet -------------
        int middle = leaf.length() / 2;
        String junk = leaf.substring(0, middle) + "!" + leaf.substring(middle);
        write(out, "transaction-x5c-leaf-junk-character.jws", sign(pki, junk, claimsJson));

        // --- 2. the base64url alphabet ------------------------------------
        // Every '+' and '/' swapped, so the string uses one alphabet only and
        // a decoder that refuses a MIXED alphabet still accepts it. Fresh
        // keys make the DER differ per run, so the swap is checked to have
        // changed something.
        String urlSafe = leaf.replace('+', '-').replace('/', '_');
        if (urlSafe.equals(leaf)) {
            throw new IllegalStateException("x5c[0] has no '+' or '/'; rerun for fresh keys");
        }
        write(out, "transaction-x5c-leaf-base64url-alphabet.jws", sign(pki, urlSafe, claimsJson));

        // --- 3. PEM-style line breaks -------------------------------------
        StringBuilder wrapped = new StringBuilder();
        for (int i = 0; i < leaf.length(); i += 64) {
            if (i > 0) {
                wrapped.append('\n');
            }
            wrapped.append(leaf, i, Math.min(leaf.length(), i + 64));
        }
        write(out, "transaction-x5c-leaf-line-breaks.jws", sign(pki, wrapped.toString(), claimsJson));
    }

    /** Signs a header whose x5c[0] is {@code leafText} and whose other two entries are genuine. */
    private static byte[] sign(TestPki pki, String leafText, String claimsJson) throws Exception {
        List<String> x5c = new ArrayList<String>(pki.x5c());
        x5c.set(0, leafText);
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", x5c);
        return pki.signJwsWithHeader(MAPPER.writeValueAsString(header), claimsJson)
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
