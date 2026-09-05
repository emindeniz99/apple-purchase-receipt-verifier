package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Map;

/**
 * Writes the six empty-or-non-object compact-JWS segment fixtures into
 * {@code fixtures/generated/}.
 *
 * <p>RFC 7515 §7.1 gives a compact JWS three base64url segments, and the first
 * two decode to JSON <em>objects</em>. Nothing in the ports' shared vectors
 * said what happens when a segment is empty, or decodes to a JSON array or a
 * bare scalar — and an empty header is not a header a port can read {@code alg}
 * out of, which Java's fuzzing walked out of the library as a
 * NullPointerException rather than a verdict. All six are
 * {@code INVALID_JWS_FORMAT}: the input is not a compact JWS this library can
 * read, decided before any certificate is decoded and long before any
 * signature is checked.</p>
 *
 * <p>Four of the six need no signing at all, since the defect is in the header
 * and the header is read first. The two that put the defect in the PAYLOAD do
 * need a genuine header, or a port would answer about the certificates in a
 * fake one instead — so they carry the real header and signature of a real
 * JWS over this generator's own PKI, and only the payload segment is replaced.
 * The signature is then stale, which is exactly the point: every port parses
 * the payload as JSON before it checks the signature, because the payload
 * states the instant the chain is judged at.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.JwsSegmentFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. The root is emitted
 * beside them and the private keys are not kept.</p>
 */
public final class JwsSegmentFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    private JwsSegmentFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        TestPki pki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "jws-segments-root.der", pki.root.getEncoded());

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
        String[] genuine = pki.signJws(transaction).split("\\.", -1);
        String header = genuine[0];
        String payload = genuine[1];
        String signature = genuine[2];

        // --- 1. every segment empty --------------------------------------
        // Two dots and nothing else. It splits into three segments, so a port
        // that only counts them gets past that check with no header to read.
        write(out, "jws-all-segments-empty.jws", "..");

        // --- 2. an empty header ------------------------------------------
        // The payload and the signature are the genuine ones, so the empty
        // header is the only defect. An empty segment decodes to zero bytes,
        // which is not JSON — but a JSON reader that answers "nothing" rather
        // than raising hands the caller a null the next line dereferences.
        write(out, "jws-header-empty.jws", "." + payload + "." + signature);

        // --- 3. an empty payload -----------------------------------------
        // The genuine header, so a port reaches the payload at all.
        write(out, "jws-payload-empty.jws", header + ".." + signature);

        // --- 4. a header that is a JSON array ----------------------------
        // Valid base64url and valid JSON, and not an object: there is no
        // member to read `alg` or `x5c` from, and a port indexing into it
        // by name has to decide that on purpose rather than by accident.
        write(out, "jws-header-json-array.jws", segment("[\"ES256\",[]]") + "." + payload + "." + signature);

        // --- 5. a header that is a bare JSON scalar ----------------------
        // The other shape a JSON document can take. `42` is a complete JSON
        // text under RFC 8259 §2, so a port that only asks "does this parse
        // as JSON" accepts it.
        write(out, "jws-header-json-scalar.jws", segment("42") + "." + payload + "." + signature);

        // --- 6. a payload that is a JSON array ---------------------------
        // The genuine header again, so this is a verdict about the payload.
        // The claims a port reads by name are simply absent from an array,
        // and reading them as absent would move certificate validity onto
        // the current-time fallback and silence the staleness rule with it —
        // the same fail-open the out-of-range signedDate vector guards.
        write(out, "jws-payload-json-array.jws", header + "." + segment("[1,2,3]") + "." + signature);
    }

    /** One base64url segment holding {@code json} verbatim. */
    private static String segment(String json) {
        return TestPki.b64url(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void write(Path out, String name, String text) throws Exception {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
