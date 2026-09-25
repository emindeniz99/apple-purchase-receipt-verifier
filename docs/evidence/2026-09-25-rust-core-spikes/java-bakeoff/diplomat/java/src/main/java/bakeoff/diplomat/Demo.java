package bakeoff.diplomat;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Prints the bake-off facts by calling the Diplomat-generated Kotlin API
 * directly from plain Java. It only reads results; the Rust core decides.
 */
public final class Demo {
    static final String F = "$REPO/fixtures/";
    private static int failures = 0;

    private Demo() {}

    private static void check(String fact, boolean ok, Object shown) {
        System.out.println((ok ? "PASS " : "FAIL ") + fact + ": " + shown);
        if (!ok) failures++;
    }

    private static String text(String path) throws Exception {
        return new String(Files.readAllBytes(Paths.get(F + path)), "UTF-8");
    }

    private static byte[] bytes(String path) throws Exception {
        return Files.readAllBytes(Paths.get(F + path));
    }

    /**
     * Runs every fact and exits non-zero if any fails.
     *
     * @param args unused
     * @throws Exception on fixture I/O failure or an unexpected error
     */
    public static void main(String[] args) throws Exception {
        System.out.println("java " + System.getProperty("java.version"));
        String g5 = text("public-receipts/receipt-sandbox-g5.b64").replaceAll("\\s", "");

        // 1. genuine g5 against Apple's pinned roots (roots == null)
        ReceiptVerifier apple = ReceiptVerifier.create("dev.bonzer.weeka.app", null).verifier();
        AppReceipt g = apple.verifyBase64(g5).receipt();
        InAppPurchase first = g.inAppPurchase(0);
        check("g5 bundleId", "dev.bonzer.weeka.app".equals(g.bundleId()), g.bundleId());
        check("g5 IAP count 2", g.inAppPurchaseCount() == 2, g.inAppPurchaseCount());
        check("g5 first productId", first.productId() != null, first.productId());
        check("g5 first purchaseDateMs", first.purchaseDateMs() != null, first.purchaseDateMs());

        // 2. generated DER with a custom root
        TrustRoots receiptRoot = TrustRoots.create();
        ConfigError addErr = receiptRoot.addDer(bytes("generated/receipt-root.der"));
        byte[] der = bytes("generated/receipt.der");
        AppReceipt gen = ReceiptVerifier.create("com.example.app", receiptRoot).verifier().verify(der).receipt();
        check("generated bundleId", addErr == null && "com.example.app".equals(gen.bundleId()), gen.bundleId());
        check("generated creationDateMs", Long.valueOf(1722945600000L).equals(gen.creationDateMs()), gen.creationDateMs());

        // 3. wrong bundle id: Diplomat returns the error object (it extends Exception)
        ReceiptOutcome wrong = ReceiptVerifier.create("com.wrong.app", receiptRoot).verifier().verify(der);
        VerificationError ve = wrong.error();
        check("wrong bundle id -> WRONG_BUNDLE_ID", wrong.receipt() == null && ve != null && ve.reason() == Reason.WrongBundleId,
                ve == null ? null : ve.reason() + " / " + ve.detail());

        // 4. JWS
        String jws = text("generated/transaction.jws").trim();
        TrustRoots jwsRoot = TrustRoots.create();
        jwsRoot.addDer(bytes("generated/jws-root.der"));
        EnvironmentSet sandbox = EnvironmentSet.create();
        sandbox.add(Environment.Sandbox);
        TransactionPayload tx = JwsVerifier.create("com.example.app", sandbox, null, jwsRoot).verifier().verifyTransaction(jws).payload();
        check("jws productId", "com.example.app.pro".equals(tx.productId()), tx.productId());
        check("jws signedDate", Long.valueOf(1722945600000L).equals(tx.signedDate()), tx.signedDate());
        EnvironmentSet prodOnly = EnvironmentSet.create();
        prodOnly.add(Environment.Production);
        TransactionOutcome prodTx = JwsVerifier.create("com.example.app", prodOnly, null, jwsRoot).verifier().verifyTransaction(jws);
        check("jws PRODUCTION-only -> WRONG_ENVIRONMENT", prodTx.error() != null && prodTx.error().reason() == Reason.WrongEnvironment,
                prodTx.error() == null ? null : prodTx.error().reason());

        // 5. endpoint
        VerifyReceiptEndpoint prod = VerifyReceiptEndpoint.create(Environment.Production, null).endpoint();
        String body = "{\"receipt-data\":\"" + g5 + "\"}";
        String json = prod.verifyReceiptJson(body);
        check("endpoint verifyReceiptJson", "{\"status\":21007}".equals(json), json);
        VerifyReceiptResult r = prod.verifyReceiptResult(body);
        check("endpoint status 21007", r.status() == 21007L, r.status());
        check("endpoint verified", r.verified(), r.verified());
        check("endpoint receipt bundleId", "dev.bonzer.weeka.app".equals(r.receipt().bundleId()), r.receipt().bundleId());
        String sb = r.toJsonIn(Environment.Sandbox).json();
        check("endpoint toJsonIn(SANDBOX)", sb != null && sb.startsWith("{\"environment\":\"Sandbox\",\"receipt\":"),
                sb == null ? null : sb.substring(0, 40) + "...");

        // 6. malformed body: a status, never an exception
        VerifyReceiptResult bad = prod.verifyReceiptResult("not json");
        check("not json -> 21002 MALFORMED_REQUEST", bad.status() == 21002L && bad.failureReason() == Reason.MalformedRequest,
                bad.status() + " " + bad.failureReason());

        // 7. bad root bytes: addDer returns the ConfigError instead of throwing
        ConfigError ce = TrustRoots.create().addDer(new byte[] {1, 2, 3});
        check("bad root -> ConfigError", ce != null, ce == null ? null : ce.detail());

        // 8. 8 threads x 100 calls on one shared verifier
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<Integer>> futures = new ArrayList<Future<Integer>>();
        for (int t = 0; t < 8; t++) {
            futures.add(pool.submit(() -> {
                int ok = 0;
                for (int i = 0; i < 100; i++) {
                    AppReceipt a = apple.verifyBase64(g5).receipt();
                    if (a != null && a.inAppPurchaseCount() == 2) ok++;
                }
                return ok;
            }));
        }
        int total = 0;
        for (Future<Integer> f : futures) total += f.get();
        pool.shutdown();
        check("8 threads x 100 shared verifier", total == 800, total + "/800");

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
