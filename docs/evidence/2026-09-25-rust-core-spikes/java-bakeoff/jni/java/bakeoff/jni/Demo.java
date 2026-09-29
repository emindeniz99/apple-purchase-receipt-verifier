package bakeoff.jni;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Prints and checks the spec's facts; exits 1 if any check fails. */
public final class Demo {
    private static final String F = "$REPO/fixtures";
    private static int failures;

    private Demo() {}

    private static void check(String name, boolean ok, Object shown) {
        System.out.println((ok ? "PASS " : "FAIL ") + name + " = " + shown);
        if (!ok) failures++;
    }

    private static byte[] read(String p) throws Exception { return Files.readAllBytes(Paths.get(p)); }

    private static String text(String p) throws Exception {
        return new String(read(p), StandardCharsets.UTF_8).replaceAll("\\s", "");
    }

    /**
     * Runs every check.
     * @param args unused
     * @throws Exception on an unexpected failure
     */
    public static void main(String[] args) throws Exception {
        System.out.println("java " + System.getProperty("java.version"));
        String g5 = text(F + "/public-receipts/receipt-sandbox-g5.b64");
        List<byte[]> receiptRoot = Collections.singletonList(read(F + "/generated/receipt-root.der"));
        List<byte[]> jwsRoot = Collections.singletonList(read(F + "/generated/jws-root.der"));
        String jws = text(F + "/generated/transaction.jws");

        try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            AppReceipt r = v.verifyBase64(g5);
            check("g5 bundleId", "dev.bonzer.weeka.app".equals(r.bundleId()), r.bundleId());
            check("g5 IAP count", r.inAppPurchases().size() == 2, r.inAppPurchases().size());
            InAppPurchase p = r.inAppPurchases().get(0);
            check("g5 first productId", p.productId() != null, p.productId());
            check("g5 first purchaseDateMs", p.purchaseDateMs() != null, p.purchaseDateMs());
        }

        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", receiptRoot)) {
            AppReceipt r = v.verify(read(F + "/generated/receipt.der"));
            check("generated bundleId", "com.example.app".equals(r.bundleId()), r.bundleId());
            check("generated creationDateMs", Long.valueOf(1722945600000L).equals(r.creationDateMs()), r.creationDateMs());
        }

        try (ReceiptVerifier v = new ReceiptVerifier("com.wrong.app", receiptRoot)) {
            v.verify(read(F + "/generated/receipt.der"));
            check("wrong bundle id", false, "no exception");
        } catch (VerificationException e) {
            check("wrong bundle id", e.reason() == Reason.WRONG_BUNDLE_ID, e.reason() + " (" + e.detail() + ")");
        }

        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null, jwsRoot)) {
            TransactionPayload t = v.verifyTransaction(jws);
            check("jws productId", "com.example.app.pro".equals(t.productId()), t.productId());
            check("jws signedDate", Long.valueOf(1722945600000L).equals(t.signedDate()), t.signedDate());
        }
        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.PRODUCTION), null, jwsRoot)) {
            v.verifyTransaction(jws);
            check("jws production-only", false, "no exception");
        } catch (VerificationException e) {
            check("jws production-only", e.reason() == Reason.WRONG_ENVIRONMENT, e.reason());
        }

        try (VerifyReceiptEndpoint ep = new VerifyReceiptEndpoint(Environment.PRODUCTION)) {
            String body = "{\"receipt-data\":\"" + g5 + "\"}";
            String json = ep.verifyReceiptJson(body);
            check("endpoint json", json.equals("{\"status\":21007}"), json);
            try (VerifyReceiptResult res = ep.verifyReceiptResult(body)) {
                check("result status", res.status() == 21007, res.status());
                check("result verified", res.verified(), res.verified());
                AppReceipt r = res.receipt();
                check("result receipt bundleId", r != null && "dev.bonzer.weeka.app".equals(r.bundleId()), r == null ? null : r.bundleId());
                String sb = res.toJsonIn(Environment.SANDBOX);
                check("result toJsonIn(SANDBOX)", sb.startsWith("{\"environment\":\"Sandbox\",\"receipt\":"),
                        sb.substring(0, Math.min(40, sb.length())) + "...");
            }
            try (VerifyReceiptResult bad = ep.verifyReceiptResult("not json")) {
                check("not json status", bad.status() == 21002, bad.status());
                check("not json reason", bad.failureReason() == Reason.MALFORMED_REQUEST, bad.failureReason());
            }
        }

        try {
            new ReceiptVerifier("com.example.app", Collections.singletonList(new byte[] {1, 2, 3})).close();
            check("bad root", false, "no exception");
        } catch (ConfigurationException e) {
            check("bad root", true, "ConfigurationException: " + e.getMessage());
        }

        try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            List<Future<Integer>> fs = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                fs.add(pool.submit(() -> {
                    int ok = 0;
                    for (int i = 0; i < 100; i++) if (v.verifyBase64(g5).inAppPurchases().size() == 2) ok++;
                    return ok;
                }));
            }
            int ok = 0;
            for (Future<Integer> f : fs) ok += f.get();
            pool.shutdown();
            check("8 threads x 100", ok == 800, ok + "/800");
        }

        ReceiptVerifier closed = new ReceiptVerifier("dev.bonzer.weeka.app");
        closed.close();
        try {
            closed.verifyBase64(g5);
            check("use after close", false, "no exception");
        } catch (IllegalStateException e) {
            check("use after close", true, e.getMessage());
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILED");
        if (failures != 0) System.exit(1);
    }
}
