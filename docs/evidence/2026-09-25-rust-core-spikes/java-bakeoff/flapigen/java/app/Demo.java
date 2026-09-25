import bakeoff.flapigen.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Prints the spec's Demo facts for the flapigen binding; exits 1 on any failure. */
public final class Demo {
    static final String F = "$REPO/fixtures";
    static int failures = 0;

    static void check(String fact, boolean ok, Object shown) {
        System.out.println((ok ? "PASS " : "FAIL ") + fact + " -> " + shown);
        if (!ok) failures++;
    }

    static byte[] bytes(String p) throws Exception { return Files.readAllBytes(Paths.get(F, p)); }
    static String text(String p) throws Exception { return new String(bytes(p), StandardCharsets.UTF_8); }

    /** Entry point. */
    public static void main(String[] args) throws Exception {
        System.out.println("java.version=" + System.getProperty("java.version"));
        String g5 = text("public-receipts/receipt-sandbox-g5.b64").replaceAll("\\s", "");

        // 1. genuine g5 against Apple's built-in roots
        try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            AppReceipt r = v.verifyBase64(g5);
            InAppPurchase[] iaps = r.inAppPurchases();
            check("g5 bundleId", "dev.bonzer.weeka.app".equals(r.bundleId().orElse(null)), r.bundleId().orElse(null));
            check("g5 IAP count 2", iaps.length == 2, iaps.length);
            check("g5 first productId", iaps[0].productId().isPresent(), iaps[0].productId().orElse(null));
            check("g5 first purchaseDateMs", iaps[0].purchaseDateMs().isPresent(), iaps[0].purchaseDateMs());
        }

        // 2. generated DER with custom root
        byte[] receiptRoot = bytes("generated/receipt-root.der");
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", Collections.singletonList(receiptRoot))) {
            AppReceipt r = v.verify(bytes("generated/receipt.der"));
            check("generated bundleId com.example.app", "com.example.app".equals(r.bundleId().orElse(null)), r.bundleId().orElse(null));
            check("generated creationDateMs 1722945600000", r.creationDateMs().orElse(-1) == 1722945600000L, r.creationDateMs());
        }

        // 3. wrong bundle id
        try (ReceiptVerifier v = new ReceiptVerifier("com.wrong.app", Collections.singletonList(receiptRoot))) {
            v.verify(bytes("generated/receipt.der"));
            check("wrong bundle -> WRONG_BUNDLE_ID", false, "no exception");
        } catch (VerificationException e) {
            check("wrong bundle -> WRONG_BUNDLE_ID", e.reason() == Reason.WRONG_BUNDLE_ID, e.reason() + " / " + e.detail());
        }

        // 4. JWS
        String jws = text("generated/transaction.jws").trim();
        List<byte[]> jwsRoots = Collections.singletonList(bytes("generated/jws-root.der"));
        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null, jwsRoots)) {
            TransactionPayload p = v.verifyTransaction(jws);
            check("jws productId com.example.app.pro", "com.example.app.pro".equals(p.productId().orElse(null)), p.productId().orElse(null));
            check("jws signedDate 1722945600000", p.signedDate().orElse(-1) == 1722945600000L, p.signedDate());
        }
        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.PRODUCTION), null, jwsRoots)) {
            v.verifyTransaction(jws);
            check("jws PRODUCTION-only -> WRONG_ENVIRONMENT", false, "no exception");
        } catch (VerificationException e) {
            check("jws PRODUCTION-only -> WRONG_ENVIRONMENT", e.reason() == Reason.WRONG_ENVIRONMENT, e.reason());
        }

        // 5/6. endpoint
        try (VerifyReceiptEndpoint ep = new VerifyReceiptEndpoint(Environment.PRODUCTION)) {
            String body = "{\"receipt-data\":\"" + g5 + "\"}";
            String json = ep.verifyReceiptJson(body);
            check("endpoint json {\"status\":21007}", json.equals("{\"status\":21007}"), json);
            try (VerifyReceiptResult res = ep.verifyReceiptResult(body)) {
                check("result.status()==21007", res.status() == 21007, res.status());
                check("result.verified()", res.verified(), res.verified());
                String bid = res.receipt().flatMap(AppReceipt::bundleId).orElse(null);
                check("result.receipt().bundleId", "dev.bonzer.weeka.app".equals(bid), bid);
                String sb = res.toJsonIn(Environment.SANDBOX);
                check("toJsonIn(SANDBOX) prefix", sb.startsWith("{\"environment\":\"Sandbox\",\"receipt\":"),
                        sb.substring(0, Math.min(40, sb.length())) + "...");
            }
            try (VerifyReceiptResult bad = ep.verifyReceiptResult("not json")) {
                check("not json -> 21002", bad.status() == 21002, bad.status());
                check("not json -> MALFORMED_REQUEST", bad.failureReason().orElse(null) == Reason.MALFORMED_REQUEST, bad.failureReason());
            }
        }

        // 7. bad root bytes
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", Collections.singletonList(new byte[] {1, 2, 3}))) {
            check("bad root -> ConfigurationException", false, "no exception");
        } catch (ConfigurationException e) {
            check("bad root -> ConfigurationException", true, e.getMessage());
        }

        // 8. 8 threads x 100 calls on one shared verifier
        try (ReceiptVerifier shared = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            AtomicInteger ok = new AtomicInteger();
            List<Future<?>> fs = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                fs.add(pool.submit(() -> {
                    for (int i = 0; i < 100; i++) {
                        try {
                            if (shared.verifyBase64(g5).inAppPurchases().length == 2) ok.incrementAndGet();
                        } catch (Exception e) { /* counted as failure */ }
                    }
                }));
            }
            for (Future<?> f : fs) f.get();
            pool.shutdown();
            check("8 threads x 100 calls", ok.get() == 800, ok.get() + "/800");
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
