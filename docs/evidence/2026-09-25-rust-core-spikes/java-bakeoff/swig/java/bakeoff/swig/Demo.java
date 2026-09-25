package bakeoff.swig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicInteger;

/** Prints the facts SPEC.md's "Required programs" section asks for. */
public final class Demo {
    private static final String F = "$REPO/fixtures";

    public static void main(String[] args) throws Exception {
        System.loadLibrary("aprv");

        String g5 = readTrimmed(F + "/public-receipts/receipt-sandbox-g5.b64");
        byte[] genDer = Files.readAllBytes(Paths.get(F + "/generated/receipt.der"));
        byte[] genRoot = Files.readAllBytes(Paths.get(F + "/generated/receipt-root.der"));
        String jws = readTrimmed(F + "/generated/transaction.jws");
        byte[] jwsRoot = Files.readAllBytes(Paths.get(F + "/generated/jws-root.der"));

        // --- genuine g5 ---
        try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            AppReceipt r = v.verifyBase64(g5);
            System.out.println("g5 bundleId=" + r.bundleId());
            System.out.println("g5 iapCount=" + r.inAppPurchases().size());
            System.out.println("g5 firstProductId=" + r.inAppPurchases().get(0).productId());
            System.out.println("g5 firstPurchaseDateMs=" + r.inAppPurchases().get(0).purchaseDateMs());
        }

        // --- generated DER with custom root ---
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", Collections.singletonList(genRoot))) {
            AppReceipt r = v.verify(genDer);
            System.out.println("generated bundleId=" + r.bundleId());
            System.out.println("generated creationDateMs=" + r.creationDateMs());
        }

        // --- wrong bundle id ---
        try (ReceiptVerifier v = new ReceiptVerifier("wrong.bundle.id", Collections.singletonList(genRoot))) {
            v.verify(genDer);
            System.out.println("wrong-bundle FAIL (no exception thrown)");
        } catch (VerificationException e) {
            System.out.println("wrong-bundle reason=" + e.reason());
        }

        // --- JWS ---
        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null,
                Collections.singletonList(jwsRoot))) {
            TransactionPayload p = v.verifyTransaction(jws);
            System.out.println("jws productId=" + p.productId());
            System.out.println("jws signedDate=" + p.signedDate());
        }
        try (JwsVerifier v = new JwsVerifier("com.example.app", EnumSet.of(Environment.PRODUCTION), null,
                Collections.singletonList(jwsRoot))) {
            v.verifyTransaction(jws);
            System.out.println("jws-wrong-env FAIL (no exception thrown)");
        } catch (VerificationException e) {
            System.out.println("jws-wrong-env reason=" + e.reason());
        }

        // --- endpoint PRODUCTION with a genuine sandbox receipt ---
        try (VerifyReceiptEndpoint ep = new VerifyReceiptEndpoint(Environment.PRODUCTION)) {
            String body = "{\"receipt-data\":\"" + g5 + "\"}";
            String json = ep.verifyReceiptJson(body);
            System.out.println("endpoint verifyReceiptJson=" + json);

            VerifyReceiptResult result = ep.verifyReceiptResult(body);
            System.out.println("endpoint result.status=" + result.status());
            System.out.println("endpoint result.verified=" + result.verified());
            System.out.println("endpoint result.receipt.bundleId=" + result.receipt().bundleId());
            String inSandbox = result.toJsonIn(Environment.SANDBOX);
            System.out.println("endpoint toJsonIn(SANDBOX) startsWith expected="
                    + inSandbox.startsWith("{\"environment\":\"Sandbox\",\"receipt\":"));

            VerifyReceiptResult bad = ep.verifyReceiptResult("not json");
            System.out.println("endpoint bad.status=" + bad.status());
            System.out.println("endpoint bad.failureReason=" + bad.failureReason());
            System.out.println("endpoint bad.exceptionThrown=false");
        }

        // --- bad root bytes -> ConfigurationException ---
        try {
            new ReceiptVerifier("com.example.app", Collections.singletonList(new byte[]{1, 2, 3}));
            System.out.println("bad-root FAIL (no exception thrown)");
        } catch (ConfigurationException e) {
            System.out.println("bad-root ConfigurationException thrown");
        }

        // --- 8 threads x 100 calls on one shared ReceiptVerifier ---
        try (final ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app")) {
            final AtomicInteger failures = new AtomicInteger(0);
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                threads[t] = new Thread(new Runnable() {
                    public void run() {
                        for (int i = 0; i < 100; i++) {
                            try {
                                AppReceipt r = v.verifyBase64(g5);
                                if (!"dev.bonzer.weeka.app".equals(r.bundleId())) failures.incrementAndGet();
                            } catch (Exception e) {
                                failures.incrementAndGet();
                            }
                        }
                    }
                });
            }
            for (Thread t : threads) t.start();
            for (Thread t : threads) t.join();
            System.out.println("threaded-calls failures=" + failures.get() + " (0 expected)");
        }

        System.out.println("DEMO DONE");
    }

    private static String readTrimmed(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path))).replaceAll("\\s+", "");
    }
}
