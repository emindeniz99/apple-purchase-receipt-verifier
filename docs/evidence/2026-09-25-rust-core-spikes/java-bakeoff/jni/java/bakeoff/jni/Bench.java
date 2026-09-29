package bakeoff.jni;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.EnumSet;

/** Times verifyBase64(g5) and verifyTransaction(jws). Iterations per round: -Dbench.n (default 10000). */
public final class Bench {
    private static final String F = "$REPO/fixtures";

    private Bench() {}

    private static String text(String p) throws Exception {
        return new String(Files.readAllBytes(Paths.get(p)), StandardCharsets.UTF_8).replaceAll("\\s", "");
    }

    /**
     * Runs the benchmark.
     * @param args unused
     * @throws Exception on failure
     */
    public static void main(String[] args) throws Exception {
        int n = Integer.getInteger("bench.n", 10000);
        String g5 = text(F + "/public-receipts/receipt-sandbox-g5.b64");
        String jws = text(F + "/generated/transaction.jws");
        byte[] root = Files.readAllBytes(Paths.get(F + "/generated/jws-root.der"));
        long sink = 0;
        try (ReceiptVerifier rv = new ReceiptVerifier("dev.bonzer.weeka.app");
             JwsVerifier jv = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null,
                     Collections.singletonList(root))) {
            for (int i = 0; i < n; i++) {
                sink += rv.verifyBase64(g5).inAppPurchases().size();
                sink += jv.verifyTransaction(jws).productId().length();
            }
            for (int round = 1; round <= 3; round++) {
                long t0 = System.nanoTime();
                for (int i = 0; i < n; i++) sink += rv.verifyBase64(g5).inAppPurchases().size();
                long t1 = System.nanoTime();
                for (int i = 0; i < n; i++) sink += jv.verifyTransaction(jws).productId().length();
                long t2 = System.nanoTime();
                System.out.printf("jni round %d: receipt %.1f us, jws %.1f us%n",
                        round, (t1 - t0) / 1e3 / n, (t2 - t1) / 1e3 / n);
            }
        }
        if (sink == 42) System.out.println();
    }
}
