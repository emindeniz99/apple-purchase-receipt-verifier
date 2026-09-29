package bakeoff.swig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.EnumSet;

/**
 * 10,000 warm-up calls, then 3 rounds x 10,000 of
 * {@link ReceiptVerifier#verifyBase64} and {@link JwsVerifier#verifyTransaction}.
 * {@code -Dbench.n=N} overrides the round size for a quick smoke run.
 */
public final class Bench {
    private static final String F = "$REPO/fixtures";

    public static void main(String[] args) throws Exception {
        System.loadLibrary("aprv");

        int n = Integer.getInteger("bench.n", 10_000);

        String g5 = readTrimmed(F + "/public-receipts/receipt-sandbox-g5.b64");
        String jws = readTrimmed(F + "/generated/transaction.jws");
        byte[] jwsRoot = Files.readAllBytes(Paths.get(F + "/generated/jws-root.der"));

        try (ReceiptVerifier rv = new ReceiptVerifier("dev.bonzer.weeka.app");
             JwsVerifier jv = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null,
                     Collections.singletonList(jwsRoot))) {

            warmUp(rv, jv, g5, jws, n);

            for (int round = 1; round <= 3; round++) {
                long receiptUs = timeUs(rv, g5, n);
                long jwsUs = timeUs(jv, jws, n);
                System.out.println("swig round " + round + ": receipt " + receiptUs + " us, jws " + jwsUs + " us");
            }
        }
    }

    private static void warmUp(ReceiptVerifier rv, JwsVerifier jv, String g5, String jws, int n) throws Exception {
        for (int i = 0; i < n; i++) {
            rv.verifyBase64(g5);
            jv.verifyTransaction(jws);
        }
    }

    private static long timeUs(ReceiptVerifier rv, String g5, int n) throws Exception {
        long start = System.nanoTime();
        for (int i = 0; i < n; i++) rv.verifyBase64(g5);
        return (System.nanoTime() - start) / 1000 / n;
    }

    private static long timeUs(JwsVerifier jv, String jws, int n) throws Exception {
        long start = System.nanoTime();
        for (int i = 0; i < n; i++) jv.verifyTransaction(jws);
        return (System.nanoTime() - start) / 1000 / n;
    }

    private static String readTrimmed(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path))).replaceAll("\\s+", "");
    }
}
