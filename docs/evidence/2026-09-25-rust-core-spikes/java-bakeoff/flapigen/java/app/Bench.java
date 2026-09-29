import bakeoff.flapigen.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.EnumSet;

/** Warm-up then 3 timed rounds of receipt and JWS verification (n from -Dbench.n, default 10000). */
public final class Bench {
    /** Entry point. */
    public static void main(String[] args) throws Exception {
        String f = "$REPO/fixtures";
        int n = Integer.getInteger("bench.n", 10000);
        String g5 = new String(Files.readAllBytes(Paths.get(f, "public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.UTF_8).replaceAll("\\s", "");
        String jws = new String(Files.readAllBytes(Paths.get(f, "generated/transaction.jws")), StandardCharsets.UTF_8).trim();
        byte[] jwsRoot = Files.readAllBytes(Paths.get(f, "generated/jws-root.der"));
        try (ReceiptVerifier rv = new ReceiptVerifier("dev.bonzer.weeka.app");
             JwsVerifier jv = new JwsVerifier("com.example.app", EnumSet.of(Environment.SANDBOX), null, Collections.singletonList(jwsRoot))) {
            for (int i = 0; i < n; i++) { rv.verifyBase64(g5); jv.verifyTransaction(jws); }
            for (int round = 1; round <= 3; round++) {
                long t0 = System.nanoTime();
                for (int i = 0; i < n; i++) rv.verifyBase64(g5);
                long t1 = System.nanoTime();
                for (int i = 0; i < n; i++) jv.verifyTransaction(jws);
                long t2 = System.nanoTime();
                System.out.printf("flapigen round %d: receipt %.1f us, jws %.1f us%n",
                        round, (t1 - t0) / 1000.0 / n, (t2 - t1) / 1000.0 / n);
            }
        }
    }
}
