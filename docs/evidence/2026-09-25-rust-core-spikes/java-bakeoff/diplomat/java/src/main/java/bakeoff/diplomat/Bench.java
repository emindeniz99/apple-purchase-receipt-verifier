package bakeoff.diplomat;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Times receipt and JWS verification through the Diplomat-generated API.
 * {@code -Dbench.n=N} sets calls per round (default 10,000).
 */
public final class Bench {
    private Bench() {}

    /**
     * Warms up, then runs three timed rounds.
     *
     * @param args unused
     * @throws Exception on fixture I/O failure
     */
    public static void main(String[] args) throws Exception {
        String f = "$REPO/fixtures/";
        int n = Integer.getInteger("bench.n", 10000);
        String g5 = new String(Files.readAllBytes(Paths.get(f + "public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
        String jws = new String(Files.readAllBytes(Paths.get(f + "generated/transaction.jws")), "UTF-8").trim();
        ReceiptVerifier rv = ReceiptVerifier.create("dev.bonzer.weeka.app", null).verifier();
        TrustRoots roots = TrustRoots.create();
        roots.addDer(Files.readAllBytes(Paths.get(f + "generated/jws-root.der")));
        EnvironmentSet envs = EnvironmentSet.create();
        envs.add(Environment.Sandbox);
        JwsVerifier jv = JwsVerifier.create("com.example.app", envs, null, roots).verifier();

        for (int i = 0; i < n; i++) {
            rv.verifyBase64(g5).receipt();
            jv.verifyTransaction(jws).payload();
        }
        for (int round = 1; round <= 3; round++) {
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                if (rv.verifyBase64(g5).receipt() == null) throw new IllegalStateException("receipt failed");
            }
            long t1 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                if (jv.verifyTransaction(jws).payload() == null) throw new IllegalStateException("jws failed");
            }
            long t2 = System.nanoTime();
            System.out.printf("diplomat round %d: receipt %.1f us, jws %.1f us%n",
                    round, (t1 - t0) / 1000.0 / n, (t2 - t1) / 1000.0 / n);
        }
    }
}
