package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Probe7: smallest thread stack on which a genuine receipt / JWS / endpoint call completes (cold and warm). */
public class Probe7MinStack {
    public static void main(String[] a) throws Exception {
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        TestPki pki = TestPki.jws();
        String jws = pki.signJws(TestPki.claims("signedDate", System.currentTimeMillis(), "environment", "Sandbox"));
        Verifier v = Verifier.create(Config.defaults());
        Verifier v2 = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        for (int kb : new int[]{64, 80, 96, 112, 128, 160, 192, 256}) {
            for (String what : new String[]{"receipt", "jws", "endpoint"}) {
                final String[] res = new String[1];
                Thread t = new Thread(null, () -> {
                    try {
                        boolean ok = what.equals("receipt") ? v.verifyReceipt(src).verified() : what.equals("jws") ? v2.verifySignedData(jws).verified() : v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + src + "\"}").startsWith("{\"status\":0");
                        res[0] = ok ? "ok" : "fail";
                    } catch (Throwable th) { res[0] = "ESCAPED " + th.getClass().getSimpleName(); }
                }, "t", kb * 1024L);
                t.start(); t.join();
                System.out.print("stack=" + kb + "k " + what + "=" + res[0] + "  ");
            }
            System.out.println();
        }
    }
}
