package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Evidence only (2026-11-02, ABI 0.2.0 enum lift): calls aprv.wasm's
 * verify-receipt-endpoint on Endive with env 0, 1, 2, 255 and 2^32-1 and
 * prints a value (its status) or the exception's class and message. Copy it
 * to java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/,
 * place the module (.github/scripts/place-module.sh <out> java), and run
 * `mvn -f java-wasm test -Dtest=EndiveTrapProbe -DexcludedGroups=server`.
 */
@Tag("endive")
class EndiveTrapProbe {
    @Test
    void probe() throws Exception {
        byte[] g5 = Base64.getEncoder().encode(Cases.fixtureBytes("public-receipt-sandbox-g5"));
        byte[] request = ("{\"receipt-data\":\"" + new String(g5, StandardCharsets.US_ASCII) + "\"}")
                .getBytes(StandardCharsets.US_ASCII);
        for (int env : new int[] {0, 1, 2, 255, -1}) {
            EndiveGuest guest = new EndiveGuest(new SecureRandom());
            guest.init(new byte[0]);
            String label = "endpoint env " + Integer.toUnsignedString(env);
            try {
                String out = guest.verifyReceiptEndpoint(env, 1_793_577_600_000L, request);
                System.out.println("PROBE " + label + ": value " + out.substring(0, Math.min(out.length(), 20)));
            } catch (RuntimeException e) {
                Throwable root = e;
                while (root.getCause() != null) {
                    root = root.getCause();
                }
                System.out.println("PROBE " + label + ": " + e.getClass().getName() + ": " + e.getMessage()
                        + " (root " + root.getClass().getName() + ": " + root.getMessage() + ")");
            }
        }
    }
}
