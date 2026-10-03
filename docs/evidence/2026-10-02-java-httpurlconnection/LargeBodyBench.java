package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Throwaway bench for docs/evidence/2026-10-02-java-httpurlconnection.md:
 * one managed child, POST /v1/receipt/verify with the 7,556-byte g5 receipt
 * and the 105,472-byte legacy one, through the engine's own connection.
 * Copy into java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/.
 * It compiles against both the hand-written client and HttpURLConnection,
 * because it never names the response type.
 */
@Tag("server")
class LargeBodyBench {

    @Test
    void bench() throws Exception {
        ServerVerifier verifier = (ServerVerifier)
                Verifier.create(Config.defaults(), Engine.server(ServerSource.executable(ServerTests.binary())));
        try {
            for (String name : new String[] {"receipt-sandbox-g5", "receipt-sandbox-legacy"}) {
                String text = new String(
                                Files.readAllBytes(Paths.get("..", "fixtures", "public-receipts", name + ".b64")),
                                StandardCharsets.US_ASCII)
                        .trim();
                System.out.println("   " + name + ": " + verifier.verifyReceipt(text).failure());
                byte[] body = text.getBytes(StandardCharsets.US_ASCII);
                long now = System.currentTimeMillis();
                ServerConnection connection = verifier.connection();
                for (int i = 0; i < 300; i++) {
                    connection.send("POST", "/v1/receipt/verify", body, now);
                }
                int n = 1000;
                long[] latencies = new long[n];
                for (int i = 0; i < n; i++) {
                    long s = System.nanoTime();
                    connection.send("POST", "/v1/receipt/verify", body, now);
                    latencies[i] = System.nanoTime() - s;
                }
                Arrays.sort(latencies);
                long sum = 0;
                for (long latency : latencies) {
                    sum += latency;
                }
                System.out.printf(
                        "BENCH %s (%d bytes) on Java %d: mean %d us, p50 %d us, p99 %d us%n",
                        name,
                        body.length,
                        Engine.javaFeatureVersion(),
                        sum / n / 1000,
                        latencies[n / 2] / 1000,
                        latencies[n * 99 / 100] / 1000);
            }
        } finally {
            verifier.close();
        }
    }
}
