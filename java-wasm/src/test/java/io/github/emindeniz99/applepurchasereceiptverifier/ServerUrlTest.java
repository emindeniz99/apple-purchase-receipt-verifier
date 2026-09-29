package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@link ServerSource#url}: a server the caller runs, with a token. The
 * JVM starts nothing. The spike's six URL-mode checks, plus the refusals: a
 * wrong token and a server that trusts other roots than the config.
 */
@Tag("server")
class ServerUrlTest {

    @TempDir
    Path temp;

    @Test
    void aServerTheCallerRunsAnswersAndNothingIsStarted() throws Exception {
        try (ServerTests.Standalone server = new ServerTests.Standalone(temp)) {
            ServerVerifier verifier = (ServerVerifier)
                    Verifier.create(Config.defaults(), Engine.server(ServerSource.url(server.uri(), server.token)));
            try {
                assertEquals(null, verifier.connection().process(), "no child: the url source starts nothing");
                String g5 = Cases.receiptString(Cases.MAPPER.readTree("{\"fixture\":\"public-receipt-sandbox-g5\"}"));
                long now = System.currentTimeMillis();
                String receipt = verifier.connection()
                        .send("POST", "/v1/receipt/verify", g5.getBytes(StandardCharsets.US_ASCII), now)
                        .text();
                assertTrue(receipt.startsWith("{\"verified\":true"), receipt);
                String jws = verifier.connection()
                        .send("POST", "/v1/signed-data/verify", Cases.fixtureBytes("transaction"), now)
                        .text();
                assertTrue(jws.contains("\"verified\":false"), jws);
                String body = "{\"receipt-data\":\"" + g5 + "\"}";
                assertTrue(verifier.verifyReceiptEndpoint(Environment.SANDBOX, body)
                        .contains("\"status\":0"));
                assertEquals("{\"status\":21007}", verifier.verifyReceiptEndpoint(Environment.PRODUCTION, body));
                String garbage = verifier.connection()
                        .send("POST", "/v1/receipt/verify", "not base64!".getBytes(StandardCharsets.US_ASCII), now)
                        .text();
                assertTrue(garbage.contains("\"verified\":false"), garbage);
                long t = System.nanoTime();
                for (int i = 0; i < 100; i++) {
                    verifier.connection()
                            .send("POST", "/v1/receipt/verify", g5.getBytes(StandardCharsets.US_ASCII), now);
                }
                System.out.printf("BENCH url source, g5: %.0f us per call%n", (System.nanoTime() - t) / 1000.0 / 100);
            } finally {
                verifier.close();
            }
            assertTrue(server.process.isAlive(), "closing the verifier leaves the caller's server running");
        }
    }

    @Test
    void aWrongTokenFailsTheSourceAtCreateAndTheCallsWithoutTheProbe() throws Exception {
        try (ServerTests.Standalone server = new ServerTests.Standalone(temp)) {
            Engine.Server engine = Engine.server(ServerSource.url(server.uri(), "wrong-token-0123456789"));
            IllegalStateException e =
                    assertThrows(IllegalStateException.class, () -> Verifier.create(Config.defaults(), engine));
            assertTrue(e.getMessage().contains("401") && e.getMessage().contains("UNAUTHORIZED"), e.getMessage());
            Verifier lazy = Verifier.create(Config.builder().runtimeProbe(false).build(), engine);
            Failure failure = lazy.verifySignedData("x").failure();
            assertEquals(Reason.INTERNAL_ERROR, failure.reason());
            assertTrue(failure.cause() instanceof ServerProcessFailure, String.valueOf(failure.cause()));
            assertEquals("{\"status\":21009}", lazy.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
        }
    }

    /** The server runs Apple's roots; a config with the JWS fixture's own root must not use it. */
    @Test
    void aServerThatTrustsOtherRootsIsRefused() throws Exception {
        try (ServerTests.Standalone server = new ServerTests.Standalone(temp)) {
            Config other = Config.builder()
                    .roots(Cases.roots(Cases.MAPPER.readTree("[\"jws-root\"]")))
                    .build();
            IllegalStateException e = assertThrows(
                    IllegalStateException.class,
                    () -> Verifier.create(other, Engine.server(ServerSource.url(server.uri(), server.token))));
            assertTrue(e.getMessage().contains("trusts other roots"), e.getMessage());
        }
    }
}
