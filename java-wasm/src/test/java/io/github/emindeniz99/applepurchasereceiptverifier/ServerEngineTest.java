package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The managed child of the server engine, the 13 managed-mode checks of the
 * aprv-server spike on Java 8 (docs/evidence/2026-09-26-aprv-server.md §6,
 * java/Tests.java), against lane B's server through
 * {@link ServerSource#executable}. The spike crashed its child through a
 * spike-only route; here the child is sent {@code SIGABRT}, which is what an
 * abort in the child does.
 *
 * <p>The operations are checked on the bytes the server returns, as the
 * spike checked them; {@link ServerConformanceCasesTest} checks the facade's
 * decoded results.</p>
 */
@Tag("server")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ServerEngineTest {

    private static ServerVerifier verifier;
    private static String g5;
    private static String jws;
    private static String endpointBody;
    private static final long NOW = System.currentTimeMillis();

    @BeforeAll
    static void start() throws Exception {
        g5 = Cases.receiptString(Cases.MAPPER.readTree("{\"fixture\":\"public-receipt-sandbox-g5\"}"));
        jws = Cases.text(Cases.fixtureBytes("transaction"));
        endpointBody = "{\"receipt-data\":\"" + g5 + "\"}";
        long t0 = System.nanoTime();
        verifier = (ServerVerifier)
                Verifier.create(Config.defaults(), Engine.server(ServerSource.executable(ServerTests.binary())));
        System.out.println(
                "server engine: child started and /v1/info checked in " + (System.nanoTime() - t0) / 1_000_000 + " ms");
    }

    @AfterAll
    static void stop() {
        if (verifier != null) {
            verifier.close();
        }
    }

    private static String raw(String path, String body) {
        ServerConnection.Response response =
                verifier.connection().send("POST", path, body.getBytes(StandardCharsets.UTF_8), NOW);
        assertEquals(200, response.status, response.text());
        return response.text();
    }

    private static long pid() {
        return verifier.connection().process().pid();
    }

    @Test
    @Order(1)
    void theChildStartedOnLoopbackWithTheTokenOnStdin() {
        assertTrue(ServerTests.alive(pid()), "pid " + pid());
        ServerConnection.Target target = verifier.connection().process().target();
        assertEquals("127.0.0.1", target.host);
        assertEquals(64, target.token.length(), "a 256-bit token in hex");
    }

    @Test
    @Order(2)
    void theOperationsAnswer() {
        long t = System.nanoTime();
        String receipt = raw("/v1/receipt/verify", g5);
        System.out.println("   g5 through the child: " + (System.nanoTime() - t) / 1000 + " us");
        assertTrue(receipt.startsWith("{\"verified\":true") && receipt.contains("dev.bonzer.weeka.app"), receipt);
        String signed = raw("/v1/signed-data/verify", jws);
        assertTrue(signed.contains("\"verified\":false"), "the shared-sandbox JWS under Apple's roots: " + signed);
        String sandbox = verifier.verifyReceiptEndpoint(Environment.SANDBOX, endpointBody);
        assertTrue(sandbox.contains("\"status\":0"), sandbox);
        String production = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, endpointBody);
        assertEquals("{\"status\":21007}", production);
        String garbage = raw("/v1/receipt/verify", "not base64!");
        assertTrue(garbage.contains("\"verified\":false"), "a verification failure is a value: " + garbage);
    }

    @Test
    @Order(3)
    void aRequestWithoutTheTokenOrWithAWrongOneIsRefused() throws Exception {
        ServerConnection.Target real = verifier.connection().process().target();
        for (String token : new String[] {null, real.token.replace('a', 'b').replace('0', '1') + "x"}) {
            ServerConnection.Target target = new ServerConnection.Target(real.host, real.port, false, "", token, 0);
            ServerConnection.Response response = ServerConnection.exchange(
                    target, "POST", "/v1/receipt/verify", g5.getBytes(StandardCharsets.US_ASCII), NOW, 2000, 10_000);
            assertEquals(401, response.status, response.text());
            assertEquals("UNAUTHORIZED", ServerJson.problem(response).code());
        }
    }

    @Test
    @Order(4)
    void aBodyOverTheCapIsTooLarge() {
        char[] big = new char[3_145_729];
        Arrays.fill(big, 'A');
        String over = new String(big);
        Failure failure = verifier.verifyReceipt(over).failure();
        assertEquals(Reason.TOO_LARGE, failure.reason(), failure.message());
        assertEquals(
                "{\"status\":21002}",
                verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + over + "\"}"));
    }

    /**
     * An input past the server's 16 MiB drain limit: the server reads only
     * 3,145,729 bytes of a body announced that large and closes after its
     * answer, so an engine that sent the whole input would meet a reset
     * (INTERNAL_ERROR). The engine cuts the input as Endive does, and the
     * verdict is the module's, as on Endive.
     */
    @Test
    @Order(4)
    void anInputOverTheDrainLimitIsTooLargeAsOnEndive() {
        char[] big = new char[20 << 20];
        Arrays.fill(big, 'A');
        String twentyMib = new String(big);
        Failure receipt = verifier.verifyReceipt(twentyMib).failure();
        assertEquals(Reason.TOO_LARGE, receipt.reason(), receipt.message());
        assertEquals("receipt exceeds the maximum accepted size of 3145728 bytes", receipt.message());
        Failure signed = verifier.verifySignedData(twentyMib).failure();
        assertEquals(Reason.TOO_LARGE, signed.reason(), signed.message());
        assertEquals(
                "{\"status\":21002}",
                verifier.verifyReceiptEndpoint(Environment.PRODUCTION, "{\"receipt-data\":\"" + twentyMib + "\"}"));
        assertEquals(
                "{\"status\":21002}",
                verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + twentyMib + "\"}"));
    }

    @Test
    @Order(5)
    void aChildThatAbortsIsStartedAgainByTheNextCall() throws Exception {
        long before = pid();
        ServerTests.kill(before, "ABRT");
        assertTrue(ServerTests.gone(before, 2000), "the child aborted: pid " + before);
        long t = System.nanoTime();
        String after = raw("/v1/receipt/verify", g5);
        long micros = (System.nanoTime() - t) / 1000;
        assertTrue(after.startsWith("{\"verified\":true"), after);
        assertEquals(1, verifier.connection().process().restarts());
        assertNotEquals(before, pid());
        assertTrue(ServerTests.alive(pid()));
        System.out.println("   the call that restarted the child: " + micros + " us");
    }

    @Test
    @Order(6)
    void aChildKilledWithSigkillIsStartedAgain() throws Exception {
        long victim = pid();
        ServerTests.kill(victim, "KILL");
        assertTrue(ServerTests.gone(victim, 2000));
        String again = verifier.verifyReceiptEndpoint(Environment.SANDBOX, endpointBody);
        assertTrue(again.contains("\"status\":0"), again);
        assertEquals(2, verifier.connection().process().restarts());
        assertNotEquals(victim, pid());
    }

    @Test
    @Order(7)
    void roundTripTimes() throws Exception {
        ServerConnection connection = verifier.connection();
        for (int i = 0; i < 2000; i++) {
            connection.send("GET", "/healthz", new byte[0], null);
        }
        int n = 5000;
        long t = System.nanoTime();
        for (int i = 0; i < n; i++) {
            connection.send("GET", "/healthz", new byte[0], null);
        }
        System.out.printf("BENCH GET /healthz round trip: %.1f us%n", (System.nanoTime() - t) / 1000.0 / n);
        byte[] body = g5.getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 300; i++) {
            connection.send("POST", "/v1/receipt/verify", body, NOW);
        }
        n = 1000;
        long[] latencies = new long[n];
        t = System.nanoTime();
        for (int i = 0; i < n; i++) {
            long s = System.nanoTime();
            connection.send("POST", "/v1/receipt/verify", body, NOW);
            latencies[i] = System.nanoTime() - s;
        }
        long total = System.nanoTime() - t;
        Arrays.sort(latencies);
        System.out.printf(
                "BENCH g5 through the server engine on Java %d, 1 thread: mean %.0f us, p50 %d us, p99 %d us, %.0f/s%n",
                Engine.javaFeatureVersion(),
                total / 1000.0 / n,
                latencies[n / 2] / 1000,
                latencies[n * 99 / 100] / 1000,
                n * 1e9 / total);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        AtomicInteger done = new AtomicInteger();
        long end = System.nanoTime() + 5_000_000_000L;
        t = System.nanoTime();
        List<Future<?>> workers = new ArrayList<>();
        for (int k = 0; k < 4; k++) {
            workers.add(pool.submit(() -> {
                while (System.nanoTime() < end) {
                    connection.send("POST", "/v1/receipt/verify", body, NOW);
                    done.incrementAndGet();
                }
                return null;
            }));
        }
        for (Future<?> worker : workers) {
            worker.get();
        }
        pool.shutdown();
        System.out.printf(
                "BENCH g5 through the server engine, 4 threads, 5 s: %.0f/s%n",
                done.get() * 1e9 / (System.nanoTime() - t));
    }

    @Test
    @Order(8)
    void closeStopsTheChild() throws Exception {
        long last = pid();
        verifier.close();
        assertTrue(ServerTests.gone(last, 3000), "pid " + last);
        Failure failure = verifier.verifyReceipt(g5).failure();
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertTrue(failure.cause() instanceof ServerProcessFailure, String.valueOf(failure.cause()));
    }
}
