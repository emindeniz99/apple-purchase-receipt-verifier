package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * {@link Verifier} is documented as immutable and thread-safe, and the README
 * tells integrators to share one instance (a singleton bean, typically). That
 * is a claim about code nothing in the suite exercised concurrently.
 *
 * <p>Sixteen threads, released together, run fifty verifications each through
 * every method a shared instance would serve, and every answer has to equal
 * the answer a single thread gets. What this is written to catch is not a
 * lock that is missing but state that is shared: a cached parser, a reused
 * buffer, a verified payload published to another thread through non-final
 * fields.
 */
class ConcurrencyTest {

    private static final Path FIXTURES = TestFixtures.generated();
    private static final Path PUBLIC_RECEIPTS = TestFixtures.publicReceipts();
    private static final int THREADS = 16;
    private static final int ITERATIONS = 50;

    // A fixed clock so the endpoint response is comparable: request_date is
    // "now" by design, and two calls a millisecond apart legitimately differ
    // on it. Nothing else in the response moves with time.
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void oneSharedVerifierServesManyThreadsIdentically() throws Exception {
        final Verifier verifier = Checks.verifier(CLOCK, SyntheticReceipts.root(), root("jws-root.der"));

        final String receiptBase64 = SyntheticReceipts.base64();
        final String requestJson = "{\"receipt-data\":\"" + receiptBase64 + "\"}";
        final String jws = text(FIXTURES.resolve("transaction.jws"));

        // The single-threaded answers, taken first: the test compares against
        // what the library says when nothing is racing, not merely against
        // itself.
        final String expectedReceipt = describe(verifier.verifyReceipt(receiptBase64));
        final String expectedJson = verifier.verifyReceiptEndpoint(Environment.SANDBOX, requestJson);
        final String expectedTransaction = describe(verifier.verifySignedData(jws));
        assertTrue(expectedJson.startsWith("{\"status\":0,"), expectedJson);
        assertTrue(expectedReceipt.startsWith("{"), expectedReceipt);
        assertTrue(expectedTransaction.startsWith("{"), expectedTransaction);

        final Queue<Throwable> failures = new ConcurrentLinkedQueue<Throwable>();
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(THREADS);
        List<Thread> threads = new ArrayList<Thread>();
        for (int i = 0; i < THREADS; i++) {
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        start.await();
                        for (int n = 0; n < ITERATIONS; n++) {
                            assertEquals(expectedReceipt, describe(verifier.verifyReceipt(receiptBase64)));
                            assertEquals(
                                    expectedJson, verifier.verifyReceiptEndpoint(Environment.SANDBOX, requestJson));
                            assertEquals(expectedTransaction, describe(verifier.verifySignedData(jws)));
                        }
                    } catch (Throwable t) {
                        failures.add(t);
                    } finally {
                        done.countDown();
                    }
                }
            });
            threads.add(thread);
            thread.start();
        }
        start.countDown();
        assertTrue(done.await(2, TimeUnit.MINUTES), "the verification threads did not finish");
        for (Thread thread : threads) {
            thread.join();
        }
        assertTrue(failures.isEmpty(), "concurrent verification failed: " + failures);
    }

    /**
     * The test above warms the verifier single-threaded before any thread
     * starts, so a race that exists only on first use (lazy initialization
     * inside the verifier, Jackson or BouncyCastle, a cache filled by the
     * first caller) never runs in it. Here the instances are fresh and their
     * very first calls come from many threads at once, mixing every method
     * with passing and failing inputs. The expected answers come afterwards,
     * from a second fresh set used by one thread.
     *
     * <p>Class-level state (the shared BouncyCastle provider, the JSON
     * factories) is cold only when this class is the first to run in its
     * JVM, for example with {@code -Dtest=ConcurrencyTest}.</p>
     */
    @Test
    void freshInstancesAnswerTheirFirstConcurrentCallsAsOneThreadWould() throws Exception {
        final List<Callable<String>> racing = calls(new Instances());
        final int threadCount = 128;
        final String[] answers = new String[threadCount];
        final Queue<Throwable> failures = new ConcurrentLinkedQueue<Throwable>();
        final CountDownLatch ready = new CountDownLatch(threadCount);
        final CountDownLatch start = new CountDownLatch(1);
        List<Thread> threads = new ArrayList<Thread>();
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        ready.countDown();
                        start.await();
                        answers[index] = racing.get(index % racing.size()).call();
                    } catch (Throwable t) {
                        failures.add(t);
                    }
                }
            });
            threads.add(thread);
            thread.start();
        }
        assertTrue(ready.await(30, TimeUnit.SECONDS), "the threads did not start");
        start.countDown();
        for (Thread thread : threads) {
            thread.join(TimeUnit.SECONDS.toMillis(60));
            assertTrue(!thread.isAlive(), "a verification thread did not finish");
        }
        assertTrue(failures.isEmpty(), "concurrent first calls failed: " + failures);

        List<Callable<String>> alone = calls(new Instances());
        // The mix must really hold passing and failing inputs, or equal
        // answers would prove little.
        assertEquals("refused INVALID_SIGNATURE", alone.get(1).call());
        assertEquals("refused INVALID_SIGNATURE", alone.get(3).call());
        assertEquals("{\"status\":21003}", alone.get(5).call());
        assertTrue(alone.get(6).call().startsWith("{\"status\":0,"));
        assertTrue(alone.get(7).call().startsWith("{\"status\":0,"));
        for (int i = 0; i < threadCount; i++) {
            assertEquals(alone.get(i % alone.size()).call(), answers[i], "call " + (i % alone.size()));
        }
    }

    /** One set of verifiers, built and not yet used. */
    private static final class Instances {
        final Verifier generated;
        final Verifier gaps;
        final Verifier apple;

        Instances() throws Exception {
            generated = Checks.verifier(CLOCK, SyntheticReceipts.root(), root("jws-root.der"));
            gaps = Checks.verifier(CLOCK, SyntheticReceipts.root(), root("gaps-jws-root.der"));
            apple = Verifier.create(Config.builder().clock(CLOCK).build());
        }
    }

    /**
     * Every method, each with an input that verifies and one that does not.
     * An answer is the payload's own text, or the reason it was refused.
     */
    private static List<Callable<String>> calls(final Instances in) throws Exception {
        final String jws = text(FIXTURES.resolve("transaction.jws"));
        final String tamperedJws = text(FIXTURES.resolve("transaction-tampered-payload.jws"));
        // The receipts are SyntheticReceipts', whose chain carries the WWDR
        // marker 0.7 checks; the committed ones predate it.
        final String receipt = SyntheticReceipts.base64();
        final String tamperedReceipt = Base64.getEncoder().encodeToString(SyntheticReceipts.tamperedDer());
        final String genuine = text(PUBLIC_RECEIPTS.resolve("receipt-sandbox-g5.b64"));
        final String genuineLegacy = text(PUBLIC_RECEIPTS.resolve("receipt-sandbox-legacy.b64"));
        List<Callable<String>> calls = new ArrayList<Callable<String>>();
        calls.add(() -> describe(in.generated.verifySignedData(jws)));
        calls.add(() -> describe(in.gaps.verifySignedData(tamperedJws)));
        calls.add(() -> describe(in.generated.verifyReceipt(receipt)));
        calls.add(() -> describe(in.gaps.verifyReceipt(tamperedReceipt)));
        calls.add(() ->
                in.generated.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + receipt + "\"}"));
        calls.add(() -> in.generated.verifyReceiptEndpoint(
                Environment.SANDBOX, "{\"receipt-data\":\"" + tamperedReceipt + "\"}"));
        calls.add(() -> in.apple.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + genuine + "\"}"));
        calls.add(() ->
                in.apple.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + genuineLegacy + "\"}"));
        return calls;
    }

    /**
     * The payload's full text ({@link ReceiptPayload#toJson()} or the JWS
     * payload), so a field read from another thread's parse shows up, or the
     * reason it was refused.
     */
    private static String describe(VerificationResult<?> result) {
        return result.verified()
                ? String.valueOf(result.payload())
                : "refused " + result.failure().reason();
    }

    private static String text(Path path) throws Exception {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim();
    }

    private static X509Certificate root(String name) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve(name));
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }
}
