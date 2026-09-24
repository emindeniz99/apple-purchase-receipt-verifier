package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
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
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The verifiers are documented as thread-safe once constructed, and the README
 * tells integrators to share one instance (a singleton bean, typically). That
 * is a claim about code nothing in the suite exercised concurrently.
 *
 * <p>Sixteen threads, released together, run fifty verifications each through
 * every entry point that a shared instance would serve, and every answer has to
 * equal the answer a single thread gets. What this is written to catch is not a
 * lock that is missing but state that is shared: a cached parser, a reused
 * buffer, a verified payload published to another thread through non-final
 * fields, the last being why {@code TransactionPayload} and
 * {@code AppTransactionPayload} take their claims through a constructor rather
 * than having Jackson write them in afterwards.
 */
class ConcurrencyTest {

    private static final Path FIXTURES = TestFixtures.generated();
    private static final Path PUBLIC_RECEIPTS = TestFixtures.publicReceipts();
    private static final String BUNDLE = "com.example.app";
    private static final int THREADS = 16;
    private static final int ITERATIONS = 50;

    @Test
    void oneSharedInstanceOfEachVerifierServesManyThreadsIdentically() throws Exception {
        final ReceiptVerifier receipts = new ReceiptVerifier(Collections.singleton(root("receipt-root.der")), BUNDLE);
        // A fixed clock so the response is comparable: request_date is "now"
        // by design, and two calls a millisecond apart legitimately differ on
        // it. Nothing else in the response moves with time.
        final VerifyReceiptEndpoint endpoint = new VerifyReceiptEndpoint(
                Collections.singleton(root("receipt-root.der")),
                Environment.SANDBOX,
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        final JwsVerifier transactions =
                new JwsVerifier(Collections.singleton(root("jws-root.der")), BUNDLE, EnumSet.of(Environment.SANDBOX));

        final String receiptBase64 =
                Base64.getEncoder().encodeToString(Files.readAllBytes(FIXTURES.resolve("receipt.der")));
        final Map<String, Object> request = Collections.<String, Object>singletonMap("receipt-data", receiptBase64);
        final String requestJson = "{\"receipt-data\":\"" + receiptBase64 + "\"}";
        final String jws =
                new String(Files.readAllBytes(FIXTURES.resolve("transaction.jws")), StandardCharsets.UTF_8).trim();

        // The single-threaded answers, taken first: the test compares against
        // what the library says when nothing is racing, not merely against
        // itself.
        final String expectedReceipt = describe(receipts.verify(receiptBase64));
        final Map<String, Object> expectedResponse =
                endpoint.verifyReceiptResult(request).toResponse();
        final String expectedJson = endpoint.verifyReceiptJson(requestJson);
        final String expectedTransaction = describe(transactions.verifyTransaction(jws));
        assertEquals(Integer.valueOf(VerifyReceiptEndpoint.STATUS_OK), expectedResponse.get("status"));

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
                            assertEquals(expectedReceipt, describe(receipts.verify(receiptBase64)));
                            assertEquals(
                                    expectedResponse,
                                    endpoint.verifyReceiptResult(request).toResponse());
                            assertEquals(expectedJson, endpoint.verifyReceiptJson(requestJson));
                            assertEquals(expectedTransaction, describe(transactions.verifyTransaction(jws)));
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
     * The test above warms every verifier single-threaded before any thread
     * starts, so a race that exists only on first use (lazy initialization
     * inside the verifiers, Jackson or BouncyCastle, a cache filled by the
     * first caller) never runs in it. Here the instances are fresh and their
     * very first calls come from many threads at once, mixing every entry
     * point with passing and failing inputs. The expected answers come
     * afterwards, from a second fresh set used by one thread.
     *
     * <p>Class-level state (the shared BouncyCastle provider, the claim
     * mappers, the signer-verifier builder) is cold only when this class is
     * the first to run in its JVM, for example with
     * {@code -Dtest=ConcurrencyTest}.</p>
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
        assertEquals("refused INVALID_SIGNATURE", alone.get(5).call());
        assertEquals("{\"status\":21003}", alone.get(7).call());
        assertTrue(alone.get(8).call().startsWith("{\"status\":0,"));
        assertTrue(alone.get(9).call().startsWith("{\"status\":0,"));
        for (int i = 0; i < threadCount; i++) {
            assertEquals(alone.get(i % alone.size()).call(), answers[i], "call " + (i % alone.size()));
        }
    }

    /** One set of verifiers and an endpoint, built and not yet used. */
    private static final class Instances {
        final JwsVerifier jws;
        final JwsVerifier gapsJws;
        final ReceiptVerifier receipts;
        final ReceiptVerifier gapsReceipts;
        final VerifyReceiptEndpoint endpoint;
        final VerifyReceiptEndpoint appleEndpoint;

        Instances() throws Exception {
            Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
            jws = new JwsVerifier(Collections.singleton(root("jws-root.der")), BUNDLE, EnumSet.of(Environment.SANDBOX));
            gapsJws = new JwsVerifier(
                    Collections.singleton(root("gaps-jws-root.der")), BUNDLE, EnumSet.of(Environment.SANDBOX));
            receipts = new ReceiptVerifier(Collections.singleton(root("receipt-root.der")), BUNDLE);
            gapsReceipts = new ReceiptVerifier(Collections.singleton(root("gaps-receipt-root.der")), BUNDLE);
            endpoint = new VerifyReceiptEndpoint(
                    Collections.singleton(root("receipt-root.der")), Environment.SANDBOX, clock);
            appleEndpoint = new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), Environment.SANDBOX, clock);
        }
    }

    /**
     * Every entry point, each with an input that verifies and one that does
     * not. An answer is the described payload, or the reason it was refused.
     */
    private static List<Callable<String>> calls(final Instances in) throws Exception {
        final String jws = text(FIXTURES.resolve("transaction.jws"));
        final String tamperedJws = text(FIXTURES.resolve("transaction-tampered-payload.jws"));
        final String receipt = Base64.getEncoder().encodeToString(Files.readAllBytes(FIXTURES.resolve("receipt.der")));
        final String tamperedReceipt = Base64.getEncoder()
                .encodeToString(Files.readAllBytes(FIXTURES.resolve("receipt-tampered-payload.der")));
        final String genuine = text(PUBLIC_RECEIPTS.resolve("receipt-sandbox-g5.b64"));
        final String genuineLegacy = text(PUBLIC_RECEIPTS.resolve("receipt-sandbox-legacy.b64"));
        List<Callable<String>> calls = new ArrayList<Callable<String>>();
        calls.add(() -> describe(in.jws.verifyTransaction(jws)));
        calls.add(() -> refusal(() -> in.gapsJws.verifyTransaction(tamperedJws)));
        calls.add(() -> String.valueOf(in.jws.verifyRaw(jws)));
        calls.add(() -> refusal(() -> in.gapsJws.verifyRaw(tamperedJws)));
        calls.add(() -> describe(in.receipts.verify(receipt)));
        calls.add(() -> refusal(() -> in.gapsReceipts.verify(tamperedReceipt)));
        calls.add(() -> in.endpoint.verifyReceiptJson("{\"receipt-data\":\"" + receipt + "\"}"));
        calls.add(() -> in.endpoint.verifyReceiptData(tamperedReceipt).toJson());
        calls.add(() -> in.appleEndpoint.verifyReceiptData(genuine).toJson());
        calls.add(() -> in.appleEndpoint.verifyReceiptJson("{\"receipt-data\":\"" + genuineLegacy + "\"}"));
        return calls;
    }

    private interface Verification {
        Object run() throws VerificationException;
    }

    private static String refusal(Verification verification) {
        try {
            return "verified " + verification.run();
        } catch (VerificationException e) {
            return "refused " + e.reason();
        }
    }

    private static String text(Path path) throws Exception {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim();
    }

    /** Enough of a verified receipt to notice a claim read from another thread's parse. */
    private static String describe(AppReceipt receipt) {
        return receipt.bundleId() + "|" + receipt.receiptType() + "|" + receipt.appVersion() + "|"
                + receipt.creationDate() + "|" + receipt.inAppPurchases().size() + "|"
                + receipt.unknownAttributes().keySet();
    }

    /** Every modelled claim, so a field left unwritten by a racing bind shows up. */
    private static String describe(TransactionPayload payload) {
        return payload.bundleId() + "|" + payload.environment() + "|" + payload.productId() + "|"
                + payload.transactionId() + "|" + payload.originalTransactionId() + "|" + payload.quantity() + "|"
                + payload.type() + "|" + payload.inAppOwnershipType() + "|" + payload.signedDate() + "|"
                + payload.purchaseDate() + "|" + payload.originalPurchaseDate() + "|" + payload.expiresDate();
    }

    private static X509Certificate root(String name) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve(name));
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }
}
