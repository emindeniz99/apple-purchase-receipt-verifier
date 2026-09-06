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
import java.nio.file.Paths;
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

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");
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
        final Map<String, Object> expectedResponse = endpoint.verifyReceipt(request);
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
                            assertEquals(expectedResponse, endpoint.verifyReceipt(request));
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
