package aprvj.bench;

import aprvj.Bridge;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The JVM side of the benchmark: the same inputs, operations and
 * measurements as c/harness.c's bench mode, on the same Bridge code the
 * native image runs (so both sides pay for the same JSON output).
 *
 *   java -cp <bridge + verifier + deps + this> aprvj.bench.JvmBench <fixtures> <op> <threads> <seconds> <warmup-seconds>
 *
 * op: receipt | jws | endpoint (through Bridge, JSON out, as the C ABI does),
 *     receipt-direct | jws-direct (the library's own call, object out: what
 *     a JVM user of the Maven artifact pays).
 * Prints one JSON line. "jvm_start_to_ready_ms" is the time from JVM start
 * (RuntimeMXBean) to the first verdict of the benchmarked operation.
 */
public final class JvmBench {

    static final String BUNDLE = "dev.bonzer.weeka.app";

    interface Op {
        String call() throws Exception;
    }

    static byte[] receiptB64;
    static String jws;
    static String body;
    static String jwsOptions;

    static Op open(String op) throws Exception {
        if (op.equals("receipt")) {
            final Object v = Bridge.newReceiptVerifier("{\"bundleId\":\"" + BUNDLE + "\"}");
            return () -> check(Bridge.verifyReceipt(v, receiptB64, true, null));
        }
        if (op.equals("jws")) {
            final Object v = Bridge.newJwsVerifier(jwsOptions);
            return () -> check(Bridge.verifyJws(v, jws, Bridge.JWS_TRANSACTION));
        }
        if (op.equals("endpoint")) {
            final Object v = Bridge.newEndpoint("{\"environment\":\"Sandbox\",\"nowMillis\":1767225600000}");
            return () -> check(Bridge.verifyReceiptJson(v, body));
        }
        if (op.equals("receipt-direct")) {
            final ReceiptVerifier v = Bridge.newReceiptVerifier("{\"bundleId\":\"" + BUNDLE + "\"}");
            final String text = new String(receiptB64, StandardCharsets.US_ASCII);
            return () -> v.verify(text, null).bundleId();
        }
        if (op.equals("jws-direct")) {
            final JwsVerifier v = Bridge.newJwsVerifier(jwsOptions);
            return () -> v.verifyTransaction(jws).transactionId();
        }
        throw new IllegalArgumentException(op);
    }

    static String check(Bridge.Result r) {
        if (r.code != 0) {
            throw new IllegalStateException("code " + r.code + " " + r.json);
        }
        return r.json;
    }

    static long rssKb() {
        try (BufferedReader in = new BufferedReader(new FileReader("/proc/self/status"))) {
            for (String line; (line = in.readLine()) != null; ) {
                if (line.startsWith("VmRSS:")) {
                    return Long.parseLong(line.replaceAll("[^0-9]", ""));
                }
            }
        } catch (Exception ignored) {
            // not Linux
        }
        return -1;
    }

    public static void main(String[] args) throws Exception {
        String fixtures = args[0];
        final String op = args[1];
        int threads = Integer.parseInt(args[2]);
        final double seconds = Double.parseDouble(args[3]);
        double warmupSeconds = Double.parseDouble(args[4]);
        long rssStart = rssKb();

        String wrapped = new String(Files.readAllBytes(Paths.get(fixtures, "public-receipts/receipt-sandbox-g5.b64")),
                StandardCharsets.US_ASCII);
        String unwrapped = wrapped.replace("\n", "").replace("\r", "").trim();
        receiptB64 = unwrapped.getBytes(StandardCharsets.US_ASCII);
        jws = new String(Files.readAllBytes(Paths.get(fixtures, "generated/transaction.jws")), StandardCharsets.US_ASCII).trim();
        body = "{\"receipt-data\":\"" + unwrapped + "\"}";
        byte[] root = Files.readAllBytes(Paths.get(fixtures, "generated/jws-root.der"));
        jwsOptions = "{\"bundleId\":\"com.example.app\",\"acceptedEnvironments\":[\"Sandbox\"],\"roots\":[\""
                + Base64.getEncoder().encodeToString(root) + "\"]}";

        long t0 = System.nanoTime();
        Op main = open(op);
        long t1 = System.nanoTime();
        final String reference = main.call();
        long t2 = System.nanoTime();
        long ready = System.currentTimeMillis() - ManagementFactory.getRuntimeMXBean().getStartTime();

        long warmEnd = System.nanoTime() + (long) (warmupSeconds * 1e9);
        long warm = 0;
        while (System.nanoTime() < warmEnd) {
            main.call();
            warm++;
        }
        final int n = 2000;
        double[] lat = new double[n];
        for (int i = 0; i < n; i++) {
            long a = System.nanoTime();
            main.call();
            lat[i] = (System.nanoTime() - a) / 1e3;
        }
        Arrays.sort(lat);
        double sum = 0;
        for (double l : lat) {
            sum += l;
        }
        long rssWarm = rssKb();

        final AtomicLong calls = new AtomicLong();
        final AtomicLong bad = new AtomicLong();
        Thread[] workers = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            workers[i] = new Thread(() -> {
                try {
                    Op mine = open(op);
                    long end = System.nanoTime() + (long) (seconds * 1e9);
                    while (System.nanoTime() < end) {
                        for (int k = 0; k < 20; k++) {
                            String out;
                            try {
                                out = mine.call();
                            } catch (Exception e) {
                                out = null;
                            }
                            if (out == null || !out.equals(reference)) {
                                bad.incrementAndGet();
                            }
                            calls.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    bad.addAndGet(1_000_000);
                }
            });
            workers[i].start();
        }
        for (Thread w : workers) {
            w.join();
        }
        long rssLoad = rssKb();
        System.out.printf(java.util.Locale.ROOT,
                "{\"op\":\"%s\",\"threads\":%d,\"java\":\"%s\",\"jvm_start_to_ready_ms\":%d,\"ctx_open_ms\":%.2f,"
                        + "\"first_call_ms\":%.2f,\"warmup_calls\":%d,\"mean_us\":%.1f,\"p50_us\":%.1f,\"p99_us\":%.1f,"
                        + "\"throughput_per_s\":%.0f,\"calls\":%d,\"mismatched\":%d,\"rss_kb_at_main\":%d,"
                        + "\"rss_kb_after_warmup\":%d,\"rss_kb_after_load\":%d}%n",
                op, threads, System.getProperty("java.version"), ready, (t1 - t0) / 1e6, (t2 - t1) / 1e6, warm,
                sum / n, lat[n / 2], lat[n * 99 / 100], calls.get() / seconds, calls.get(), bad.get(), rssStart,
                rssWarm, rssLoad);
    }

    private JvmBench() {}
}
