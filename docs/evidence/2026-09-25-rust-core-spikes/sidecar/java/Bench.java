import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Timing measurements for the research spike. Each phase is a separate
 * process invocation ({@code java Bench <phase>}), run sequentially with
 * nothing else running, per the spike's rules.
 *
 * <p>Phases: {@code coldstart}, {@code latency}, {@code throughput}.
 */
public final class Bench {

    private static final int WARMUP = 2000;
    private static final int LATENCY_CALLS = 10000;
    private static final int THROUGHPUT_THREADS = 8;
    private static final int THROUGHPUT_CALLS_PER_THREAD = 2000;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: Bench <coldstart|latency|throughput>");
            System.exit(2);
        }
        String fixturesDir = System.getProperty(
                "aprv.demo.fixtures", "$REPO/fixtures");
        String receiptPath = fixturesDir + "/public-receipts/receipt-sandbox-g5.b64";
        String b64 = new String(Files.readAllBytes(Paths.get(receiptPath)), StandardCharsets.UTF_8)
                .replaceAll("\\s+", "");
        String body = "{\"receipt-data\":\"" + b64 + "\"}";

        switch (args[0]) {
            case "coldstart":
                coldStart();
                break;
            case "latency":
                latency(body);
                break;
            case "throughput":
                throughput(body);
                break;
            default:
                System.err.println("unknown phase: " + args[0]);
                System.exit(2);
        }
    }

    private static void coldStart() throws IOException {
        try (SidecarVerifier sidecar = new SidecarVerifier("Sandbox")) {
            double ms = sidecar.startupNanos() / 1_000_000.0;
            System.out.printf("cold_start_ms=%.3f%n", ms);
        }
    }

    private static void latency(String body) throws Exception {
        try (SidecarVerifier sidecar = new SidecarVerifier("Sandbox")) {
            for (int i = 0; i < WARMUP; i++) {
                sidecar.verifyReceiptJson(body);
            }

            long[] samplesNanos = new long[LATENCY_CALLS];
            for (int i = 0; i < LATENCY_CALLS; i++) {
                long t0 = System.nanoTime();
                sidecar.verifyReceiptJson(body);
                samplesNanos[i] = System.nanoTime() - t0;
            }

            long rssKb = readRssKb(sidecar.pid());
            printStats("single_thread_latency", samplesNanos);
            System.out.println("server_rss_kb=" + rssKb);
        }
    }

    private static void throughput(String body) throws Exception {
        try (final SidecarVerifier sidecar = new SidecarVerifier("Sandbox")) {
            // Shared warm-up before the timed run, single-threaded.
            for (int i = 0; i < WARMUP; i++) {
                sidecar.verifyReceiptJson(body);
            }

            Thread[] threads = new Thread[THROUGHPUT_THREADS];
            final CountDownLatch ready = new CountDownLatch(THROUGHPUT_THREADS);
            final CountDownLatch go = new CountDownLatch(1);
            final CountDownLatch done = new CountDownLatch(THROUGHPUT_THREADS);
            final AtomicReference<Exception> failure = new AtomicReference<>();

            for (int t = 0; t < THROUGHPUT_THREADS; t++) {
                threads[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            ready.countDown();
                            go.await();
                            for (int i = 0; i < THROUGHPUT_CALLS_PER_THREAD; i++) {
                                sidecar.verifyReceiptJson(body);
                            }
                        } catch (Exception e) {
                            failure.compareAndSet(null, e);
                        } finally {
                            done.countDown();
                        }
                    }
                }, "bench-" + t);
                threads[t].start();
            }

            ready.await();
            long t0 = System.nanoTime();
            go.countDown();
            done.await();
            long elapsedNanos = System.nanoTime() - t0;

            for (Thread t : threads) {
                t.join();
            }
            if (failure.get() != null) {
                throw failure.get();
            }

            long rssKb = readRssKb(sidecar.pid());
            int totalCalls = THROUGHPUT_THREADS * THROUGHPUT_CALLS_PER_THREAD;
            double seconds = elapsedNanos / 1_000_000_000.0;
            double reqPerSec = totalCalls / seconds;
            System.out.println("threads=" + THROUGHPUT_THREADS);
            System.out.println("calls_per_thread=" + THROUGHPUT_CALLS_PER_THREAD);
            System.out.println("total_calls=" + totalCalls);
            System.out.printf("elapsed_s=%.3f%n", seconds);
            System.out.printf("throughput_req_per_s=%.1f%n", reqPerSec);
            System.out.println("server_rss_kb=" + rssKb);
        }
    }

    private static void printStats(String label, long[] samplesNanos) {
        long[] sorted = samplesNanos.clone();
        Arrays.sort(sorted);
        double meanUs = mean(sorted) / 1000.0;
        double p50Us = percentile(sorted, 50) / 1000.0;
        double p99Us = percentile(sorted, 99) / 1000.0;
        System.out.println(label + "_n=" + sorted.length);
        System.out.printf(label + "_mean_us=%.1f%n", meanUs);
        System.out.printf(label + "_p50_us=%.1f%n", p50Us);
        System.out.printf(label + "_p99_us=%.1f%n", p99Us);
    }

    private static double mean(long[] sorted) {
        long sum = 0;
        for (long v : sorted) {
            sum += v;
        }
        return sum / (double) sorted.length;
    }

    private static long percentile(long[] sorted, double p) {
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        idx = Math.max(0, Math.min(sorted.length - 1, idx));
        return sorted[idx];
    }

    private static long readRssKb(long pid) throws IOException {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/" + pid + "/status"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("VmRSS:")) {
                    String digits = line.replaceAll("[^0-9]", "");
                    return Long.parseLong(digits);
                }
            }
        }
        return -1;
    }
}
