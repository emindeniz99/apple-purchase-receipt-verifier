package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Not a test: start-up and throughput of the Endive engine for the record
 * (MIGRATION step 3.7), run by {@code scripts/bench.sh} in a fresh JVM.
 * Start-up: the first instance in the JVM (loading the compiled classes,
 * parsing the stripped module, {@code _initialize}, {@code init}) and the
 * median of 20 later ones. Throughput: the genuine g5 sandbox receipt and
 * the shared sandbox transaction JWS (with its own root), each thread on an
 * instance of its own, warmed up for as long as it is then measured.
 *
 * <pre>java -cp JAR:TEST_CLASSES:DEPS ...BenchMain [SECONDS] [THREADS...]</pre>
 */
public final class BenchMain {

    private BenchMain() {}

    public static void main(String[] args) throws Exception {
        long jvmStart = System.nanoTime();
        int seconds = args.length > 0 ? Integer.parseInt(args[0]) : 10;
        List<Integer> threadCounts = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            threadCounts.add(Integer.parseInt(args[i]));
        }
        if (threadCounts.isEmpty()) {
            threadCounts.add(1);
            threadCounts.add(2);
            threadCounts.add(4);
        }
        byte[] none = "{\"roots\":[]}".getBytes(StandardCharsets.US_ASCII);

        long t0 = System.nanoTime();
        EndiveGuestFactory factory = new EndiveGuestFactory();
        Guest first = factory.newGuest();
        first.init(none);
        long firstMicros = (System.nanoTime() - t0) / 1000;
        long[] later = new long[20];
        for (int i = 0; i < later.length; i++) {
            long t = System.nanoTime();
            factory.newGuest().init(none);
            later[i] = (System.nanoTime() - t) / 1000;
        }
        java.util.Arrays.sort(later);

        byte[] g5 = Base64.getEncoder().encode(Cases.fixtureBytes("public-receipt-sandbox-g5"));
        byte[] jws = Cases.fixtureBytes("transaction");
        byte[] jwsConfig =
                WasmVerifier.configJson(new LinkedHashSet<>(Cases.roots(Cases.MAPPER.readTree("[\"jws-root\"]"))));
        long now = System.currentTimeMillis();
        long t1 = System.nanoTime();
        String answer = first.verifyReceipt(now, g5);
        long firstCallMicros = (System.nanoTime() - t1) / 1000;
        if (!answer.contains("\"verified\":true")) {
            throw new IllegalStateException("g5 did not verify");
        }
        System.out.println("{\"bench\":\"startup\",\"java\":" + Engine.javaFeatureVersion()
                + ",\"first_instance_ms\":" + firstMicros / 1000.0 + ",\"later_instance_median_ms\":"
                + later[later.length / 2] / 1000.0 + ",\"first_g5_call_ms\":" + firstCallMicros / 1000.0
                + ",\"since_main_ms\":" + (System.nanoTime() - jvmStart) / 1_000_000 + "}");
        // Memory: one instance's linear memory after the g5 call, and the heap
        // this JVM holds after a GC with the module loaded and that instance live.
        EndiveGuest measured = new EndiveGuest(new SecureRandom());
        measured.init(none);
        long linearAfterInit = measured.linearMemoryBytes();
        measured.verifyReceipt(now, g5);
        long linearAfterG5 = measured.linearMemoryBytes();
        for (int i = 0; i < 3; i++) {
            System.gc();
        }
        Runtime runtime = Runtime.getRuntime();
        System.out.println("{\"bench\":\"memory\",\"instance_linear_after_init_mib\":" + mib(linearAfterInit)
                + ",\"instance_linear_after_g5_mib\":" + mib(linearAfterG5) + ",\"heap_used_after_gc_mib\":"
                + mib(runtime.totalMemory() - runtime.freeMemory()) + ",\"rss_mib\":" + procStatus("VmRSS")
                + "}");

        for (int threads : threadCounts) {
            System.out.println(run("g5", threads, seconds, factory, none, now, g5, false));
            System.out.println(run("jws", threads, seconds, factory, jwsConfig, now, jws, true));
        }
        System.out.println("{\"bench\":\"peak\",\"peak_rss_mib\":" + procStatus("VmHWM") + "}");
    }

    private static String run(
            String what,
            int threads,
            int seconds,
            EndiveGuestFactory factory,
            byte[] config,
            long now,
            byte[] input,
            boolean jws)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier start = new CyclicBarrier(threads);
        try {
            List<Future<long[]>> workers = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                workers.add(pool.submit(() -> {
                    Guest guest = new EndiveGuest(new SecureRandom());
                    guest.init(config);
                    // Warm-up for as long as the measurement: Endive's generated
                    // methods are large, and C2 takes a while to reach them.
                    long warm = System.nanoTime() + seconds * 1_000_000_000L;
                    while (System.nanoTime() < warm) {
                        call(guest, jws, now, input);
                    }
                    start.await();
                    long begin = System.nanoTime();
                    long end = begin + seconds * 1_000_000_000L;
                    long calls = 0;
                    while (System.nanoTime() < end) {
                        call(guest, jws, now, input);
                        calls++;
                    }
                    return new long[] {calls, System.nanoTime() - begin};
                }));
            }
            long calls = 0;
            double perSecond = 0;
            for (Future<long[]> worker : workers) {
                long[] result = worker.get();
                calls += result[0];
                perSecond += result[0] / (result[1] / 1e9);
            }
            return "{\"bench\":\"" + what + "\",\"threads\":" + threads + ",\"seconds\":" + seconds + ",\"calls\":"
                    + calls + ",\"per_second\":" + Math.round(perSecond * 10) / 10.0 + ",\"mean_ms\":"
                    + Math.round(1000.0 * threads / perSecond * 1000) / 1000.0 + "}";
        } finally {
            pool.shutdown();
        }
    }

    private static double mib(long bytes) {
        return Math.round(bytes / 1048576.0 * 10) / 10.0;
    }

    /** A {@code /proc/self/status} size in MiB, or null where there is none. */
    private static String procStatus(String key) {
        try {
            for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get("/proc/self/status"))) {
                if (line.startsWith(key + ":")) {
                    long kib = Long.parseLong(
                            line.substring(key.length() + 1).replace("kB", "").trim());
                    return String.valueOf(mib(kib * 1024));
                }
            }
        } catch (java.io.IOException | RuntimeException e) {
            // not Linux
        }
        return "null";
    }

    private static void call(Guest guest, boolean jws, long now, byte[] input) {
        String answer = jws ? guest.verifySignedData(now, input) : guest.verifyReceipt(now, input);
        if (!answer.startsWith("{\"verified\":true")) {
            throw new IllegalStateException("did not verify");
        }
    }
}
