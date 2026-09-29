package spike;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import uniffi.aprv_uniffi.Environment;
import uniffi.aprv_uniffi.VerifyReceiptEndpoint;

public final class SharedDemo {
    // like a Spring @Service field: created once, never closed per request
    private static final VerifyReceiptEndpoint ENDPOINT = new VerifyReceiptEndpoint(Environment.PRODUCTION, null);

    public static void main(String[] a) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
        String body = "{\"receipt-data\":\"" + b64 + "\"}";
        ExecutorService pool = Executors.newFixedThreadPool(16);
        AtomicInteger ok = new AtomicInteger(), bad = new AtomicInteger();
        long t = System.nanoTime();
        for (int i = 0; i < 16 * 200; i++) {
            pool.submit(() -> {
                // result deliberately NOT closed: the Cleaner frees it after GC
                long s = ENDPOINT.verifyReceiptResult(body).status();
                if (s == 21007) ok.incrementAndGet(); else bad.incrementAndGet();
            });
        }
        pool.shutdown();
        pool.awaitTermination(5, TimeUnit.MINUTES);
        long ms = (System.nanoTime() - t) / 1_000_000;
        System.gc(); Thread.sleep(500);
        Runtime rt = Runtime.getRuntime();
        System.out.println("java " + System.getProperty("java.version") + ": 16 threads, 3200 calls on ONE endpoint -> ok=" + ok + " bad=" + bad
                + " in " + ms + " ms (" + (3200 * 1000L / Math.max(ms, 1)) + " verifications/s); heap used " + (rt.totalMemory() - rt.freeMemory()) / 1_048_576 + " MB");
        String rss = new String(Files.readAllBytes(Paths.get("/proc/self/status"))).replaceAll("(?s).*VmRSS:\\s*(\\d+ kB).*", "$1");
        System.out.println("process RSS after 3200 unclosed results + GC: " + rss);
    }
}
