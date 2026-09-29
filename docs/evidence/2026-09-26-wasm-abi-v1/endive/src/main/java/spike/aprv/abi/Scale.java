package spike.aprv.abi;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;

/**
 * Spike only (ABI v1). Round 6's scaling measurement on the ABI v1 bridge:
 * each thread owns one {@link AprvAbi} (one instance), makes the same call
 * `warm` times, waits at a barrier, then makes it `n` times. Reports total
 * calls per second over the timed phase (barrier to last thread done) and
 * checks every result is verified=true.
 *   java -cp ... spike.aprv.abi.Scale calls.jsonl id threads warm n
 */
public final class Scale {
    private Scale() {}

    public static void main(String[] args) throws Exception {
        String id = args[1];
        int threads = Integer.parseInt(args[2]);
        int warm = Integer.parseInt(args[3]);
        int n = Integer.parseInt(args[4]);
        Map<String, Object> call = null;
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> c = (Map<String, Object>) Json.parse(line);
            if (id.equals(c.get("id"))) {
                call = c;
            }
        }
        final int op = ((Long) call.get("op")).intValue();
        final byte[] input = Base64.getDecoder().decode((String) call.get("input"));
        final byte[] want = "{\"verified\":true".getBytes(StandardCharsets.UTF_8);
        CyclicBarrier start = new CyclicBarrier(threads + 1);
        long[] bad = new long[threads];
        List<Thread> ts = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int k = t;
            Thread th = new Thread(() -> {
                AprvAbi abi = new AprvAbi();
                for (int i = 0; i < warm; i++) {
                    abi.call(op, input);
                }
                try {
                    start.await();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                for (int i = 0; i < n; i++) {
                    byte[] out = abi.call(op, input);
                    if (!startsWith(out, want)) {
                        bad[k]++;
                    }
                }
            });
            ts.add(th);
            th.start();
        }
        start.await();
        long t0 = System.nanoTime();
        for (Thread th : ts) {
            th.join();
        }
        double s = (System.nanoTime() - t0) / 1e9;
        long wrong = 0;
        for (long b : bad) {
            wrong += b;
        }
        System.out.println("{\"id\":" + Json.quote(id) + ",\"op\":" + op + ",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"memory\":\"bytearray\",\"threads\":" + threads + ",\"warm_each\":" + warm + ",\"n_each\":" + n
                + ",\"seconds\":" + Math.round(s * 100) / 100.0 + ",\"total_per_s\":" + Math.round(threads * n / s * 10) / 10.0
                + ",\"not_verified\":" + wrong + "}");
    }

    private static boolean startsWith(byte[] a, byte[] p) {
        if (a.length < p.length) {
            return false;
        }
        for (int i = 0; i < p.length; i++) {
            if (a[i] != p[i]) {
                return false;
            }
        }
        return true;
    }
}
