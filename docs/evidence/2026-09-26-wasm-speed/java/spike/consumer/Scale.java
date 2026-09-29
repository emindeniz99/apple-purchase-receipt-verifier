package spike.consumer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import spike.aprv.endive.AprvWasm;

/**
 * Spike only (2026-09-26 speed round). Throughput across threads: each thread
 * owns one instance (round 5's Driver over the build-time-compiled module),
 * verifies the same row `warm` times, waits at a barrier, then verifies it
 * `n` times. Reports total verifications per second over the timed phase
 * (barrier to last thread done), and checks every result code.
 *
 * Compiled against round 5's consumer classes (same package, so it can use
 * the package-private Driver):
 *   java -cp <consumer classes>:<this>:<jars> spike.consumer.Scale rows.jsonl id threads warm n
 */
public final class Scale {
    private Scale() {}

    public static void main(String[] args) throws Exception {
        String id = args[1];
        int threads = Integer.parseInt(args[2]);
        int warm = Integer.parseInt(args[3]);
        int n = Integer.parseInt(args[4]);
        Map<String, Object> r = Main.rows(args[0]).stream().filter(x -> id.equals(x.get("id"))).findFirst().orElseThrow();
        String want = new Driver(AprvWasm::create).run(r).replaceAll(".*\"code\":([^,]*),.*", "$1");
        CyclicBarrier start = new CyclicBarrier(threads + 1);
        long[] bad = new long[threads];
        List<Thread> ts = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int k = t;
            Thread th = new Thread(() -> {
                Driver d = new Driver(AprvWasm::create);
                for (int i = 0; i < warm; i++) {
                    d.runSync(r);
                }
                try {
                    start.await();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                for (int i = 0; i < n; i++) {
                    String row = d.runSync(r);
                    if (!row.contains("\"code\":" + want + ",")) {
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
        System.out.println("{\"id\":" + Json.quote(id) + ",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"memory\":" + Json.quote(System.getProperty("spike.aprv.memory", "default"))
                + ",\"threads\":" + threads + ",\"warm_each\":" + warm + ",\"n_each\":" + n
                + ",\"seconds\":" + Math.round(s * 100) / 100.0 + ",\"total_per_s\":" + Math.round(threads * n / s * 10) / 10.0
                + ",\"wrong_codes\":" + wrong + "}");
    }
}
