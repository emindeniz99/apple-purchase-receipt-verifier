package spike.consumer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import spike.aprv.endive.AprvWasm;
import spike.aprv.trap.TrapProbe;

/**
 * Spike only. A separate Maven project that depends on the generated
 * library ({@code spike.aprv:aprv-endive}) like any other dependency and
 * runs real verification through it.
 *
 * <pre>
 *   corpus  requests.jsonl                  rows to stdout, one summary line to stderr
 *   bench   requests.jsonl id warm n        warm latency of one row
 *   threads requests.jsonl threads rounds   one instance per thread, every row compared with a single-threaded run
 *   shared  requests.jsonl threads rounds   ONE instance used from several threads (expected to break)
 *   memory                                  two instances have separate linear memories
 *   maps    [requests.jsonl]                shared objects mapped into this JVM after verifying the rows
 *   trap                                    the trap-probe module: out-of-bounds, unreachable, stack exhaustion
 *   instances n                             time to create each of n instances in one JVM
 * </pre>
 */
public final class Main {
    private Main() {}

    static List<Map<String, Object>> rows(String path) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(path), StandardCharsets.UTF_8)) {
            if (!line.isBlank()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> r = (Map<String, Object>) Json.parse(line);
                out.add(r);
            }
        }
        return out;
    }

    static String mask(String row) {
        return row.replaceAll("request_date[a-z_]*\\\\\":[^,}]*", "request_date*");
    }

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "corpus": corpus(args[1]); break;
            case "bench": bench(args[1], args[2], Integer.parseInt(args[3]), Integer.parseInt(args[4])); break;
            case "threads": threads(args[1], Integer.parseInt(args[2]), Integer.parseInt(args[3]), false); break;
            case "shared": threads(args[1], Integer.parseInt(args[2]), Integer.parseInt(args[3]), true); break;
            case "memory": memory(); break;
            case "maps": maps(args.length > 1 ? args[1] : null); break;
            case "trap": trap(); break;
            case "instances": instances(Integer.parseInt(args[1])); break;
            default: throw new IllegalArgumentException(args[0]);
        }
    }

    static void corpus(String path) throws IOException {
        List<Map<String, Object>> rs = rows(path);
        long t0 = System.nanoTime();
        Driver d = new Driver(AprvWasm::create);
        double initMs = (System.nanoTime() - t0) / 1e6;
        StringBuilder out = new StringBuilder();
        int traps = 0;
        long clock = 0, random = 0;
        AprvWasm seen = d.wasm();
        long c0 = 0, r0 = 0;
        for (Map<String, Object> r : rs) {
            String row = d.run(r);
            if (row.contains("\"code\":\"TRAP\"")) {
                traps++;
            }
            out.append(row).append('\n');
            if (d.wasm() != seen) {
                clock += seen.clockCalls() - c0;
                random += seen.randomCalls() - r0;
                seen = d.wasm();
                c0 = 0;
                r0 = 0;
            }
        }
        clock += seen.clockCalls() - c0;
        random += seen.randomCalls() - r0;
        System.out.print(out);
        System.err.println("{\"host\":\"endive-build-time\",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"calls\":{\"aprv.clock_now_ms\":" + clock + ",\"aprv.random_get\":" + random + "}"
                + ",\"traps\":" + traps + ",\"rows\":" + rs.size() + ",\"instances\":" + d.instancesCreated
                + ",\"init_ms\":" + Math.round(initMs * 100) / 100.0 + "}");
    }

    static void bench(String path, String id, int warm, int n) throws IOException {
        Map<String, Object> r = rows(path).stream().filter(x -> id.equals(x.get("id"))).findFirst().orElseThrow();
        long t0 = System.nanoTime();
        Driver d = new Driver(AprvWasm::create);
        double initMs = (System.nanoTime() - t0) / 1e6;
        long t1 = System.nanoTime();
        String first = d.run(r);
        double firstMs = (System.nanoTime() - t1) / 1e6;
        for (int i = 0; i < warm; i++) {
            d.runSync(r);
        }
        long[] ns = new long[n];
        long ta = System.nanoTime();
        for (int i = 0; i < n; i++) {
            long s = System.nanoTime();
            d.runSync(r);
            ns[i] = System.nanoTime() - s;
        }
        double totalS = (System.nanoTime() - ta) / 1e9;
        Arrays.sort(ns);
        String code = first.replaceAll(".*\"code\":([^,]*),.*", "$1");
        System.out.println("{\"id\":" + Json.quote(id) + ",\"code\":" + code + ",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"init_ms\":" + r2(initMs) + ",\"first_call_ms\":" + r2(firstMs) + ",\"warm\":" + warm + ",\"n\":" + n
                + ",\"mean_us\":" + r2(totalS * 1e6 / n) + ",\"median_us\":" + r2(ns[n / 2] / 1e3)
                + ",\"p99_us\":" + r2(ns[(int) (n * 0.99)] / 1e3) + ",\"per_s\":" + Math.round(n / totalS)
                + ",\"memory_bytes\":" + d.wasm().memoryBytes() + "}");
    }

    static double r2(double v) {
        return Math.round(v * 100) / 100.0;
    }

    static void threads(String path, int threads, int rounds, boolean shared) throws Exception {
        List<Map<String, Object>> rs = rows(path);
        Driver ref = new Driver(AprvWasm::create);
        List<String> want = rs.stream().map(ref::run).map(Main::mask).collect(Collectors.toList());
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        Driver one = shared ? new Driver(AprvWasm::create) : null;
        List<Future<long[]>> fs = new ArrayList<>();
        long t0 = System.nanoTime();
        for (int t = 0; t < threads; t++) {
            fs.add(pool.submit(() -> {
                Driver d = shared ? one : new Driver(AprvWasm::create);
                long same = 0, differ = 0, errors = 0;
                for (int k = 0; k < rounds; k++) {
                    for (int i = 0; i < rs.size(); i++) {
                        try {
                            String got = mask(d.run(rs.get(i)));
                            if (got.equals(want.get(i))) {
                                same++;
                            } else {
                                differ++;
                            }
                        } catch (RuntimeException | Error e) {
                            errors++;
                        }
                    }
                }
                return new long[] {same, differ, errors};
            }));
        }
        long same = 0, differ = 0, errors = 0;
        for (Future<long[]> f : fs) {
            long[] v = f.get();
            same += v[0];
            differ += v[1];
            errors += v[2];
        }
        pool.shutdown();
        double s = (System.nanoTime() - t0) / 1e9;
        System.out.println("{\"mode\":" + Json.quote(shared ? "one shared instance" : "one instance per thread")
                + ",\"java\":" + Json.quote(System.getProperty("java.version")) + ",\"threads\":" + threads
                + ",\"rounds\":" + rounds + ",\"rows_each\":" + rs.size() + ",\"same\":" + same + ",\"differ\":" + differ
                + ",\"errors\":" + errors + ",\"seconds\":" + r2(s) + ",\"rows_per_s\":" + Math.round((same + differ + errors) / s) + "}");
    }

    static void memory() {
        AprvWasm a = AprvWasm.create();
        AprvWasm b = AprvWasm.create();
        int pa = a.put("instance A".getBytes(StandardCharsets.UTF_8), true);
        int pb = b.put("instance B".getBytes(StandardCharsets.UTF_8), true);
        // Same allocator, same heap layout: the pointers are expected to be equal.
        String ra = a.memory().readCString(pa);
        String rb = b.memory().readCString(pb);
        a.memory().writeByte(pa, (byte) 'X');
        String rbAfter = b.memory().readCString(pb);
        System.out.println("{\"ptr_a\":" + pa + ",\"ptr_b\":" + pb + ",\"a\":" + Json.quote(ra) + ",\"b\":" + Json.quote(rb)
                + ",\"b_after_writing_a\":" + Json.quote(rbAfter) + ",\"a_after\":" + Json.quote(a.memory().readCString(pa))
                + ",\"same_memory_object\":" + (a.memory() == b.memory()) + "}");
    }

    /** Verifies one row (if given), then lists every shared object mapped into this process. */
    static void maps(String path) throws IOException {
        if (path != null) {
            Driver d = new Driver(AprvWasm::create);
            for (Map<String, Object> r : rows(path)) {
                d.run(r);
            }
        }
        Files.readAllLines(Path.of("/proc/self/maps")).stream()
                .map(l -> l.replaceAll("^.* ", ""))
                .filter(l -> l.contains(".so") || l.endsWith(".jsa"))
                .map(l -> l.replaceAll(".*/", ""))
                .distinct()
                .sorted()
                .forEach(System.out::println);
    }

    /** Each probe: what Java sees, then whether the SAME instance still works. */
    static void trap() {
        TrapProbe t = new TrapProbe();
        t.call("store", 100, 42);
        String[][] probes = {
            {"load", "65533"}, {"load", "-1"}, {"store", "65534", "7"}, {"fill_oob"}, {"unreachable"}, {"div0", "0"}, {"deep", "0"},
        };
        for (String[] p : probes) {
            long[] a = new long[p.length - 1];
            for (int i = 1; i < p.length; i++) {
                a[i - 1] = Long.parseLong(p[i]);
            }
            String outcome;
            try {
                long v = a.length == 2 ? callStore(t, a) : t.call(p[0], a);
                outcome = "returned " + v;
            } catch (Throwable e) {
                outcome = e.getClass().getName() + ": " + e.getMessage();
            }
            String reuse;
            try {
                reuse = "load(100) after = " + t.call("load", 100) + ", load(65532) after = " + t.call("load", 65532);
            } catch (Throwable e) {
                reuse = "instance unusable: " + e.getClass().getName() + ": " + e.getMessage();
            }
            System.out.println(String.join(" ", p) + " -> " + outcome + " | " + reuse);
        }
        // The verifier instance in the same JVM is unaffected.
        AprvWasm w = AprvWasm.create();
        System.out.println("aprv_version after all traps: " + w.memory().readCString((int) w.call("aprv_version")));
    }

    private static long callStore(TrapProbe t, long[] a) {
        t.call("store", a);
        return 0;
    }

    /** The first instance pays class loading and .meta parsing; later ones only instantiation. */
    static void instances(int n) {
        StringBuilder b = new StringBuilder();
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            long s = System.nanoTime();
            AprvWasm w = AprvWasm.create();
            b.append(i == 0 ? "" : ",").append(r2((System.nanoTime() - s) / 1e6));
            if (w.memoryBytes() == 0) {
                throw new IllegalStateException();
            }
        }
        System.out.println("{\"java\":" + Json.quote(System.getProperty("java.version")) + ",\"create_ms\":[" + b
                + "],\"total_ms\":" + r2((System.nanoTime() - t0) / 1e6) + "}");
    }
}
