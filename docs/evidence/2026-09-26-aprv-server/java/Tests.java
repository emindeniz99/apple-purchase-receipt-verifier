import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Spike only (2026-09-26). Drives AprvClient on Java 8.
 *   java Tests managed  EXE G5_B64 JWS ENDPOINT_JSON    modes 2: ops, token, crash, kill -9, bench, close
 *   java Tests url      URL TOKEN G5_B64 JWS ENDPOINT_JSON   mode 1: an external server, nothing started
 *   java Tests hold     EXE exit|sleep                   prints "CHILD <pid>", then exits without close() or sleeps
 *   java Tests download BASE CACHE NAME SHA256 THREADS    mode 3: THREADS concurrent resolves, then start + verify
 *   java Tests tampered BASE CACHE NAME SHA256            mode 3: a file whose hash is not the pin is refused
 */
public class Tests {
    static int pass, fail;

    static void check(String name, boolean ok, String detail) {
        if (ok) pass++; else fail++;
        System.out.println((ok ? "PASS " : "FAIL ") + name + (detail.isEmpty() ? "" : ": " + detail));
    }

    static String read(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }

    static boolean alive(long pid) { return pid > 0 && Files.exists(Paths.get("/proc/" + pid)) && !zombie(pid); }

    static boolean zombie(long pid) {
        try { return read("/proc/" + pid + "/stat").replaceFirst("^.*\\) ", "").startsWith("Z"); } catch (IOException e) { return false; }
    }

    static String head(String s) { return s.length() > 90 ? s.substring(0, 90) + "..." : s; }

    public static void main(String[] a) throws Exception {
        System.out.println("# java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + "), " + System.getProperty("os.arch"));
        switch (a[0]) {
            case "managed": managed(a); break;
            case "url": url(a); break;
            case "hold": hold(a); break;
            case "download": download(a); break;
            case "tampered": tampered(a); break;
            default: throw new IllegalArgumentException(a[0]);
        }
        System.out.println("summary: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    static void ops(AprvClient c, String g5, String jws, String endpointJson) throws IOException {
        String r = c.verifyReceipt(g5);
        check("verifyReceipt(g5) verified", r.startsWith("{\"verified\":true") && r.contains("dev.bonzer.weeka.app"), head(r));
        String j = c.verifySignedData(jws);
        check("verifySignedData(shared-sandbox JWS) is a result value (Apple roots: not anchored)", j.contains("\"verified\":false") && j.contains("INVALID_CHAIN"), head(j));
        String e = c.verifyReceiptEndpoint("sandbox", endpointJson);
        check("verifyReceiptEndpoint(sandbox) status 0", e.contains("\"status\":0"), head(e));
        String p = c.verifyReceiptEndpoint("production", endpointJson);
        check("verifyReceiptEndpoint(production) on a sandbox receipt answers 21007", p.contains("\"status\":21007"), head(p));
        String bad = c.verifyReceipt("not base64!");
        check("garbage receipt is a verification failure value, not an exception", bad.contains("INVALID_RECEIPT_FORMAT"), head(bad));
    }

    static void managed(String[] a) throws Exception {
        String g5 = read(a[2]).trim(), jws = read(a[3]).trim(), ep = read(a[4]);
        long t0 = System.nanoTime();
        AprvClient c = AprvClient.forExecutable(Paths.get(a[1]));
        long pid = c.childPid();
        check("child started (managed, loopback, token on stdin)", alive(pid), "pid " + pid + ", " + (System.nanoTime() - t0) / 1_000_000 + " ms to port");
        long t1 = System.nanoTime();
        String first = c.verifyReceipt(g5);
        System.out.println("   first verification after start: " + (System.nanoTime() - t1) / 1000 + " us");
        ops(c, g5, jws, ep);

        // The token is required: a request without it is refused.
        AprvClient.Endpoint real = null;
        {
            java.lang.reflect.Field f = AprvClient.class.getDeclaredField("supervisor");
            f.setAccessible(true);
            real = ((AprvClient.Supervisor) f.get(c)).endpoint();
            AprvClient.Conn noToken = new AprvClient.Conn(new AprvClient.Endpoint(real.host, real.port, null, 0));
            try { noToken.post("/v1/receipt/verify", g5.getBytes(StandardCharsets.US_ASCII)); check("request without token refused", false, "answered"); }
            catch (AprvClient.AprvException e) { check("request without token refused", e.httpStatus == 401, e.getMessage()); }
            noToken.closeQuietly();
            AprvClient.Conn wrong = new AprvClient.Conn(new AprvClient.Endpoint(real.host, real.port, real.token.replace('a', 'b').replace('0', '1'), 0));
            try { wrong.post("/v1/receipt/verify", g5.getBytes(StandardCharsets.US_ASCII)); check("request with a wrong token refused", false, "answered"); }
            catch (AprvClient.AprvException e) { check("request with a wrong token refused", e.httpStatus == 401, e.getMessage()); }
            wrong.closeQuietly();
        }

        // Oversized body: refused client-side (413) before anything is sent.
        try { c.verifyReceipt(new String(new char[AprvClient.MAX_BODY + 1]).replace('\0', 'A')); check("body over 3 MiB refused", false, "answered"); }
        catch (AprvClient.AprvException e) { check("body over 3 MiB refused with 413", e.httpStatus == 413, e.getMessage()); }

        // Deliberate child crash (spike-only route): the JVM survives, the next call restarts it.
        long before = c.childPid();
        c.crashChildForTest();
        Thread.sleep(100);
        check("deliberate crash (abort) killed the child", !alive(before), "pid " + before);
        long t2 = System.nanoTime();
        String after = c.verifyReceipt(g5);
        long recoverUs = (System.nanoTime() - t2) / 1000;
        check("JVM survived; next call succeeds after restart", after.startsWith("{\"verified\":true") && c.restarts() == 1 && alive(c.childPid()) && c.childPid() != before,
                "restarts " + c.restarts() + ", new pid " + c.childPid() + ", call incl. restart " + recoverUs + " us");

        // External SIGKILL of the child: same recovery.
        long victim = c.childPid();
        new ProcessBuilder("kill", "-9", String.valueOf(victim)).start().waitFor();
        Thread.sleep(100);
        String again = c.verifyReceipt(g5);
        check("child killed with SIGKILL; next call restarts it", again.startsWith("{\"verified\":true") && c.restarts() == 2 && c.childPid() != victim, "restarts " + c.restarts());

        bench(c, g5);

        long last = c.childPid();
        c.close();
        Thread.sleep(50);
        check("close() stops the child", !alive(last), "pid " + last);
    }

    static void bench(AprvClient c, String g5) throws Exception {
        for (int i = 0; i < 2000; i++) c.health();
        int n = 10000;
        long t = System.nanoTime();
        for (int i = 0; i < n; i++) c.health();
        System.out.printf("BENCH local HTTP round trip, GET /healthz (transport only): %.1f us%n", (System.nanoTime() - t) / 1000.0 / n);
        for (int i = 0; i < 300; i++) c.verifyReceipt(g5);
        n = 1500;
        long[] lat = new long[n];
        t = System.nanoTime();
        for (int i = 0; i < n; i++) { long s = System.nanoTime(); c.verifyReceipt(g5); lat[i] = System.nanoTime() - s; }
        long total = System.nanoTime() - t;
        Arrays.sort(lat);
        System.out.printf("BENCH verifyReceipt(g5) from Java 8, 1 thread: mean %.0f us, p50 %d us, p99 %d us, %.0f/s%n",
                total / 1000.0 / n, lat[n / 2] / 1000, lat[n * 99 / 100] / 1000, n * 1e9 / total);
        ExecutorService ex = Executors.newFixedThreadPool(4);
        AtomicInteger done = new AtomicInteger();
        long end = System.nanoTime() + 8_000_000_000L;
        t = System.nanoTime();
        List<Future<?>> fs = new ArrayList<>();
        for (int k = 0; k < 4; k++) fs.add(ex.submit(() -> { while (System.nanoTime() < end) { c.verifyReceipt(g5); done.incrementAndGet(); } return null; }));
        for (Future<?> f : fs) f.get();
        ex.shutdown();
        System.out.printf("BENCH verifyReceipt(g5) from Java 8, 4 threads, 8 s: %.0f/s (client and child share 4 vCPUs)%n", done.get() * 1e9 / (System.nanoTime() - t));
    }

    static void url(String[] a) throws Exception {
        String g5 = read(a[3]).trim(), jws = read(a[4]).trim(), ep = read(a[5]);
        System.setProperty("aprv.server.url", a[1]);
        System.setProperty("aprv.server.token", a[2]);
        AprvClient c = AprvClient.create();
        check("resolution picked the configured URL (mode 1)", c.mode().equals("url") && c.childPid() == -1, c.mode());
        ops(c, g5, jws, ep);
        long t = System.nanoTime();
        for (int i = 0; i < 200; i++) c.verifyReceipt(g5);
        System.out.printf("BENCH mode 1 verifyReceipt(g5): %.0f us per call%n", (System.nanoTime() - t) / 1000.0 / 200);
        c.close();
    }

    static void hold(String[] a) throws Exception {
        AprvClient c = AprvClient.forExecutable(Paths.get(a[1]));
        c.verifyReceipt("x");
        System.out.println("CHILD " + c.childPid());
        System.out.flush();
        if (a[2].equals("exit")) System.exit(0); // no close(): the shutdown hook must stop the child
        Thread.sleep(600_000); // the script kills this JVM with SIGKILL: stdin EOF must stop the child
    }

    static void pin(String name, String sha) {
        AprvClient.Download.PINNED.put(AprvClient.Download.platform(), new String[] {name, sha});
    }

    static void download(String[] a) throws Exception {
        pin(a[3], a[4]);
        Path cache = Paths.get(a[2]);
        int threads = Integer.parseInt(a[5]);
        ExecutorService ex = Executors.newFixedThreadPool(threads);
        List<Future<Path>> fs = new ArrayList<>();
        for (int i = 0; i < threads; i++) fs.add(ex.submit(() -> AprvClient.Download.resolve(a[1], cache, true)));
        Set<Path> got = new HashSet<>();
        for (Future<Path> f : fs) got.add(f.get());
        ex.shutdown();
        Path exe = got.iterator().next();
        System.out.println("DOWNLOADS " + AprvClient.Download.downloads.get());
        check(threads + " concurrent resolves agree on one verified file", got.size() == 1 && AprvClient.Download.sha256(exe).equals(a[4]), exe.getFileName().toString());
        check("cached file is owner r-x only, directory owner-only", PosixPerms.of(exe).equals("r-x------") && PosixPerms.of(cache).equals("rwx------"), PosixPerms.of(exe) + " " + PosixPerms.of(cache));
        AprvClient c = AprvClient.forExecutable(exe);
        String r = c.verifyReceipt(read(a[6]).trim());
        check("downloaded server verifies g5", r.startsWith("{\"verified\":true"), head(r));
        c.close();
    }

    static void tampered(String[] a) throws Exception {
        pin(a[3], a[4]);
        Path cache = Paths.get(a[2]);
        try {
            Path p = AprvClient.Download.resolve(a[1], cache, true);
            check("tampered download refused", false, "returned " + p);
        } catch (SecurityException e) {
            boolean leftover;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(cache, "{aprv-*,.dl-*}")) { leftover = ds.iterator().hasNext(); }
            check("tampered download refused before it is executable; nothing left in the cache", !leftover, e.getMessage().replaceAll("https?://[^ ]*", "<url>"));
        }
    }

    static final class PosixPerms {
        static String of(Path p) throws IOException { return java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(p)); }
    }
}
