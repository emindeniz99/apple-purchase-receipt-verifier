package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * What a stdio transport could save, and what the one-shot CLI costs, seen
 * from the JVM:
 *
 * <ol>
 *   <li>{@code http}: {@code aprv serve --managed} (the handshake as
 *       ServerProcess does it) and main's HttpConn, keep-alive: the g5
 *       receipt, and {@code GET /healthz} (transport alone);</li>
 *   <li>{@code oneshot}: one {@code aprv verify-receipt} process per call,
 *       the receipt on stdin, the answer read from stdout to EOF and the exit
 *       awaited;</li>
 *   <li>{@code pipe}: the floor of a stdio transport, a length-prefixed frame
 *       of the receipt's size (and of 2 bytes) written to {@code cat} and read
 *       back.</li>
 * </ol>
 *
 * <p>Arguments: the aprv binary, the g5 fixture (base64), the number of timed
 * calls for http and pipe; one-shot runs a tenth of them.</p>
 */
public final class TransportBench {

    static final long NOW_MS = 1_700_000_000_000L;

    public static void main(String[] args) throws Exception {
        String aprv = args[0];
        byte[] receipt = Base64.getEncoder()
                .encodeToString(Base64.getMimeDecoder().decode(Files.readAllBytes(Paths.get(args[1]))))
                .getBytes(StandardCharsets.US_ASCII);
        int n = Integer.parseInt(args[2]);
        System.out.println("# java " + System.getProperty("java.version") + "; receipt " + receipt.length + " bytes");

        // 1. managed child over HTTP
        String token = randomToken();
        Process child = new ProcessBuilder(aprv, "serve", "--managed").redirectError(ProcessBuilder.Redirect.INHERIT).start();
        OutputStream stdin = child.getOutputStream();
        stdin.write((token + "\n{}\n").getBytes(StandardCharsets.US_ASCII));
        stdin.flush();
        BufferedReader stdout = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.US_ASCII));
        String listen = stdout.readLine();
        int port = Integer.parseInt(listen.substring(listen.lastIndexOf(':') + 1));
        HttpConn conn = new HttpConn(new HttpConn.Target("127.0.0.1", port, false, "", token, 0), 5_000, 60_000);
        byte[] httpAnswer = null;
        for (int i = 0; i < 300; i++) {
            httpAnswer = conn.exchange("POST", "/v1/receipt/verify", receipt, NOW_MS).body;
        }
        long[] times = new long[n];
        for (int i = 0; i < n; i++) {
            long t = System.nanoTime();
            HttpConn.Response r = conn.exchange("POST", "/v1/receipt/verify", receipt, NOW_MS);
            times[i] = System.nanoTime() - t;
            check(r.status == 200 && Arrays.equals(r.body, httpAnswer), "http answer changed");
        }
        report("http keep-alive, g5", times);
        for (int i = 0; i < 1000; i++) {
            conn.exchange("GET", "/healthz", new byte[0], null);
        }
        long[] health = new long[n * 5];
        for (int i = 0; i < health.length; i++) {
            long t = System.nanoTime();
            conn.exchange("GET", "/healthz", new byte[0], null);
            health[i] = System.nanoTime() - t;
        }
        report("http keep-alive, GET /healthz", health);
        conn.close();
        stdin.close();
        child.waitFor();

        // 2. one process per call
        int m = Math.max(20, n / 10);
        byte[] cliAnswer = null;
        for (int i = 0; i < 20; i++) {
            cliAnswer = oneShot(aprv, receipt);
        }
        long[] cli = new long[m];
        for (int i = 0; i < m; i++) {
            long t = System.nanoTime();
            byte[] answer = oneShot(aprv, receipt);
            cli[i] = System.nanoTime() - t;
            check(Arrays.equals(answer, cliAnswer), "one-shot answer changed");
        }
        report("one-shot process per call, g5", cli);
        String a = new String(httpAnswer, StandardCharsets.UTF_8).trim();
        String b = new String(cliAnswer, StandardCharsets.UTF_8).trim();
        System.out.println("# one-shot answer equals the server's: " + a.equals(b) + " (" + b.length() + " chars)");

        // 3. the pipe floor
        for (int size : new int[] {2, receipt.length}) {
            Process cat = new ProcessBuilder("cat").start();
            DataOutputStream out = new DataOutputStream(cat.getOutputStream());
            DataInputStream in = new DataInputStream(cat.getInputStream());
            byte[] frame = Arrays.copyOf(receipt, size);
            byte[] back = new byte[size];
            long[] pipe = new long[n * 5];
            for (int i = -1000; i < pipe.length; i++) {
                long t = System.nanoTime();
                out.writeInt(size);
                out.write(frame);
                out.flush();
                int length = in.readInt();
                in.readFully(back, 0, length);
                if (i >= 0) {
                    pipe[i] = System.nanoTime() - t;
                }
            }
            check(Arrays.equals(frame, back), "pipe echo differs");
            report("length-prefixed frame through a pipe and back, " + size + " bytes", pipe);
            out.close();
            cat.waitFor();
        }
        System.exit(0);
    }

    static byte[] oneShot(String aprv, byte[] receipt) throws Exception {
        Process p = new ProcessBuilder(aprv, "verify-receipt", "--now-ms", Long.toString(NOW_MS))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (OutputStream in = p.getOutputStream()) {
            in.write(receipt);
        }
        byte[] answer = readAll(p.getInputStream());
        check(p.waitFor() == 0, "one-shot exit code");
        return answer;
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[16384];
        int n;
        while ((n = in.read(buffer)) >= 0) {
            bytes.write(buffer, 0, n);
        }
        return bytes.toByteArray();
    }

    static String randomToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException(what);
        }
    }

    static void report(String what, long[] nanos) {
        long[] sorted = nanos.clone();
        Arrays.sort(sorted);
        long sum = 0;
        for (long t : sorted) {
            sum += t;
        }
        System.out.printf("%s\tn=%d\tmean %.1f us\tp50 %.1f us\tp99 %.1f us%n", what, sorted.length,
                sum / 1e3 / sorted.length, sorted[sorted.length / 2] / 1e3, sorted[(int) (sorted.length * 0.99)] / 1e3);
    }

    private TransportBench() {}
}
