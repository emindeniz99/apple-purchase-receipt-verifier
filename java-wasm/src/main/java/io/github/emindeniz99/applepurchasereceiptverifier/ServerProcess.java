package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;

/**
 * {@code aprv serve --managed} as a supervised child (ARCHITECTURE.md §7.8,
 * THREAT-MODEL.md §6). The handshake: a fresh 256-bit {@link SecureRandom}
 * token as the first stdin line (never in argv, which {@code /proc} shows
 * to every user, nor in the environment), the roots as the second, and the
 * child answers {@code APRV_LISTEN=127.0.0.1:<port>} on stdout. stdin then
 * stays open: its EOF, which also happens when this JVM dies by
 * {@code kill -9}, makes the child exit.
 *
 * <p>A child that dies is started again on the next call; one that died 10
 * times within a minute is not, and calls fail until the verifier is
 * created again. The binary's SHA-256, when pinned, is checked again before
 * every start.</p>
 */
final class ServerProcess {

    static final int MAX_STARTS_PER_MINUTE = 10;
    private static final long MINUTE_NANOS = TimeUnit.MINUTES.toNanos(1);
    private static final long PORT_TIMEOUT_SECONDS = 10;
    private static final String LISTEN = "APRV_LISTEN=127.0.0.1:";

    private final Path executable;
    private final @Nullable String pinnedSha256;
    private final String rootsLine;
    private final SecureRandom random = new SecureRandom();
    private final Deque<Long> recentStarts = new ArrayDeque<>();
    private final AtomicInteger restarts = new AtomicInteger();

    private @Nullable Process process;
    private HttpConn.@Nullable Target target;
    private int generation;
    private boolean stopped;
    private @Nullable String stoppedBecause;

    /**
     * @param executable the binary
     * @param pinnedSha256 its expected SHA-256, checked before every start, or
     *     {@code null} for {@link ServerSource#executable}, which pins nothing
     * @param rootsLine the second handshake line: {@code {}} or
     *     {@code {"roots":[...]}}
     */
    ServerProcess(Path executable, @Nullable String pinnedSha256, String rootsLine) {
        this.executable = executable;
        this.pinnedSha256 = pinnedSha256;
        this.rootsLine = rootsLine;
    }

    /** The running child's address, starting it first if it is not running. */
    synchronized HttpConn.Target target() {
        if (stopped) {
            throw new ServerProcessFailure(stoppedBecause != null ? stoppedBecause : "the server engine was closed");
        }
        if (process == null || !process.isAlive() || target == null) {
            start();
        }
        return target;
    }

    /**
     * Called after a request on {@code failedGeneration}'s child failed: if
     * that child has died, the next {@link #target()} starts another.
     */
    synchronized void recover(int failedGeneration) {
        if (stopped || failedGeneration != generation || process == null) {
            return;
        }
        try {
            process.waitFor(300, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (!process.isAlive()) {
            target = null;
        }
    }

    /** The binary this process starts. */
    Path executablePath() {
        return executable;
    }

    int restarts() {
        return restarts.get();
    }

    synchronized void start() {
        long now = System.nanoTime();
        while (!recentStarts.isEmpty() && now - recentStarts.peekFirst() > MINUTE_NANOS) {
            recentStarts.pollFirst();
        }
        if (recentStarts.size() >= MAX_STARTS_PER_MINUTE) {
            stopped = true;
            stoppedBecause = "aprv-server died " + MAX_STARTS_PER_MINUTE
                    + " times within a minute and is not started again; create the verifier again to retry";
            throw new ServerProcessFailure(stoppedBecause);
        }
        recentStarts.addLast(now);
        if (process != null) {
            process.destroyForcibly();
            restarts.incrementAndGet();
        }
        if (pinnedSha256 != null) {
            ServerBinary.verifyBeforeStart(executable, pinnedSha256);
        }
        if (ServerBinary.noexec(executable)) {
            throw new ServerProcessFailure("cannot start " + executable + ". " + ServerBinary.NOEXEC_ADVICE);
        }
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = ServerBinary.hex(raw);
        Process child;
        try {
            child = new ProcessBuilder(executable.toString(), "serve", "--managed").start();
        } catch (IOException e) {
            throw new ServerProcessFailure(ServerBinary.explainStartFailure(executable, e), e);
        }
        StderrTail stderr = new StderrTail(child.getErrorStream());
        Thread stderrReader = daemon("aprv-stderr", stderr);
        stderrReader.start();
        SynchronousQueue<String> firstLine = new SynchronousQueue<>();
        BufferedReader stdout =
                new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.US_ASCII));
        daemon("aprv-stdout", () -> {
                    String line;
                    try {
                        line = stdout.readLine();
                    } catch (IOException e) {
                        line = null;
                    }
                    try {
                        firstLine.offer(line == null ? "" : line, PORT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                        // Keep reading so the child never blocks on a full pipe.
                        while (stdout.readLine() != null) {
                            // discarded
                        }
                    } catch (IOException | InterruptedException e) {
                        // the child is gone
                    }
                })
                .start();
        String line;
        try {
            OutputStream stdin = child.getOutputStream();
            stdin.write((token + "\n" + rootsLine + "\n").getBytes(StandardCharsets.US_ASCII));
            stdin.flush(); // stdin stays open: its EOF tells the child this JVM is gone
            line = firstLine.poll(PORT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            child.destroyForcibly();
            throw new ServerProcessFailure(
                    "aprv-server did not take the handshake: " + e + exitAndStderr(child, stderr), e);
        }
        if (line == null || !line.startsWith(LISTEN)) {
            InitRefused refused = rootsRefusal(child, stderrReader, stderr);
            if (refused != null) {
                throw refused;
            }
            child.destroyForcibly();
            throw new ServerProcessFailure("aprv-server did not report its port"
                    + (line == null ? " within " + PORT_TIMEOUT_SECONDS + " s" : "")
                    + exitAndStderr(child, stderr));
        }
        int port;
        try {
            port = Integer.parseInt(line.substring(LISTEN.length()).trim());
        } catch (NumberFormatException e) {
            child.destroyForcibly();
            throw new ServerProcessFailure("aprv-server reported a port that is not a number", e);
        }
        process = child;
        generation++;
        target = new HttpConn.Target("127.0.0.1", port, false, "", token, generation);
    }

    /** Closes stdin (the child exits on EOF), then waits, then ends it harder. */
    synchronized void stop() {
        stopped = true;
        Process child = process;
        process = null;
        target = null;
        if (child == null) {
            return;
        }
        try {
            child.getOutputStream().close();
        } catch (IOException e) {
            // already closed
        }
        try {
            if (!child.waitFor(2, TimeUnit.SECONDS)) {
                child.destroy();
                if (!child.waitFor(2, TimeUnit.SECONDS)) {
                    child.destroyForcibly().waitFor(2, TimeUnit.SECONDS);
                }
            }
        } catch (InterruptedException e) {
            child.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    /** The running child's process id, or -1: for tests and support requests. */
    synchronized long pid() {
        Process child = process;
        if (child == null) {
            return -1;
        }
        try {
            Method pid = Process.class.getMethod("pid"); // Java 9 and later
            return (Long) pid.invoke(child);
        } catch (NoSuchMethodException e) {
            try {
                Field field = child.getClass().getDeclaredField("pid"); // Java 8's UNIXProcess
                field.setAccessible(true);
                return ((Number) field.get(child)).longValue();
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                return -1;
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            return -1;
        }
    }

    private static final String REFUSED = "the component refused the roots configuration: ";

    /**
     * The child exited 2 because the module's {@code init} refused the roots
     * of the handshake: the caller's mistake, as on Endive, not a process
     * failure. Null for any other exit.
     */
    private static @Nullable InitRefused rootsRefusal(Process child, Thread stderrReader, StderrTail stderr) {
        try {
            if (!child.waitFor(2, TimeUnit.SECONDS) || child.exitValue() != 2) {
                return null;
            }
            stderrReader.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        return rootsRefusal(stderr.tail());
    }

    /** The refusal in the child's stderr, {@code aprv: ... refused the roots configuration: <init answer>}. */
    static @Nullable InitRefused rootsRefusal(String stderr) {
        int at = stderr.indexOf(REFUSED);
        if (at < 0) {
            return null;
        }
        String answer = stderr.substring(at + REFUSED.length()).trim();
        try {
            Wire.initAnswer(answer);
        } catch (InitRefused e) {
            return new InitRefused(e.getMessage(), answer);
        } catch (RuntimeException e) {
            return null;
        }
        return null;
    }

    private static String exitAndStderr(Process child, StderrTail stderr) {
        String exit = "";
        try {
            if (child.waitFor(1, TimeUnit.SECONDS)) {
                exit = "; it exited with code " + child.exitValue();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        String tail = stderr.tail();
        return exit + (tail.isEmpty() ? "" : "; its stderr: " + tail);
    }

    private static Thread daemon(String name, Runnable body) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        return thread;
    }

    /** Reads the child's stderr to its end and keeps the last 2 KiB, for error messages. */
    static final class StderrTail implements Runnable {
        private static final int KEEP = 2048;
        private final InputStream in;
        private final StringBuilder tail = new StringBuilder();

        StderrTail(InputStream in) {
            this.in = in;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[1024];
            try {
                int n;
                while ((n = in.read(buffer)) > 0) {
                    synchronized (tail) {
                        tail.append(new String(buffer, 0, n, StandardCharsets.UTF_8));
                        if (tail.length() > KEEP) {
                            tail.delete(0, tail.length() - KEEP);
                        }
                    }
                }
            } catch (IOException e) {
                // the child is gone
            }
        }

        String tail() {
            synchronized (tail) {
                return tail.toString().trim().replace('\n', ' ');
            }
        }
    }
}
