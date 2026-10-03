package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * How the server engine maps what a server answers, against a fake server
 * on loopback reached through {@link ServerSource#url}: 401 and 500
 * problems (WASM_TRAP, ABI_ERROR, and a body that is not a problem), a 413
 * with the module's answer and one with a problem, the
 * clock read once per call and sent as {@code X-Aprv-Now-Ms}, a clock that
 * throws, and a server whose roots differ from the config's. No binary
 * runs, so this runs wherever the tests do; the {@code noexec} parser is
 * here too.
 */
class ServerProblemTest {

    private static final String TOKEN = "fake-token-0123456789";

    private HttpServer http;
    private final Map<String, String[]> answers = new ConcurrentHashMap<>();
    private final List<String> nowHeaders = Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> bodyLengths = Collections.synchronizedList(new ArrayList<>());
    private volatile List<String> infoRoots;
    private volatile String infoLimits = ",\"limits\":{\"max_input_bytes\":3145729}";

    @BeforeEach
    void serve() throws Exception {
        infoRoots = new ArrayList<>(ServerSources.fingerprints(AppleRootCerts.roots()));
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            int status;
            String type = "application/json";
            if (!TOKEN.equals(exchange.getRequestHeaders().getFirst("X-Aprv-Token"))) {
                status = 401;
                body = problem(401, "UNAUTHORIZED");
                type = "application/problem+json";
            } else if (path.equals("/v1/info")) {
                StringBuilder roots = new StringBuilder();
                for (String root : infoRoots) {
                    roots.append(roots.length() == 0 ? "" : ",")
                            .append('"')
                            .append(root)
                            .append('"');
                }
                status = 200;
                body = ("{\"roots\":{\"source\":\"test\",\"sha256\":[" + roots + "]},\"component_sha256\":\"fake\""
                                + infoLimits + "}")
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                nowHeaders.add(exchange.getRequestHeaders().getFirst("X-Aprv-Now-Ms"));
                int length = 0;
                byte[] buffer = new byte[8192];
                for (int n; (n = exchange.getRequestBody().read(buffer)) > 0; ) {
                    length += n;
                }
                bodyLengths.add(length);
                String[] answer = answers.get(path);
                status = Integer.parseInt(answer[0]);
                body = answer[1].getBytes(StandardCharsets.UTF_8);
                type = answer.length > 2 ? answer[2] : "application/problem+json";
            }
            exchange.getResponseHeaders().set("Content-Type", type);
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        http.start();
    }

    @AfterEach
    void stop() {
        http.stop(0);
    }

    private static byte[] problem(int status, String code) {
        return problemText(status, code).getBytes(StandardCharsets.UTF_8);
    }

    private static String problemText(int status, String code) {
        return "{\"type\":\"about:blank\",\"title\":\"" + code + "\",\"status\":" + status + ",\"code\":\"" + code
                + "\",\"detail\":\"detail of " + code + "\"}";
    }

    private URI uri() {
        return URI.create("http://127.0.0.1:" + http.getAddress().getPort());
    }

    private Verifier verifier(Config config) {
        return Verifier.create(config, Engine.server(ServerSource.url(uri(), TOKEN)));
    }

    private void answer(String path, int status, String body) {
        answers.put(path, new String[] {String.valueOf(status), body});
    }

    private static ServerProblem assertProblem(Failure failure, int status, String code) {
        assertEquals(Reason.INTERNAL_ERROR, failure.reason(), failure.message());
        assertTrue(failure.cause() instanceof ServerProblem, String.valueOf(failure.cause()));
        ServerProblem problem = (ServerProblem) failure.cause();
        assertEquals(status, problem.status());
        assertEquals(code, problem.code());
        assertEquals(problem.getMessage(), failure.message());
        return problem;
    }

    @Test
    void aTrapAndAnAbiErrorAreInternalErrorsCarryingTheProblem() {
        Verifier verifier = verifier(Config.defaults());
        answer("/v1/receipt/verify", 500, problemText(500, "WASM_TRAP"));
        answer("/v1/signed-data/verify", 500, problemText(500, "ABI_ERROR"));
        ServerProblem trap = assertProblem(verifier.verifyReceipt("AAAA").failure(), 500, "WASM_TRAP");
        assertEquals("aprv-server answered HTTP 500 WASM_TRAP: detail of WASM_TRAP", trap.getMessage());
        assertProblem(verifier.verifySignedData("a.b.c").failure(), 500, "ABI_ERROR");
        answer("/v1/receipt/verify", 500, "not json at all");
        assertProblem(verifier.verifyReceipt("AAAA").failure(), 500, "HTTP_500");
        answer("/v1/verify-receipt/sandbox", 500, problemText(500, "INTERNAL_ERROR"));
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
    }

    @Test
    void anUnauthorizedAnswerIsAnInternalError() {
        Verifier verifier = verifier(Config.defaults());
        answer("/v1/receipt/verify", 401, problemText(401, "UNAUTHORIZED"));
        answer("/v1/verify-receipt/production", 401, problemText(401, "UNAUTHORIZED"));
        assertProblem(verifier.verifyReceipt("AAAA").failure(), 401, "UNAUTHORIZED");
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.PRODUCTION, "{}"));
    }

    /** The clock is read once per call, and its reading is what the server is told. */
    @Test
    void theClockIsReadOncePerCallAndSentAsNow() {
        AtomicInteger reads = new AtomicInteger();
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return Instant.ofEpochMilli(millis());
            }

            @Override
            public long millis() {
                return 1_700_000_000_000L + reads.incrementAndGet();
            }
        };
        Verifier verifier = verifier(Config.builder().clock(clock).build());
        answer("/v1/receipt/verify", 500, problemText(500, "WASM_TRAP"));
        answer("/v1/verify-receipt/sandbox", 200, "{\"status\":21002}");
        verifier.verifyReceipt("AAAA");
        assertEquals("{\"status\":21002}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
        assertEquals(2, reads.get());
        assertEquals(Arrays.asList("1700000000001", "1700000000002"), nowHeaders);
    }

    @Test
    void aClockThatThrowsIsAnInternalErrorAndNoRequest() {
        Clock broken = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                throw new IllegalStateException("clock broken");
            }

            @Override
            public long millis() {
                throw new IllegalStateException("clock broken");
            }
        };
        Verifier verifier = verifier(Config.builder().clock(broken).build());
        Failure failure = verifier.verifyReceipt("AAAA").failure();
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertEquals("unexpected java.lang.IllegalStateException", failure.message());
        assertTrue(failure.cause() instanceof IllegalStateException);
        assertEquals(
                Reason.INTERNAL_ERROR,
                verifier.verifySignedData("a.b.c").failure().reason());
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
        assertTrue(nowHeaders.isEmpty(), "nothing was sent: " + nowHeaders);
    }

    @Test
    void aServerWithOtherRootsIsRefused() {
        infoRoots = new ArrayList<>(infoRoots.subList(0, 2));
        IllegalStateException fewer = assertThrows(IllegalStateException.class, () -> verifier(Config.defaults()));
        assertTrue(fewer.getMessage().contains("trusts other roots than the Config"), fewer.getMessage());
        infoRoots = new ArrayList<>(ServerSources.fingerprints(AppleRootCerts.roots()));
        infoRoots.add("00".replace("0", "ab"));
        assertThrows(IllegalStateException.class, () -> verifier(Config.defaults()));
        infoRoots = Collections.emptyList();
        assertThrows(IllegalStateException.class, () -> verifier(Config.defaults()));
    }

    /**
     * The input length is the module's (DECISIONS.md R42): the engine cuts an
     * input to the {@code limits.max_input_bytes} the server states, and
     * refuses a server that states none, whose module is older than this
     * library.
     */
    @Test
    void inputsAreCutToTheLengthTheServerStatesAndAServerStatingNoneIsRefused() {
        infoLimits = ",\"limits\":{\"max_input_bytes\":10}";
        Verifier verifier = verifier(Config.defaults());
        answers.put("/v1/receipt/verify", new String[] {
            "413", "{\"verified\":false,\"reason\":\"TOO_LARGE\",\"message\":\"m\"}", "application/json"
        });
        assertEquals(
                Reason.TOO_LARGE,
                verifier.verifyReceipt(repeat('A', 100)).failure().reason());
        assertEquals(
                Reason.TOO_LARGE,
                verifier.verifyReceipt(repeat('A', 9)).failure().reason());
        assertEquals(Arrays.asList(10, 9), bodyLengths);
        for (String limits : new String[] {
            "", ",\"limits\":{}", ",\"limits\":{\"max_input_bytes\":0}", ",\"limits\":{\"max_input_bytes\":\"10\"}"
        }) {
            infoLimits = limits;
            IllegalStateException refused =
                    assertThrows(IllegalStateException.class, () -> verifier(Config.defaults()));
            assertTrue(refused.getMessage().contains("max_input_bytes"), refused.getMessage());
        }
    }

    private static String repeat(char c, int n) {
        char[] chars = new char[n];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    @Test
    void aRootsRefusalIsReadFromTheChildsStderr() {
        String answer = "{\"ok\":false,\"message\":\"roots[0]: trust anchor is not a certificate\"}";
        InitRefused refused =
                ServerProcess.rootsRefusal("aprv: the component refused the roots configuration: " + answer);
        assertEquals(answer, refused.answer());
        assertEquals("roots[0]: trust anchor is not a certificate", refused.getMessage());
        assertEquals(null, ServerProcess.rootsRefusal("aprv: bad handshake: the token is too short"));
        assertEquals(
                null,
                ServerProcess.rootsRefusal("aprv: the component refused the roots configuration: not json"),
                "an unreadable answer is a process failure, not a refusal");
    }

    /**
     * The server sends the module's own answer to an input over the cap with
     * 413, and the engine reads it as it reads a 200: whatever the module
     * said, not an answer of the engine's own.
     */
    @Test
    void a413CarryingTheModulesAnswerIsReadAsA200() {
        Verifier verifier = verifier(Config.defaults());
        answers.put("/v1/receipt/verify", new String[] {
            "413",
            "{\"verified\":false,\"reason\":\"TOO_LARGE\",\"message\":\"said by the module\"}",
            "application/json"
        });
        answers.put("/v1/signed-data/verify", new String[] {
            "413", "{\"verified\":false,\"reason\":\"TOO_LARGE\",\"message\":\"the jws one\"}", "application/json"
        });
        answers.put("/v1/verify-receipt/production", new String[] {"413", "{\"status\":21002}", "application/json"});
        Failure receipt = verifier.verifyReceipt("AAAA").failure();
        assertEquals(Reason.TOO_LARGE, receipt.reason());
        assertEquals("said by the module", receipt.message());
        Failure jws = verifier.verifySignedData("a.b.c").failure();
        assertEquals(Reason.TOO_LARGE, jws.reason());
        assertEquals("the jws one", jws.message());
        assertEquals("{\"status\":21002}", verifier.verifyReceiptEndpoint(Environment.PRODUCTION, "{}"));
    }

    /**
     * A 413 that is a problem document, as servers before the module
     * answered the cap sent, is a server problem like any other: the engine
     * does not make up the module's answer.
     */
    @Test
    void a413ProblemIsAnInternalError() {
        Verifier verifier = verifier(Config.defaults());
        answer("/v1/receipt/verify", 413, problemText(413, "PAYLOAD_TOO_LARGE"));
        answer("/v1/verify-receipt/sandbox", 413, problemText(413, "PAYLOAD_TOO_LARGE"));
        assertProblem(verifier.verifyReceipt("AAAA").failure(), 413, "PAYLOAD_TOO_LARGE");
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
    }

    @Test
    void theNoexecParserFindsTheMountHoldingThePath() {
        List<String> mountinfo = Arrays.asList(
                "22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/root rw",
                "30 22 0:26 / /tmp rw,nosuid,nodev,noexec,relatime shared:2 - tmpfs tmpfs rw",
                "31 30 0:27 / /tmp/exec\\040ok rw,relatime shared:3 - tmpfs tmpfs rw",
                "32 22 0:28 / /home/me/.cache rw,noexec shared:4 - tmpfs tmpfs rw",
                "33 22 0:29 / /opt rw,relatime - ext4 /dev/sdb rw",
                "34 33 0:30 / /opt rw,noexec - tmpfs tmpfs rw");
        assertTrue(ServerBinary.noexec(Paths.get("/tmp/aprv/aprv-x"), mountinfo));
        assertFalse(ServerBinary.noexec(Paths.get("/tmp/exec ok/aprv-x"), mountinfo), "a nested exec mount wins");
        assertFalse(ServerBinary.noexec(Paths.get("/tmpfoo/aprv-x"), mountinfo), "a path prefix is not a parent");
        assertTrue(ServerBinary.noexec(Paths.get("/home/me/.cache/aprv/aprv-x"), mountinfo));
        assertFalse(ServerBinary.noexec(Paths.get("/home/me/aprv-x"), mountinfo));
        assertTrue(ServerBinary.noexec(Paths.get("/opt/aprv"), mountinfo), "the later mount on the same point wins");
        assertTrue(ServerBinary.NOEXEC_ADVICE.contains("cacheDirectory(...)"));
    }
}
