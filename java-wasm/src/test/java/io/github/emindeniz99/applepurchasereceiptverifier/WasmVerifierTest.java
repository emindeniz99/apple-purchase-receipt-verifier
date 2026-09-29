package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The facade on the Endive engine: the instance model (a forced trap
 * discards the instance and the next call succeeds; the probe; the pool
 * under threads), the clock rule, and the outcomes a wrapper maps itself.
 */
@Tag("endive")
class WasmVerifierTest {

    private static final Config DEFAULTS = Config.defaults();

    /** An Endive guest that traps once, on the call after {@code trapNext} is set, through env 2. */
    private static final class TrapOnce implements Guest {
        final EndiveGuest guest = new EndiveGuest(new SecureRandom());
        final AtomicBoolean trapNext;

        TrapOnce(AtomicBoolean trapNext) {
            this.trapNext = trapNext;
        }

        @Override
        public String init(byte[] configJson) {
            return guest.init(configJson);
        }

        @Override
        public String verifyReceipt(long nowMs, byte[] receiptBase64) {
            if (trapNext.getAndSet(false)) {
                return guest.verifyReceiptEndpoint(2, nowMs, receiptBase64);
            }
            return guest.verifyReceipt(nowMs, receiptBase64);
        }

        @Override
        public String verifySignedData(long nowMs, byte[] jws) {
            return guest.verifySignedData(nowMs, jws);
        }

        @Override
        public String verifyReceiptEndpoint(int env, long nowMs, byte[] requestJson) {
            if (trapNext.getAndSet(false)) {
                return guest.verifyReceiptEndpoint(2, nowMs, requestJson);
            }
            return guest.verifyReceiptEndpoint(env, nowMs, requestJson);
        }
    }

    private static GuestFactory trapping(AtomicBoolean trapNext, AtomicInteger made) {
        return new GuestFactory() {
            @Override
            public Guest newGuest() {
                made.incrementAndGet();
                return new TrapOnce(trapNext);
            }

            @Override
            public String describe() {
                return "test";
            }
        };
    }

    /** A real Endive guest that records the longest input it was handed and its memory afterwards. */
    private static GuestFactory recording(AtomicInteger longest, AtomicLong memory) {
        return new GuestFactory() {
            @Override
            public Guest newGuest() {
                EndiveGuest guest = new EndiveGuest(new SecureRandom());
                return new Guest() {
                    @Override
                    public String init(byte[] configJson) {
                        return guest.init(configJson);
                    }

                    @Override
                    public String verifyReceipt(long nowMs, byte[] input) {
                        longest.accumulateAndGet(input.length, Math::max);
                        String answer = guest.verifyReceipt(nowMs, input);
                        memory.accumulateAndGet(guest.linearMemoryBytes(), Math::max);
                        return answer;
                    }

                    @Override
                    public String verifySignedData(long nowMs, byte[] input) {
                        longest.accumulateAndGet(input.length, Math::max);
                        String answer = guest.verifySignedData(nowMs, input);
                        memory.accumulateAndGet(guest.linearMemoryBytes(), Math::max);
                        return answer;
                    }

                    @Override
                    public String verifyReceiptEndpoint(int env, long nowMs, byte[] input) {
                        longest.accumulateAndGet(input.length, Math::max);
                        String answer = guest.verifyReceiptEndpoint(env, nowMs, input);
                        memory.accumulateAndGet(guest.linearMemoryBytes(), Math::max);
                        return answer;
                    }
                };
            }

            @Override
            public String describe() {
                return "recording";
            }
        };
    }

    private static String repeat(char c, int n) {
        char[] chars = new char[n];
        java.util.Arrays.fill(chars, c);
        return new String(chars);
    }

    /**
     * An input far over the cap is cut to one byte over it before it enters
     * the module, and the core answers exactly as for the whole input:
     * TOO_LARGE with its own message, 21002 from the endpoint. The instance
     * does not grow to the input's size.
     */
    @Test
    void anInputOverTheCapReachesTheModuleOneByteOverIt() {
        AtomicInteger longest = new AtomicInteger();
        AtomicLong memory = new AtomicLong();
        WasmVerifier verifier = new WasmVerifier(DEFAULTS, recording(longest, memory));
        String fourMib = repeat('A', 4 << 20);
        Failure receipt = verifier.verifyReceipt(fourMib).failure();
        assertEquals(Reason.TOO_LARGE, receipt.reason());
        assertEquals("receipt exceeds the maximum accepted size of 3145728 bytes", receipt.message());
        assertEquals(WasmVerifier.MAX_INPUT_BYTES, longest.get());
        assertEquals(
                Reason.TOO_LARGE, verifier.verifySignedData(fourMib).failure().reason());
        assertEquals(
                "{\"status\":21002}",
                verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + fourMib + "\"}"));
        // Two-byte characters: the cut may fall inside one; the core still sees a body over the cap.
        assertEquals(
                "{\"status\":21002}",
                verifier.verifyReceiptEndpoint(
                        Environment.SANDBOX, "{\"receipt-data\":\"" + repeat('\u00e9', 2 << 20) + "\"}"));
        assertEquals(WasmVerifier.MAX_INPUT_BYTES, longest.get());
        assertTrue(memory.get() < 16L << 20, "linear memory stayed small: " + memory.get());
    }

    /** An input at the cap is passed whole: nothing an unchanged input could answer is cut. */
    @Test
    void anInputAtTheCapIsPassedWhole() {
        AtomicInteger longest = new AtomicInteger();
        WasmVerifier verifier = new WasmVerifier(DEFAULTS, recording(longest, new AtomicLong()));
        String atCap = repeat('A', 3_145_728);
        Failure failure = verifier.verifyReceipt(atCap).failure();
        assertEquals(3_145_728, longest.get());
        assertTrue(failure.reason() != Reason.TOO_LARGE, "at the cap is not over it: " + failure);
        assertEquals(3_145_728, WasmVerifier.bytes(atCap).length);
        assertEquals(WasmVerifier.MAX_INPUT_BYTES, WasmVerifier.bytes(atCap + "A").length);
        assertEquals(WasmVerifier.MAX_INPUT_BYTES, WasmVerifier.bytes(repeat('\u20ac', 1_100_000)).length);
        assertEquals("a?b", new String(WasmVerifier.bytes("a\ud800b"), java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String g5() throws Exception {
        return Cases.receiptString(Cases.MAPPER.readTree("{\"fixture\":\"public-receipt-sandbox-g5\"}"));
    }

    @Test
    void aTrapIsInternalErrorDiscardsTheInstanceAndTheNextCallSucceeds() throws Exception {
        AtomicBoolean trapNext = new AtomicBoolean();
        AtomicInteger made = new AtomicInteger();
        WasmVerifier verifier = new WasmVerifier(DEFAULTS, trapping(trapNext, made));
        String g5 = g5();
        String before = verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5 + "\"}");
        assertTrue(before.contains("\"status\":0"), before);
        assertEquals(1, made.get());

        trapNext.set(true);
        VerificationResult<ReceiptPayload> trapped = verifier.verifyReceipt(g5);
        Failure failure = trapped.failure();
        assertNotNull(failure);
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertTrue(failure.cause() instanceof GuestFailure, String.valueOf(failure.cause()));
        assertTrue(failure.message().contains("Exception"), "the message names the trap: " + failure.message());
        assertEquals(0, verifier.pool().idle(), "the trapped instance is not back in the pool");

        String after = verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5 + "\"}");
        assertTrue(after.contains("\"status\":0"), after);
        assertEquals(2, made.get(), "a new instance answered");

        trapNext.set(true);
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
        String third = verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5 + "\"}");
        assertTrue(third.contains("\"status\":0"), third);
        assertEquals(3, made.get(), "the endpoint's trap discarded its instance too");
    }

    @Test
    void theProbeMakesTheFirstInstanceAtCreateAndOffLeavesItToTheFirstCall() throws Exception {
        AtomicInteger made = new AtomicInteger();
        WasmVerifier probed = new WasmVerifier(DEFAULTS, trapping(new AtomicBoolean(), made));
        assertEquals(1, made.get());
        assertEquals(1, probed.pool().idle());

        AtomicInteger lazy = new AtomicInteger();
        WasmVerifier unprobed =
                new WasmVerifier(Config.builder().runtimeProbe(false).build(), trapping(new AtomicBoolean(), lazy));
        assertEquals(0, lazy.get());
        // The endpoint: its answer passes through, so no answer can discard the instance.
        unprobed.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5() + "\"}");
        unprobed.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5() + "\"}");
        assertEquals(1, lazy.get(), "the first call made the instance and the second reused it");
    }

    @Test
    void theClockIsReadOncePerCallBeforeTheInput() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        Clock counting = new Clock() {
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
                reads.incrementAndGet();
                return Instant.parse("2025-01-01T00:00:00Z");
            }
        };
        Verifier verifier = Verifier.create(Config.builder().clock(counting).build(), Engine.endive());
        verifier.verifyReceipt(g5());
        verifier.verifySignedData("x");
        verifier.verifyReceiptEndpoint(Environment.PRODUCTION, null);
        assertEquals(3, reads.get());
    }

    @Test
    void aClockThatThrowsIsInternalError() throws Exception {
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
                throw new IllegalStateException("no time");
            }
        };
        Verifier verifier = Verifier.create(Config.builder().clock(broken).build(), Engine.endive());
        Failure receipt = verifier.verifyReceipt(g5()).failure();
        assertEquals(Reason.INTERNAL_ERROR, receipt.reason());
        assertEquals("unexpected java.lang.IllegalStateException", receipt.message());
        assertEquals(
                Reason.INTERNAL_ERROR, verifier.verifySignedData("x").failure().reason());
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
    }

    @Test
    void theCallerMistakesOf07() {
        assertThrows(NullPointerException.class, () -> Verifier.create(null, Engine.endive()));
        assertThrows(NullPointerException.class, () -> Verifier.create(DEFAULTS, null));
        IllegalArgumentException empty = assertThrows(
                IllegalArgumentException.class,
                () -> Verifier.create(Config.builder().roots(new ArrayList<>()).build(), Engine.endive()));
        assertEquals("trustedRoots must not be empty", empty.getMessage());
        Verifier verifier = Verifier.create(DEFAULTS, Engine.endive());
        assertThrows(NullPointerException.class, () -> verifier.verifyReceiptEndpoint(null, "{}"));
    }

    /** A root the module refuses: a caller's mistake at create with the probe, a module failure without it. */
    @Test
    void aRootTheModuleRefuses() {
        GuestFactory refusing = new GuestFactory() {
            @Override
            public Guest newGuest() {
                return new Guest() {
                    @Override
                    public String init(byte[] configJson) {
                        return "{\"ok\":false,\"message\":\"roots[0] is not a certificate\"}";
                    }

                    @Override
                    public String verifyReceipt(long nowMs, byte[] receiptBase64) {
                        throw new AssertionError();
                    }

                    @Override
                    public String verifySignedData(long nowMs, byte[] jws) {
                        throw new AssertionError();
                    }

                    @Override
                    public String verifyReceiptEndpoint(int env, long nowMs, byte[] requestJson) {
                        throw new AssertionError();
                    }
                };
            }

            @Override
            public String describe() {
                return "test";
            }
        };
        IllegalArgumentException probed =
                assertThrows(IllegalArgumentException.class, () -> new WasmVerifier(DEFAULTS, refusing));
        assertTrue(probed.getMessage().contains("roots[0] is not a certificate"), probed.getMessage());
        WasmVerifier lazy =
                new WasmVerifier(Config.builder().runtimeProbe(false).build(), refusing);
        Failure failure = lazy.verifySignedData("x").failure();
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertTrue(failure.message().contains("refused the configured roots"), failure.message());
        assertEquals("{\"status\":21009}", lazy.verifyReceiptEndpoint(Environment.PRODUCTION, "{}"));
    }

    /** A module without the exports this library binds fails create, naming the version and what it has. */
    @Test
    void anAbiMismatchFailsCreate() {
        GuestFactory mismatched = new GuestFactory() {
            @Override
            public Guest newGuest() {
                throw new GuestFailure("ABI mismatch: this library binds aprv:verifier/verify@1.0.0 and the module"
                        + " lacks [aprv:verifier/verify@1.0.0#init]; it exports [memory]");
            }

            @Override
            public String describe() {
                return "test";
            }
        };
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> new WasmVerifier(DEFAULTS, mismatched));
        assertTrue(e.getMessage().contains("aprv:verifier/verify@1.0.0"), e.getMessage());
    }

    /** The committed module exports exactly what the guest binds. */
    @Test
    void theCommittedModuleHasTheAbi() {
        new EndiveGuestFactory().newGuest();
    }

    @Test
    void theDefaultRootsReachTheModuleAsTheBuiltInOnes() throws Exception {
        assertEquals("{\"roots\":[]}", new String(WasmVerifier.configJson(DEFAULTS.roots()), "US-ASCII"));
        String custom = new String(
                WasmVerifier.configJson(
                        new java.util.LinkedHashSet<>(Cases.roots(Cases.MAPPER.readTree("[\"jws-root\"]")))),
                "US-ASCII");
        assertTrue(custom.startsWith("{\"roots\":[\"MII") && custom.endsWith("\"]}"), custom);
    }

    /**
     * N threads over one verifier give the single-thread answers: each call
     * takes an instance of its own from the pool.
     */
    @Test
    void threadsGetTheSingleThreadAnswers() throws Exception {
        List<JsonNode> cases = new ArrayList<>();
        for (JsonNode kase : Cases.document().get("cases")) {
            String operation = kase.get("operation").asText();
            if (!kase.has("clock")
                    && kase.get("config")
                            .get("trustedRoots")
                            .get("source")
                            .asText()
                            .equals("defaults")
                    && (operation.equals("verifyReceipt") || operation.equals("verifySignedData"))) {
                cases.add(kase);
            }
            if (cases.size() == 16) {
                break;
            }
        }
        Verifier verifier = Verifier.create(DEFAULTS, Engine.endive());
        List<String> inputs = new ArrayList<>();
        List<Boolean> receipts = new ArrayList<>();
        for (JsonNode kase : cases) {
            boolean receipt = kase.get("operation").asText().equals("verifyReceipt");
            receipts.add(receipt);
            inputs.add(
                    receipt
                            ? Cases.receiptString(kase.get("input"))
                            : Cases.text(Cases.fixtureBytes(
                                    kase.get("input").get("fixture").asText())));
        }
        List<String> single = new ArrayList<>();
        for (int i = 0; i < inputs.size(); i++) {
            single.add(answer(verifier, receipts.get(i), inputs.get(i)));
        }
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<List<String>>> runs = new ArrayList<>();
            for (int t = 0; t < 4; t++) {
                runs.add(pool.submit(() -> {
                    List<String> answers = new ArrayList<>();
                    for (int round = 0; round < 3; round++) {
                        for (int i = 0; i < inputs.size(); i++) {
                            answers.add(answer(verifier, receipts.get(i), inputs.get(i)));
                        }
                    }
                    return answers;
                }));
            }
            for (Future<List<String>> run : runs) {
                List<String> answers = run.get();
                for (int k = 0; k < answers.size(); k++) {
                    assertEquals(
                            single.get(k % inputs.size()),
                            answers.get(k),
                            cases.get(k % inputs.size()).get("id").asText());
                }
            }
        } finally {
            pool.shutdown();
        }
    }

    private static String answer(Verifier verifier, boolean receipt, String input) {
        VerificationResult<?> result = receipt ? verifier.verifyReceipt(input) : verifier.verifySignedData(input);
        Failure failure = result.failure();
        if (failure == null) {
            Object payload = result.payload();
            return payload instanceof ReceiptPayload ? ((ReceiptPayload) payload).toJson() : payload.toString();
        }
        // A module failure's message can carry an instance-specific detail;
        // the reason and whether there is a cause are the answer.
        return failure.reason() + (failure.reason() == Reason.INTERNAL_ERROR ? "" : ": " + failure.message());
    }

    @Test
    void nullInputIsTheEmptyInput() {
        Verifier verifier = Verifier.create(DEFAULTS, Engine.endive());
        assertEquals(
                String.valueOf(verifier.verifyReceipt("").failure()),
                String.valueOf(verifier.verifyReceipt(null).failure()));
        assertEquals(
                String.valueOf(verifier.verifySignedData("").failure()),
                String.valueOf(verifier.verifySignedData(null).failure()));
        assertEquals(
                verifier.verifyReceiptEndpoint(Environment.PRODUCTION, ""),
                verifier.verifyReceiptEndpoint(Environment.PRODUCTION, null));
        assertNull(verifier.verifyReceipt(null).payload());
    }
}
