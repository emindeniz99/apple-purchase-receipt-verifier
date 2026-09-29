package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import run.endive.runtime.Memory;

/**
 * The canonical-ABI tests of round 13 (docs/evidence/2026-09-29-canonical-abi-final,
 * hosts/endive/Tests.java) on this artifact's own Endive guest: the
 * interface's contract, env out of range, the lowering helper's type checks,
 * the import answering the wrong length, trap isolation between instances,
 * and linear memory staying the same size over 2,000 calls. They call the
 * guest directly, below the facade, since the facade never lets a caller
 * reach these misuses.
 */
@Tag("endive")
class EndiveAbiTest {

    private static final byte[] NONE = new byte[0];
    private static final byte[] DEFAULT_ROOTS = "{\"roots\":[]}".getBytes(StandardCharsets.US_ASCII);
    private static final long NOW = System.currentTimeMillis();

    private static byte[] g5() throws Exception {
        return Base64.getEncoder().encode(Cases.fixtureBytes("public-receipt-sandbox-g5"));
    }

    private static byte[] jws() throws Exception {
        return Cases.fixtureBytes("transaction");
    }

    /** init's configuration naming the JWS fixture's own root. */
    private static byte[] jwsConfig() throws Exception {
        return WasmVerifier.configJson(
                new java.util.LinkedHashSet<>(Cases.roots(Cases.MAPPER.readTree("[\"jws-root\"]"))));
    }

    private static byte[] endpointRequest() throws Exception {
        return ("{\"receipt-data\":\"" + new String(g5(), StandardCharsets.US_ASCII) + "\"}")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static EndiveGuest fresh(byte[] config) {
        EndiveGuest guest = new EndiveGuest(new SecureRandom());
        assertEquals("{\"ok\":true}", guest.init(config));
        return guest;
    }

    @AfterEach
    void resetTheImportHook() {
        EndiveGuest.randomTrimForTests = 0;
    }

    // ------------------------------------------------------------ the contract

    @Test
    void initWithNoRootsAnswersOk() {
        assertEquals("{\"ok\":true}", new EndiveGuest(new SecureRandom()).init(NONE));
        assertEquals("{\"ok\":true}", new EndiveGuest(new SecureRandom()).init(DEFAULT_ROOTS));
    }

    @Test
    void aVerifyBeforeInitTraps() {
        EndiveGuest guest = new EndiveGuest(new SecureRandom());
        assertThrows(RuntimeException.class, () -> guest.verifyReceipt(NOW, g5()));
    }

    @Test
    void aSecondInitTraps() {
        EndiveGuest guest = fresh(NONE);
        assertThrows(RuntimeException.class, () -> guest.init(NONE));
    }

    @Test
    void aConfigThatIsNotJsonIsRefusedAndInitCanBeRetried() {
        EndiveGuest guest = new EndiveGuest(new SecureRandom());
        String answer = guest.init("{not json".getBytes(StandardCharsets.US_ASCII));
        assertTrue(answer.contains("\"ok\":false"), answer);
        assertEquals("{\"ok\":true}", guest.init(NONE));
    }

    @Test
    void theFourOperationsAnswer() throws Exception {
        EndiveGuest guest = fresh(DEFAULT_ROOTS);
        String receipt = guest.verifyReceipt(NOW, g5());
        assertTrue(receipt.contains("\"verified\":true"), receipt);
        String endpoint = guest.verifyReceiptEndpoint(1, NOW, endpointRequest());
        assertTrue(endpoint.contains("\"status\":0"), endpoint);
        String jws = fresh(jwsConfig()).verifySignedData(NOW, jws());
        assertTrue(jws.contains("\"verified\":true"), jws);
    }

    /** Inputs are bytes: a JWS that is not UTF-8 reaches the core and is answered as a value. */
    @Test
    void aJwsThatIsNotUtf8IsAValue() {
        EndiveGuest guest = fresh(NONE);
        String answer = guest.verifySignedData(NOW, new byte[] {'e', 'y', (byte) 0xff, (byte) 0xfe, '.', 'x'});
        assertTrue(answer.contains("\"verified\":false"), answer);
    }

    @Test
    void theLoweringHelperRefusesAWrongTypeOrCountBeforeAnyCall() throws Exception {
        EndiveGuest guest = fresh(NONE);
        byte[] g5 = g5();
        IllegalArgumentException u64 =
                assertThrows(IllegalArgumentException.class, () -> guest.call("verify-receipt", 5, g5));
        assertTrue(u64.getMessage().contains("WIT type is d"), u64.getMessage());
        IllegalArgumentException u32 = assertThrows(
                IllegalArgumentException.class,
                () -> guest.call("verify-receipt-endpoint", 1L, NOW, endpointRequest()));
        assertTrue(u32.getMessage().contains("WIT type is w"), u32.getMessage());
        IllegalArgumentException list =
                assertThrows(IllegalArgumentException.class, () -> guest.call("verify-receipt", NOW, 3.5));
        assertTrue(list.getMessage().contains("WIT type is b"), list.getMessage());
        assertThrows(IllegalArgumentException.class, () -> guest.call("verify-receipt", NOW));
        assertThrows(IllegalArgumentException.class, () -> guest.call("no-such-export", NOW, g5));
        assertTrue(guest.verifyReceipt(NOW, g5).contains("\"verified\":true"), "the instance still verifies");
    }

    // ------------------------------------------------------------ env

    @Test
    void anEnvOtherThanZeroOrOneTraps() throws Exception {
        for (int env : new int[] {2, 255, -1}) {
            EndiveGuest guest = fresh(NONE);
            byte[] request = endpointRequest();
            assertThrows(
                    RuntimeException.class,
                    () -> guest.verifyReceiptEndpoint(env, NOW, request),
                    "env " + Integer.toUnsignedString(env));
        }
    }

    // ------------------------------------------------------------ the import

    @Test
    void randomGetAnsweringTheWrongLengthTraps() throws Exception {
        EndiveGuest guest = fresh(jwsConfig());
        byte[] jws = jws();
        EndiveGuest.randomTrimForTests = 1;
        assertThrows(RuntimeException.class, () -> guest.verifySignedData(NOW, jws));
    }

    // ------------------------------------------------------------ isolation and memory

    @Test
    void aTrapInOneInstanceLeavesAnotherVerifying() throws Exception {
        EndiveGuest trapped = fresh(NONE);
        EndiveGuest other = fresh(NONE);
        byte[] g5 = g5();
        assertTrue(other.verifyReceipt(NOW, g5).contains("\"verified\":true"));
        byte[] request = endpointRequest();
        assertThrows(RuntimeException.class, () -> trapped.verifyReceiptEndpoint(2, NOW, request));
        assertTrue(other.verifyReceipt(NOW, g5).contains("\"verified\":true"));
        assertTrue(other.verifyReceipt(NOW, g5).contains("\"verified\":true"));
        // Recorded, not asserted: Endive lets a trapped instance keep answering,
        // which is why the pool discards it (finding 4 of round 13).
        String again;
        try {
            again = trapped.verifyReceipt(NOW, g5).contains("\"verified\":true") ? "verifies" : "answers";
        } catch (RuntimeException e) {
            again = "throws " + e.getClass().getSimpleName();
        }
        System.out.println("RECORD the trapped instance, called again: " + again);
    }

    @Test
    void twoThousandCallsLeaveLinearMemoryTheSameSize() throws Exception {
        EndiveGuest guest = fresh(NONE);
        byte[] g5 = g5();
        byte[] junk = "not a receipt".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 20; i++) {
            guest.verifyReceipt(NOW, g5);
        }
        long before = pages(guest);
        for (int i = 0; i < 2000; i++) {
            guest.verifyReceipt(NOW, i % 100 == 0 ? g5 : junk);
        }
        assertEquals(before, pages(guest), "linear memory pages after 2,000 calls");
        System.out.println(
                "RECORD linear memory: " + before * Memory.PAGE_SIZE + " bytes before and after 2,000 calls");
    }

    private static long pages(EndiveGuest guest) {
        return guest.instance().memory().pages();
    }
}
