package spike.aprv.cabi;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;

/**
 * Spike only (2026-09-29, round 13). The round-13 ABI tests on Endive, on
 * the core exports called by hand (the same cases as hosts/wazero/tests.go).
 * "RECORD" lines report behaviour with no pass/fail expectation.
 *   java -cp ... spike.aprv.cabi.Tests CASES.jsonl
 */
public final class Tests {
    private static final String IFACE = "aprv:verifier/verify@1.0.0#";
    private static int failed;

    private static void check(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "PASS " : "FAIL ") + name + ": " + cut(detail));
    }

    private static void record(String name, String detail) {
        System.out.println("RECORD " + name + ": " + cut(detail));
    }

    private static String cut(String s) {
        return s.length() > 260 ? s.substring(0, 260) + "..." : s;
    }

    interface Call {
        String run();
    }

    /** The answer, or "TRAP <exception>" for anything thrown. */
    private static String attempt(Call c) {
        try {
            return c.run();
        } catch (RuntimeException e) {
            String m = String.valueOf(e.getMessage());
            int nl = m.indexOf('\n');
            return "TRAP " + e.getClass().getSimpleName() + ": " + (nl > 0 ? m.substring(0, nl) : m);
        }
    }

    private static boolean trapped(String s) {
        return s.startsWith("TRAP ");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> row(String cases, String id) throws Exception {
        for (String l : Files.readAllLines(Paths.get(cases), StandardCharsets.UTF_8)) {
            if (l.contains("\"" + id + "\"")) {
                return (Map<String, Object>) Json.parse(l);
            }
        }
        throw new IllegalStateException("no row " + id);
    }

    private static AprvCabi fresh(byte[] config) {
        AprvCabi g = new AprvCabi();
        String s = g.init(config);
        if (!s.equals("{\"ok\":true}")) {
            throw new IllegalStateException(s);
        }
        return g;
    }

    public static void main(String[] args) throws Exception {
        byte[] g5 = Base64.getDecoder().decode((String) row(args[0], "receipt/verify-genuine-sandbox-g5-against-apple-roots").get("b64"));
        Map<String, Object> jr = row(args[0], "transaction/verify-shared-sandbox");
        byte[] jws = Base64.getDecoder().decode((String) jr.get("b64"));
        byte[] jwsConfig = ((String) jr.get("config")).getBytes(StandardCharsets.UTF_8);
        byte[] none = new byte[0];
        byte[] req = ("{\"receipt-data\":\"" + new String(g5, StandardCharsets.UTF_8) + "\"}").getBytes(StandardCharsets.UTF_8);
        long now = System.currentTimeMillis();

        // --- the interface's contract
        check("init(empty) answers {\"ok\":true}", new AprvCabi().init(none).equals("{\"ok\":true}"), "");
        AprvCabi g0 = new AprvCabi();
        String s = attempt(() -> g0.verifyReceipt(now, g5));
        check("verify before init traps", trapped(s), s);
        AprvCabi g1 = fresh(none);
        s = attempt(() -> g1.init(none));
        check("a second init traps", trapped(s), s);
        AprvCabi g2 = new AprvCabi();
        s = attempt(() -> g2.init("{not json".getBytes(StandardCharsets.UTF_8)));
        check("a config that is not JSON is {\"ok\":false}, and init can be retried",
                s.contains("\"ok\":false") && g2.init(none).equals("{\"ok\":true}"), s);
        AprvCabi g = fresh(none);
        s = attempt(() -> g.verifyReceipt(now, g5));
        check("verify-receipt(genuine g5) verifies", s.contains("\"verified\":true"), s);
        AprvCabi gj = fresh(jwsConfig);
        s = attempt(() -> gj.verifySignedData(now, jws));
        check("verify-signed-data(shared-sandbox JWS, its test roots) verifies", s.contains("\"verified\":true"), s);
        s = attempt(() -> g.verifyReceiptEndpoint(1, now, req));
        check("verify-receipt-endpoint(env 1 = sandbox, g5) answers status 0", s.contains("\"status\":0"), s);
        s = attempt(() -> g.verifySignedData(now, new byte[] {'e', 'y', (byte) 0xff, (byte) 0xfe, '.', 'x'}));
        check("a JWS that is not UTF-8 reaches the guest and is a value (ABI v1's answer)", s.contains("jws is not valid UTF-8"), s);
        s = attempt(() -> g.call("verify-receipt", 5, g5));
        check("the lowering helper refuses an Integer (u32) where the WIT says u64 (loud host error, no call)",
                s.startsWith("TRAP IllegalArgumentException") && s.contains("WIT type is d"), s);
        s = attempt(() -> g.call("verify-receipt-endpoint", 1L, now, req));
        check("the lowering helper refuses a Long (u64) where the WIT says u32", s.contains("WIT type is w"), s);
        s = attempt(() -> g.call("verify-receipt", now, 3.5));
        check("the lowering helper refuses a Double where the WIT says list<u8>", s.contains("WIT type is b"), s);
        s = attempt(() -> g.call("verify-receipt", now));
        check("the lowering helper refuses a wrong argument count", s.startsWith("TRAP IllegalArgumentException"), s);
        check("  ... and the instance still verifies g5", attempt(() -> g.verifyReceipt(now, g5)).contains("\"verified\":true"), "");

        // --- env
        for (int env : new int[] {2, 255, -1}) {
            AprvCabi ge = fresh(none);
            s = attempt(() -> ge.verifyReceiptEndpoint(env, now, req));
            check("endpoint with env " + Integer.toUnsignedString(env) + " traps", trapped(s), s);
        }

        // --- pointer misuse (recorded)
        AprvCabi gp = fresh(none);
        long[] a = gp.lower("init", (Object) g5);
        int rp = (int) gp.instance().export(IFACE + "verify-receipt").apply(now, a[0], a[1])[0];
        String first = attempt(() -> { gp.instance().export("cabi_post_" + IFACE + "verify-receipt").apply(rp); return "no trap"; });
        String second = attempt(() -> { gp.instance().export("cabi_post_" + IFACE + "verify-receipt").apply(rp); return "no trap"; });
        record("double post-return on one result", "first: " + first + "; second: " + second
                + "; the instance verifies g5 afterwards: " + attempt(() -> gp.verifyReceipt(now, g5)).contains("\"verified\":true"));
        AprvCabi gf = fresh(none);
        long foreign = gf.lower("init", (Object) "12345678".getBytes(StandardCharsets.UTF_8))[0];
        String pr = attempt(() -> { gf.instance().export("cabi_post_" + IFACE + "verify-receipt").apply(foreign); return "no trap"; });
        record("post-return with a foreign pointer (a heap block no export returned)", pr
                + "; the instance verifies g5 afterwards: " + attempt(() -> gf.verifyReceipt(now, g5)).contains("\"verified\":true"));

        // --- the import
        AprvCabi.randomTrim = 1;
        AprvCabi gr = fresh(jwsConfig);
        s = attempt(() -> gr.verifySignedData(now, jws));
        AprvCabi.randomTrim = 0;
        check("random-get answering the wrong length traps", trapped(s), s);

        // --- isolation
        AprvCabi ia = fresh(none), ib = fresh(none);
        boolean before = ib.verifyReceipt(now, g5).contains("\"verified\":true");
        s = attempt(() -> ia.verifyReceiptEndpoint(2, now, req));
        boolean after = attempt(() -> ib.verifyReceipt(now, g5)).contains("\"verified\":true")
                && attempt(() -> ib.verifyReceipt(now, g5)).contains("\"verified\":true");
        check("isolation: a trap (env 2) in one instance leaves another verifying", trapped(s) && before && after, s);
        record("the trapped instance itself, called again (a host should discard it)", attempt(() -> ia.verifyReceipt(now, g5)));
        System.out.println("summary: " + failed + " failed");
        System.exit(failed);
    }
}
