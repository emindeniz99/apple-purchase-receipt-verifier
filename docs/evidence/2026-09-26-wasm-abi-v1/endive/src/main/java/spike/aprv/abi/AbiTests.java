package spike.aprv.abi;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import run.endive.wasm.WasmEngineException;

/**
 * Spike only (ABI v1). The brief's mandatory ABI tests on Endive, the same
 * list as js/abi-tests.mjs. Every trap is caught, the instance discarded,
 * and a fresh instance must then verify g5.
 *   java -cp ... spike.aprv.abi.AbiTests calls-cases.jsonl
 */
public final class AbiTests {
    private static int pass, fail;
    private static byte[] g5, jws;
    private static int jwsOp;

    private AbiTests() {}

    interface Body {
        Object run(AprvAbi i) throws Exception;
    }

    /** kind ("ok", "trap", "error") and value or message. */
    static Object[] attempt(Body f) {
        AprvAbi i = new AprvAbi();
        try {
            return new Object[] {"ok", f.run(i)};
        } catch (WasmEngineException e) {
            return new Object[] {"trap", e.getClass().getSimpleName() + ": " + e.getMessage()};
        } catch (Exception e) {
            return new Object[] {"error", e.getMessage()};
        }
    }

    static void ok(String name, boolean cond, String detail) {
        if (cond) {
            pass++;
        } else {
            fail++;
        }
        System.out.println((cond ? "PASS " : "FAIL ") + name + (detail.isEmpty() ? "" : ": " + detail));
    }

    static void trapsThenRecovers(String name, Body f) {
        Object[] r = attempt(f);
        boolean after = Boolean.TRUE.equals(dec(new AprvAbi().call(AprvAbi.VERIFY_RECEIPT, g5)).get("verified"));
        ok(name, "trap".equals(r[0]) && after, r[0] + " (" + r[1] + "); fresh instance verifies g5: " + after);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> dec(byte[] b) {
        return (Map<String, Object>) Json.parse(new String(b, StandardCharsets.UTF_8));
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static long call(AprvAbi i, long abi, long op, long ptr, long len) {
        return i.export("aprv_call").apply(abi, op, ptr, len)[0];
    }

    static long withHandle(AprvAbi i) {
        long p = i.export("aprv_alloc").apply(4)[0];
        return call(i, 1, AprvAbi.VERIFY_RECEIPT, p, 4);
    }

    /** Key-sorted rendering, for comparing two parsed JSON values. */
    @SuppressWarnings("unchecked")
    static Object canon(Object v) {
        if (v instanceof Map) {
            TreeMap<String, Object> t = new TreeMap<>();
            ((Map<String, Object>) v).forEach((k, x) -> t.put(k, canon(x)));
            return t;
        }
        if (v instanceof java.util.List) {
            java.util.List<Object> l = new java.util.ArrayList<>();
            for (Object x : (java.util.List<Object>) v) {
                l.add(canon(x));
            }
            return l;
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, Map<String, Object>> calls = new HashMap<>();
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            Map<String, Object> c = (Map<String, Object>) Json.parse(line);
            calls.put((String) c.get("id"), c);
        }
        Map<String, Object> g = calls.get("receipt/verify-genuine-sandbox-g5-against-apple-roots");
        Map<String, Object> j = calls.get("transaction/verify-shared-sandbox");
        g5 = Base64.getDecoder().decode((String) g.get("input"));
        jws = Base64.getDecoder().decode((String) j.get("input"));
        jwsOp = ((Long) j.get("op")).intValue();

        ok("aprv_abi_version() == 1", new AprvAbi().export("aprv_abi_version").apply()[0] == 1, "");
        {
            Object[] r = attempt(i -> dec(i.call(AprvAbi.VERIFY_RECEIPT, g5)));
            Map<String, Object> v = (Map<String, Object>) r[1];
            Object bundle = "ok".equals(r[0]) ? ((Map<String, Object>) v.get("payload")).get("bundleId") : null;
            ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", "ok".equals(r[0]) && Boolean.TRUE.equals(v.get("verified"))
                    && "dev.bonzer.weeka.app".equals(bundle), "bundleId " + bundle);
        }
        {
            Object[] r = attempt(i -> dec(i.call(jwsOp, jws)));
            boolean good = false;
            String detail = String.valueOf(r[1]);
            if ("ok".equals(r[0])) {
                Map<String, Object> v = (Map<String, Object>) r[1];
                String raw = (String) v.get("payloadJson");
                good = Boolean.TRUE.equals(v.get("verified")) && canon(Json.parse(raw)).equals(canon(v.get("payload")));
                detail = "payloadJson " + raw.length() + " chars";
            }
            ok("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload", good, detail);
        }
        trapsThenRecovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard", i -> call(i, 0, 0x7fffffffL, 0xfffffff0L, 0x7fffffffL));
        trapsThenRecovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard", i -> call(i, 2, 0x7fffffffL, 0xfffffff0L, 0x7fffffffL));
        {
            Object[] r = attempt(i -> i.call(2, AprvAbi.VERIFY_RECEIPT, g5));
            ok("bridge reports a version mismatch as an ABI error, never verified=false",
                    "error".equals(r[0]) && String.valueOf(r[1]).contains("APRV Wasm ABI mismatch: module=1, caller=2"), String.valueOf(r[1]));
        }
        {
            Object[] r = attempt(i -> {
                long before = i.clockCalls;
                try {
                    call(i, 3, 1, 0, 0);
                } catch (WasmEngineException e) {
                    // the trap
                }
                return i.clockCalls - before;
            });
            ok("a version mismatch runs nothing (no host import called)", "ok".equals(r[0]) && Long.valueOf(0).equals(r[1]), "clock calls during the call: " + r[1]);
        }
        for (long op : new long[] {0, 5, 99, 255, 256, 261, -1}) {
            trapsThenRecovers("unknown operation " + op + " fails hard", i -> {
                long p = i.export("aprv_alloc").apply(4)[0];
                return call(i, 1, op, p, 4);
            });
        }
        trapsThenRecovers("null input pointer with a length fails hard", i -> call(i, 1, AprvAbi.VERIFY_RECEIPT, 0, 10));
        trapsThenRecovers("input beyond linear memory fails hard", i -> call(i, 1, AprvAbi.VERIFY_RECEIPT, i.memoryBytes() - 4, 16));
        trapsThenRecovers("input range that overflows u32 fails hard", i -> call(i, 1, AprvAbi.VERIFY_RECEIPT, 0xfffffff0L, 0x20));
        {
            Object[] r = attempt(i -> dec(i.call(AprvAbi.VERIFY_RECEIPT, new byte[0])));
            Map<String, Object> v = "ok".equals(r[0]) ? (Map<String, Object>) r[1] : Map.of();
            ok("empty input is a verification failure value", Boolean.FALSE.equals(v.get("verified")) && "INVALID_RECEIPT_FORMAT".equals(v.get("reason")), String.valueOf(r[1]));
        }
        {
            Object[] r = attempt(i -> Arrays.asList(i.export("aprv_alloc").apply(0x7fffffffL)[0], i.export("aprv_alloc").apply(0x7ffffff0L)[0],
                    dec(i.call(AprvAbi.VERIFY_RECEIPT, g5)).get("verified")));
            ok("absurd aprv_alloc lengths return 0, and the instance keeps working",
                    "ok".equals(r[0]) && Arrays.asList(0L, 0L, true).equals(r[1]), String.valueOf(r[1]));
        }
        trapsThenRecovers("invalid handle: aprv_result_ptr(0) fails hard", i -> i.export("aprv_result_ptr").apply(0));
        trapsThenRecovers("invalid handle: aprv_result_len(12345) fails hard", i -> i.export("aprv_result_len").apply(12345));
        trapsThenRecovers("invalid handle: aprv_result_free(0) fails hard", i -> i.export("aprv_result_free").apply(0));
        trapsThenRecovers("invalid handle: aprv_result_free(never issued) fails hard", i -> i.export("aprv_result_free").apply(7));
        trapsThenRecovers("double free fails hard", i -> {
            long h = withHandle(i);
            i.export("aprv_result_free").apply(h);
            return i.export("aprv_result_free").apply(h);
        });
        trapsThenRecovers("use after free (result_ptr) fails hard", i -> {
            long h = withHandle(i);
            i.export("aprv_result_free").apply(h);
            return i.export("aprv_result_ptr").apply(h);
        });
        trapsThenRecovers("use after free (result_len) fails hard", i -> {
            long h = withHandle(i);
            i.export("aprv_result_free").apply(h);
            return i.export("aprv_result_len").apply(h);
        });
        {
            Object[] r = attempt(i -> {
                long[] hs = {withHandle(i), withHandle(i), withHandle(i)};
                i.export("aprv_result_free").apply(hs[1]);
                long h4 = withHandle(i);
                return new long[] {hs[0], hs[1], hs[2], h4};
            });
            long[] v = "ok".equals(r[0]) ? (long[]) r[1] : new long[4];
            ok("freed handles are reused and live ones stay valid", "ok".equals(r[0]) && v[3] == v[1], Arrays.toString(v));
        }
        {
            Object[] r = attempt(i -> dec(i.call(AprvAbi.VERIFY_RECEIPT, utf8("not a receipt"))));
            ok("garbage receipt -> verified=false value", "ok".equals(r[0]) && Boolean.FALSE.equals(((Map<String, Object>) r[1]).get("verified")), String.valueOf(r[1]));
        }
        {
            Object[] r = attempt(i -> dec(i.call(AprvAbi.VERIFY_SIGNED_DATA, new byte[] {(byte) 0xff, (byte) 0xfe, 0x2e})));
            Map<String, Object> v = "ok".equals(r[0]) ? (Map<String, Object>) r[1] : Map.of();
            ok("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT", Boolean.FALSE.equals(v.get("verified")) && "INVALID_JWS_FORMAT".equals(v.get("reason")), String.valueOf(r[1]));
        }
        {
            Object[] r = attempt(i -> dec(i.call(AprvAbi.ENDPOINT_SANDBOX, utf8("{\"receipt-data\": "))));
            Map<String, Object> v = "ok".equals(r[0]) ? (Map<String, Object>) r[1] : Map.of();
            ok("malformed endpoint request JSON -> Apple status 21002 value", Long.valueOf(21002).equals(v.get("status")), String.valueOf(r[1]));
        }
        {
            String msg = "";
            try {
                dec(utf8("{\"verified\":tru"));
            } catch (RuntimeException e) {
                msg = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            ok("malformed result JSON is a host decode error (internal failure), not a verdict", !msg.isEmpty(), msg);
        }
        {
            Object[] r = attempt(i -> {
                byte[] a = i.call(AprvAbi.VERIFY_RECEIPT, g5);
                byte[] snap = a.clone();
                for (int n = 0; n < 5; n++) {
                    i.call(AprvAbi.VERIFY_RECEIPT, utf8("x".repeat(n + 1)));
                }
                return Arrays.equals(snap, a);
            });
            ok("a result is a host-owned copy (unchanged after later calls reuse guest memory)", "ok".equals(r[0]) && Boolean.TRUE.equals(r[1]), "");
        }
        {
            Object[] r = attempt(i -> {
                for (int n = 0; n < 200; n++) {
                    i.call(AprvAbi.VERIFY_RECEIPT, g5);
                }
                long m1 = i.memoryBytes();
                for (int n = 0; n < 2000; n++) {
                    i.call(AprvAbi.VERIFY_RECEIPT, g5);
                }
                return new long[] {m1, i.memoryBytes()};
            });
            long[] v = "ok".equals(r[0]) ? (long[]) r[1] : new long[] {0, 1};
            ok("no growth of linear memory over 2,000 more calls", v[0] == v[1], Arrays.toString(v));
        }
        System.out.println("summary: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
