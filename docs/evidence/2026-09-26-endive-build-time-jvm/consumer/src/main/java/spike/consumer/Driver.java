package spike.consumer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import run.endive.wasm.WasmEngineException;
import spike.aprv.endive.AprvWasm;

/**
 * Spike only. A line-for-line port of the wasm bake-off's js/driver.mjs:
 * request-corpus rows through the unchanged C ABI inside one instance of
 * the build-time-compiled module. Same row format ({"id","code","json"}),
 * so the bake-off's py/same.py compares the rows unchanged.
 *
 * <p>A trap (a Rust panic under panic=abort, an out-of-bounds access, an
 * {@code unreachable}) becomes code "TRAP"; the instance is dropped and a
 * fresh one serves the next row, as in the JavaScript driver.
 */
final class Driver {
    private static final Map<String, Integer> ENV_BITS =
            Map.of("Production", 1, "Sandbox", 2, "Xcode", 4, "LocalTesting", 8);
    private static final String[] JWS_CALLS = {
        "aprv_verify_transaction", "aprv_verify_app_transaction", "aprv_verify_raw"
    };

    private final Supplier<AprvWasm> factory;
    private AprvWasm w;
    private Map<String, Long> handles = new HashMap<>();
    private final List<int[]> pending = new ArrayList<>();
    long instancesCreated;

    Driver(Supplier<AprvWasm> factory) {
        this.factory = factory;
        fresh();
    }

    AprvWasm wasm() {
        return w;
    }

    private void fresh() {
        w = factory.get();
        instancesCreated++;
        handles = new HashMap<>();
        pending.clear();
    }

    private int alloc(int len) {
        int p = w.alloc(len);
        pending.add(new int[] {p, len});
        return p;
    }

    private void release() {
        for (int[] a : pending) {
            w.dealloc(a[0], a[1]);
        }
        pending.clear();
    }

    private int put(byte[] data, boolean nul) {
        int len = Math.max(data.length + (nul ? 1 : 0), 1);
        int p = w.put(data, nul);
        pending.add(new int[] {p, len});
        return p;
    }

    private static boolean hasNul(byte[] b) {
        for (byte x : b) {
            if (x == 0) {
                return true;
            }
        }
        return false;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private long handleFor(Map<String, Object> r, Map<String, Object> opts) {
        String kind = (String) r.get("kind");
        String key = kind + '\0' + r.get("options");
        Long cached = handles.get(key);
        if (cached != null) {
            return cached;
        }
        int ders = 0, lens = 0, count = 0;
        List<Object> roots = (List<Object>) opts.get("roots");
        if (roots != null) {
            count = roots.size();
            ders = alloc(4 * Math.max(count, 1));
            lens = alloc(4 * Math.max(count, 1));
            for (int i = 0; i < count; i++) {
                byte[] b = Base64.getDecoder().decode((String) roots.get(i));
                int p = put(b, false);
                w.memory().writeI32(ders + 4 * i, p);
                w.memory().writeI32(lens + 4 * i, b.length);
            }
        }
        String bundleId = (String) opts.get("bundleId");
        byte[] bundle = (bundleId == null ? "" : bundleId).getBytes(StandardCharsets.UTF_8);
        if (kind.equals("jws") && bundle.length == 0) {
            bundle = "conformance.unset.bundle.id".getBytes(StandardCharsets.UTF_8);
        }
        long h;
        if (kind.equals("receipt")) {
            if (bundleId == null) {
                h = 0;
            } else {
                int bp = put(bundle, true);
                h = roots == null
                        ? w.call("aprv_verifier_new_receipt", bp)
                        : w.call("aprv_verifier_new_receipt_with_roots", bp, ders, lens, count);
            }
        } else if (kind.equals("jws")) {
            int mask = 0;
            List<Object> envs = (List<Object>) opts.get("acceptedEnvironments");
            if (envs != null) {
                for (Object n : envs) {
                    mask |= ENV_BITS.getOrDefault((String) n, 0);
                }
            }
            Object app = opts.get("appAppleId");
            long appId = app == null ? 0 : ((Number) app).longValue();
            int bp = put(bundle, true);
            h = roots == null
                    ? w.call("aprv_verifier_new_jws", bp, mask, appId)
                    : w.call("aprv_verifier_new_jws_with_roots", bp, mask, appId, ders, lens, count);
        } else {
            Object envName = opts.get("environment");
            int env = envName == null ? 0 : ENV_BITS.getOrDefault((String) envName, 0);
            int clock = 0;
            Object now = opts.get("nowMillis");
            if (now != null) {
                clock = alloc(8);
                w.memory().writeLong(clock, ((Number) now).longValue());
            }
            h = w.call("aprv_endpoint_new_with_roots_and_clock", env, ders, lens, count, clock);
        }
        handles.put(key, h);
        return h;
    }

    @SuppressWarnings("unchecked")
    private String runRow(Map<String, Object> r) {
        String id = (String) r.get("id");
        String kind = (String) r.get("kind");
        Map<String, Object> opts = (Map<String, Object>) Json.parse((String) r.get("options"));
        byte[] data = Base64.getDecoder().decode((String) r.get("input"));
        long h = handleFor(r, opts);
        if (h == 0) {
            return row(id, "\"CTOR_REFUSED\"", null);
        }
        if (kind.equals("endpoint")) {
            if (hasNul(data)) {
                return row(id, "\"NUL_IN_BODY\"", null);
            }
            int out = alloc(4);
            w.memory().writeI32(out, 0);
            long st = w.call("aprv_verify_receipt_endpoint_json", h, put(data, true), out);
            String json = w.takeString(w.memory().readInt(out));
            return row(id, st == 0 ? "null" : Long.toString((int) st), json);
        }
        int res = alloc(8);
        w.memory().writeI32(res, 0);
        w.memory().writeI32(res + 4, 0);
        if (kind.equals("jws")) {
            if (hasNul(data)) {
                return row(id, "\"NUL_IN_INPUT\"", null);
            }
            int op = ((Number) r.get("op")).intValue();
            w.call(JWS_CALLS[op], h, put(data, true), res);
        } else {
            Object gh = r.get("guidHex");
            byte[] guid = gh == null ? null : hex((String) gh);
            if (Boolean.TRUE.equals(r.get("base64"))) {
                if (hasNul(data)) {
                    return row(id, "\"NUL_IN_INPUT\"", null);
                }
                if (guid != null) {
                    w.call("aprv_verify_receipt_base64_with_device_guid", h, put(data, true), put(guid, false), guid.length, res);
                } else {
                    w.call("aprv_verify_receipt_base64", h, put(data, true), res);
                }
            } else if (guid != null) {
                w.call("aprv_verify_receipt_der_with_device_guid", h, put(data, false), data.length, put(guid, false), guid.length, res);
            } else {
                w.call("aprv_verify_receipt_der", h, put(data, false), data.length, res);
            }
        }
        int code = w.memory().readInt(res);
        String json = w.takeString(w.memory().readInt(res + 4));
        return row(id, Integer.toString(code), json);
    }

    private static String row(String id, String code, String json) {
        return "{\"id\":" + Json.quote(id) + ",\"code\":" + code + ",\"json\":"
                + (json == null ? "null" : Json.quote(json)) + "}";
    }

    /** One row; a trap becomes a TRAP row and a fresh instance. */
    String run(Map<String, Object> r) {
        try {
            String row = runRow(r);
            release();
            return row;
        } catch (WasmEngineException | StackOverflowError e) {
            fresh();
            return "{\"id\":" + Json.quote((String) r.get("id")) + ",\"code\":\"TRAP\",\"json\":null,\"trap\":"
                    + Json.quote(e.getClass().getSimpleName() + ": " + e.getMessage()) + "}";
        }
    }

    /** Hot loop for timing; no trap handling. */
    String runSync(Map<String, Object> r) {
        String row = runRow(r);
        release();
        return row;
    }
}
