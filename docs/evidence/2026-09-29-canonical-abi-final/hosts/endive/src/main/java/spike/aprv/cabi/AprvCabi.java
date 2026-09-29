package spike.aprv.cabi;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import run.endive.runtime.ByteArrayMemory;
import run.endive.runtime.ExportFunction;
import run.endive.runtime.HostFunction;
import run.endive.runtime.ImportValues;
import run.endive.runtime.Instance;
import run.endive.runtime.Memory;
import run.endive.wasm.types.FunctionType;
import run.endive.wasm.types.ValType;

/**
 * Spike only (2026-09-29, round 13). The canonical-ABI aprv module on Endive
 * (build-time compiled, ByteArrayMemory), called by hand: no component
 * runtime, no generated bindings. The lines between the "canonical ABI"
 * markers are all a host needs: one generic lowering helper for the four
 * calls and the one import (scripts/count.sh counts them). A trap surfaces
 * as an Endive exception; the caller discards this instance. One instance
 * per thread.
 */
public final class AprvCabi {
    private static final String IFACE = "aprv:verifier/verify@1.0.0#";
    private final Instance instance;
    static int randomTrim; // test hook (Tests.java): shorten random-get's answer by this many bytes

    // --- canonical ABI (hand-written) begin ---
    private final Memory memory;
    private final ExportFunction realloc;

    public AprvCabi() {
        SecureRandom rng = new SecureRandom();
        // random-get: func(len: u32) -> list<u8>, lowered (len, retptr); the list is
        // allocated in guest memory with the guest's cabi_realloc.
        HostFunction randomGet = new HostFunction("aprv:verifier/host@1.0.0", "random-get",
                FunctionType.of(List.of(ValType.I32, ValType.I32), List.of()), (inst, args) -> {
                    int n = (int) args[0] - randomTrim, retptr = (int) args[1]; // test hook
                    int p = (int) inst.export("cabi_realloc").apply(0, 0, 1, n)[0];
                    byte[] b = new byte[n];
                    rng.nextBytes(b);
                    inst.memory().write(p, b);
                    inst.memory().writeI32(retptr, p);
                    inst.memory().writeI32(retptr + 4, n);
                    return null;
                });
        instance = Instance.builder(CabiModule.load())
                .withMachineFactory(CabiModule::create)
                .withMemoryFactory(ByteArrayMemory::new)
                .withImportValues(ImportValues.builder().addFunction(randomGet).build())
                .build();
        memory = instance.memory();
        realloc = instance.export("cabi_realloc");
    }

    /** Each export's WIT parameters, in order: 'w' u32, 'd' u64, 'b' list<u8>. */
    private static final java.util.Map<String, String> SIGS = java.util.Map.of(
            "init", "b", "verify-receipt", "db", "verify-signed-data", "db", "verify-receipt-endpoint", "wdb");

    /**
     * Lowers WIT values to core arguments, checked against fn's signature: an
     * Integer is a u32 and a Long a u64 (scalars); byte[] or String is a
     * list<u8>, copied into a guest buffer from cabi_realloc (the guest takes
     * ownership) and passed as (ptr, len). A wrong count or type is an error.
     */
    long[] lower(String fn, Object... args) {
        String sig = SIGS.get(fn);
        if (sig == null || sig.length() != args.length) {
            throw new IllegalArgumentException(fn + ": unknown export or wrong argument count");
        }
        long[] out = new long[args.length * 2];
        int k = 0;
        for (int i = 0; i < args.length; i++) {
            Object a = args[i];
            char t = sig.charAt(i);
            if (t == 'w' && a instanceof Integer) {
                out[k++] = Integer.toUnsignedLong((Integer) a);
            } else if (t == 'd' && a instanceof Long) {
                out[k++] = (Long) a;
            } else if (t == 'b' && (a instanceof byte[] || a instanceof String)) {
                byte[] b = a instanceof String ? ((String) a).getBytes(StandardCharsets.UTF_8) : (byte[]) a;
                int p = (int) realloc.apply(0, 0, 1, b.length)[0];
                memory.write(p, b); // the guest takes ownership of this buffer
                out[k++] = Integer.toUnsignedLong(p);
                out[k++] = b.length;
            } else {
                throw new IllegalArgumentException(fn + ": argument " + i + " is "
                        + (a == null ? "null" : a.getClass().getSimpleName()) + ", the WIT type is " + t);
            }
        }
        return java.util.Arrays.copyOf(out, k);
    }

    /** An export whose result is a string: lower, call, lift, post-return. */
    public String call(String fn, Object... args) {
        int rp = (int) instance.export(IFACE + fn).apply(lower(fn, args))[0];
        byte[] out = memory.readBytes(memory.readInt(rp), memory.readInt(rp + 4));
        instance.export("cabi_post_" + IFACE + fn).apply(rp); // frees the result
        return new String(out, StandardCharsets.UTF_8);
    }
    // --- canonical ABI (hand-written) end ---

    Instance instance() {
        return instance;
    }

    public String init(byte[] configJson) {
        return call("init", configJson);
    }

    public String verifyReceipt(long nowMs, byte[] receiptBase64) {
        return call("verify-receipt", nowMs, receiptBase64);
    }

    public String verifySignedData(long nowMs, byte[] jws) {
        return call("verify-signed-data", nowMs, jws);
    }

    /** env: 0 production, 1 sandbox; anything else traps in the guest. */
    public String verifyReceiptEndpoint(int env, long nowMs, byte[] requestJson) {
        return call("verify-receipt-endpoint", env, nowMs, requestJson);
    }
}
