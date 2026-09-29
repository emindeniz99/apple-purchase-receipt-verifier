package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.endive.AprvModule;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import run.endive.runtime.ByteArrayMemory;
import run.endive.runtime.ExportFunction;
import run.endive.runtime.HostFunction;
import run.endive.runtime.ImportValues;
import run.endive.runtime.Instance;
import run.endive.runtime.Memory;
import run.endive.wasm.types.ExportSection;
import run.endive.wasm.types.FunctionType;
import run.endive.wasm.types.ValType;

/**
 * One instance of {@code aprv.wasm} on the classes Endive compiled from it
 * at build time ({@link AprvModule}; no interpreter, no compiler at run
 * time), with {@link ByteArrayMemory}, called through the canonical ABI by
 * hand as the WIT file declares it. Java 11 bytecode, loaded only when the
 * Endive engine is chosen.
 *
 * <p>The instance gets exactly one import, {@code random-get}, answered from
 * {@link SecureRandom}: no WASI, no filesystem, no clock, no environment.
 * Not thread-safe (Endive's {@code Instance} is not): {@link GuestPool}
 * gives it one call at a time. Any exception out of a call means the
 * instance is discarded.</p>
 */
final class EndiveGuest implements Guest {

    /** The interface the four exports belong to; its version is the ABI version. */
    static final String IFACE = "aprv:verifier/verify@1.0.0";

    /** Each export's WIT parameters, in order: 'w' u32, 'd' u64, 'b' list&lt;u8&gt;. */
    static final Map<String, String> SIGNATURES =
            Map.of("init", "b", "verify-receipt", "db", "verify-signed-data", "db", "verify-receipt-endpoint", "wdb");

    private final Instance instance;
    private final Memory memory;
    private final ExportFunction realloc;

    /** Shortens random-get's answer by this many bytes; the ABI tests' misuse hook, always 0 otherwise. */
    static volatile int randomTrimForTests;

    /**
     * @throws GuestFailure if the module lacks an export this class binds, or
     *     the instance cannot be created or initialised
     */
    EndiveGuest(SecureRandom random) {
        // --- canonical ABI (hand-written) begin ---
        // random-get: func(len: u32) -> list<u8>, lowered (len, retptr): the list
        // goes into a guest buffer from cabi_realloc, and (ptr, len) into the
        // return area. Endive checks every guest address it writes.
        HostFunction randomGet = new HostFunction(
                "aprv:verifier/host@1.0.0",
                "random-get",
                FunctionType.of(List.of(ValType.I32, ValType.I32), List.of()),
                (inst, args) -> {
                    int n = (int) args[0] - randomTrimForTests;
                    int retptr = (int) args[1];
                    byte[] bytes = new byte[n];
                    random.nextBytes(bytes);
                    int p = (int) inst.export("cabi_realloc").apply(0, 0, 1, n)[0];
                    inst.memory().write(p, bytes);
                    inst.memory().writeI32(retptr, p);
                    inst.memory().writeI32(retptr + 4, n);
                    return null;
                });
        // --- canonical ABI (hand-written) end ---
        abi(AprvModule.load().exportSection());
        try {
            instance = Instance.builder(AprvModule.load())
                    .withMachineFactory(AprvModule::create)
                    .withMemoryFactory(ByteArrayMemory::new)
                    .withImportValues(
                            ImportValues.builder().addFunction(randomGet).build())
                    .build();
            memory = instance.memory();
            realloc = instance.export("cabi_realloc");
            // A WASI reactor: its constructors run once, before any other export.
            instance.export("_initialize").apply();
        } catch (RuntimeException e) {
            throw new GuestFailure("the verifier module could not be instantiated: " + e, e);
        }
    }

    /**
     * The ABI check: every export this class calls, by its versioned name. A
     * module built for another ABI version has none of them, and fails here
     * rather than being misread.
     */
    private static void abi(ExportSection exports) {
        Set<String> names = new TreeSet<>();
        for (int i = 0; i < exports.exportCount(); i++) {
            names.add(exports.getExport(i).name());
        }
        List<String> missing = new ArrayList<>();
        for (String required : new String[] {"memory", "cabi_realloc", "_initialize"}) {
            if (!names.contains(required)) {
                missing.add(required);
            }
        }
        for (String fn : SIGNATURES.keySet()) {
            for (String name : new String[] {IFACE + "#" + fn, "cabi_post_" + IFACE + "#" + fn}) {
                if (!names.contains(name)) {
                    missing.add(name);
                }
            }
        }
        if (!missing.isEmpty()) {
            throw new GuestFailure("ABI mismatch: this library binds " + IFACE + " and the module lacks " + missing
                    + "; it exports " + names);
        }
    }

    // --- canonical ABI (hand-written) begin ---
    /**
     * Lowers WIT values to core arguments, checked against the export's
     * signature: an Integer is a u32 and a Long a u64; a byte[] is a
     * list&lt;u8&gt;, copied into a guest buffer from cabi_realloc (the guest
     * takes ownership) and passed as (ptr, len). A wrong count or type is an
     * error before any call.
     */
    long[] lower(String fn, Object... args) {
        String signature = SIGNATURES.get(fn);
        if (signature == null || signature.length() != args.length) {
            throw new IllegalArgumentException(fn + ": unknown export or wrong argument count");
        }
        long[] out = new long[args.length * 2];
        int k = 0;
        for (int i = 0; i < args.length; i++) {
            Object a = args[i];
            char t = signature.charAt(i);
            if (t == 'w' && a instanceof Integer) {
                out[k++] = Integer.toUnsignedLong((Integer) a);
            } else if (t == 'd' && a instanceof Long) {
                out[k++] = (Long) a;
            } else if (t == 'b' && a instanceof byte[]) {
                byte[] b = (byte[]) a;
                int p = (int) realloc.apply(0, 0, 1, b.length)[0];
                memory.write(p, b);
                out[k++] = Integer.toUnsignedLong(p);
                out[k++] = b.length;
            } else {
                throw new IllegalArgumentException(fn + ": argument " + i + " is "
                        + (a == null ? "null" : a.getClass().getSimpleName()) + ", the WIT type is " + t);
            }
        }
        return Arrays.copyOf(out, k);
    }

    /**
     * An export whose result is a string: lower, call, read the return area
     * ((ptr, len) as little-endian u32) with both checked against the memory
     * size, copy the result out, post-return (which frees it), and decode
     * UTF-8 strictly. No guest pointer leaves this method.
     */
    String call(String fn, Object... args) {
        long[] lowered = lower(fn, args);
        int retptr = (int) instance.export(IFACE + "#" + fn).apply(lowered)[0];
        long size = (long) memory.pages() * Memory.PAGE_SIZE;
        long area = Integer.toUnsignedLong(retptr);
        if (area + 8 > size) {
            throw new GuestFailure(fn + ": the return area lies outside linear memory");
        }
        long ptr = Integer.toUnsignedLong(memory.readInt(retptr));
        long len = Integer.toUnsignedLong(memory.readInt(retptr + 4));
        if (ptr + len > size) {
            throw new GuestFailure(fn + ": the result lies outside linear memory");
        }
        byte[] out = memory.readBytes((int) ptr, (int) len);
        instance.export("cabi_post_" + IFACE + "#" + fn).apply(retptr);
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .decode(ByteBuffer.wrap(out))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new GuestFailure(fn + ": the result is not UTF-8", e);
        }
    }
    // --- canonical ABI (hand-written) end ---

    /** The Endive instance, for the ABI tests' misuse cases. */
    Instance instance() {
        return instance;
    }

    @Override
    public String init(byte[] configJson) {
        return call("init", (Object) configJson);
    }

    @Override
    public String verifyReceipt(long nowMs, byte[] receiptBase64) {
        return call("verify-receipt", nowMs, receiptBase64);
    }

    @Override
    public String verifySignedData(long nowMs, byte[] jws) {
        return call("verify-signed-data", nowMs, jws);
    }

    @Override
    public String verifyReceiptEndpoint(int env, long nowMs, byte[] requestJson) {
        return call("verify-receipt-endpoint", env, nowMs, requestJson);
    }
}
