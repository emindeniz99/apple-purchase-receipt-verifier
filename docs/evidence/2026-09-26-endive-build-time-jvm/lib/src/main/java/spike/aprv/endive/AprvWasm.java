package spike.aprv.endive;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import run.endive.runtime.ByteArrayMemory;
import run.endive.runtime.ExportFunction;
import run.endive.runtime.HostFunction;
import run.endive.runtime.ImportValues;
import run.endive.runtime.Instance;
import run.endive.runtime.Memory;
import run.endive.runtime.TrapException;
import run.endive.wasm.types.FunctionType;
import run.endive.wasm.types.ValType;
import run.endive.wasm.types.Value;

/**
 * Spike only. One instance of the Route C {@code aprv.wasm} (the unchanged C
 * ABI of {@code rust/ffi}, compiled for wasm32-wasip1 against OpenSSL 4.0.2)
 * running on the classes Endive's build-time compiler generated from it
 * ({@link AprvModule}).
 *
 * <p>The module imports exactly two functions, and this class provides
 * exactly those two; there is no WASI, no filesystem, no environment, no
 * network:
 *
 * <ul>
 *   <li>{@code aprv.clock_now_ms: () -> f64}: wall-clock milliseconds, from
 *       {@link System#currentTimeMillis()} (or a supplied clock);
 *   <li>{@code aprv.random_get: (ptr i32, len i32) -> i32}: fills guest memory
 *       from {@link SecureRandom} and answers 0.
 * </ul>
 *
 * <p>This is a thin transport, not an API: callers drive the C ABI
 * ({@code aprv_*} exports) through {@link #call}, {@link #put} and
 * {@link #takeString}, exactly as the JavaScript driver of the wasm
 * bake-off does. An instance is single-threaded (Endive's {@code Instance}
 * is not thread-safe); use one per thread.
 */
public final class AprvWasm {

    private final Instance instance;
    private final Memory memory;
    private final Map<String, ExportFunction> exports = new HashMap<>();
    private final AtomicLong clockCalls = new AtomicLong();
    private final AtomicLong randomCalls = new AtomicLong();

    /** A new instance with the system clock and a default {@link SecureRandom}. */
    public static AprvWasm create() {
        return new AprvWasm(System::currentTimeMillis, new SecureRandom());
    }

    public AprvWasm(LongSupplier clockMillis, SecureRandom random) {
        HostFunction clock =
                new HostFunction(
                        "aprv",
                        "clock_now_ms",
                        FunctionType.of(List.of(), List.of(ValType.F64)),
                        (inst, args) -> {
                            clockCalls.incrementAndGet();
                            return new long[] {Value.doubleToLong((double) clockMillis.getAsLong())};
                        });
        HostFunction randomGet =
                new HostFunction(
                        "aprv",
                        "random_get",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> {
                            randomCalls.incrementAndGet();
                            int ptr = (int) args[0];
                            int len = (int) args[1];
                            Memory mem = inst.memory();
                            // Guest pointers are checked before the host touches memory.
                            long end = Integer.toUnsignedLong(ptr) + Integer.toUnsignedLong(len);
                            if (end > (long) mem.pages() * Memory.PAGE_SIZE) {
                                throw new TrapException("aprv.random_get out of bounds");
                            }
                            byte[] bytes = new byte[len];
                            random.nextBytes(bytes);
                            mem.write(ptr, bytes);
                            return new long[] {0};
                        });
        Instance.Builder builder =
                Instance.builder(AprvModule.load())
                        .withMachineFactory(AprvModule::create)
                        .withImportValues(ImportValues.builder().addFunction(clock, randomGet).build());
        // Endive's default linear memory is ByteBufferMemory. Its docs recommend
        // ByteArrayMemory "for recent OpenJDK systems"; the spike measures both
        // (-Dspike.aprv.memory=bytearray).
        if ("bytearray".equals(System.getProperty("spike.aprv.memory"))) {
            builder = builder.withMemoryFactory(ByteArrayMemory::new);
        }
        this.instance = builder.build();
        this.memory = instance.memory();
        // A WASI reactor: constructors first, then the ABI's own init.
        call("_initialize");
        call("aprv_init");
    }

    /** Calls an export and returns its first result (0 for none). */
    public long call(String name, long... args) {
        ExportFunction f = exports.computeIfAbsent(name, instance::export);
        long[] r = f.apply(args);
        return r == null || r.length == 0 ? 0 : r[0];
    }

    public int alloc(int len) {
        return (int) call("aprv_alloc", len);
    }

    public void dealloc(int ptr, int len) {
        call("aprv_dealloc", ptr, len);
    }

    /** Copies {@code data} (plus a NUL when asked) into a fresh guest buffer. */
    public int put(byte[] data, boolean nul) {
        int len = Math.max(data.length + (nul ? 1 : 0), 1);
        int p = alloc(len);
        memory.write(p, data);
        if (nul) {
            memory.writeByte(p + data.length, (byte) 0);
        }
        return p;
    }

    /** Reads a NUL-terminated UTF-8 string the ABI returned and frees it. */
    public String takeString(int ptr) {
        if (ptr == 0) {
            return "";
        }
        int end = ptr;
        while (memory.read(end) != 0) {
            end++;
        }
        String s = new String(memory.readBytes(ptr, end - ptr), StandardCharsets.UTF_8);
        call("aprv_string_free", ptr);
        return s;
    }

    public Memory memory() {
        return memory;
    }

    /** Bytes of guest linear memory right now. */
    public long memoryBytes() {
        return (long) memory.pages() * Memory.PAGE_SIZE;
    }

    public long clockCalls() {
        return clockCalls.get();
    }

    public long randomCalls() {
        return randomCalls.get();
    }
}
