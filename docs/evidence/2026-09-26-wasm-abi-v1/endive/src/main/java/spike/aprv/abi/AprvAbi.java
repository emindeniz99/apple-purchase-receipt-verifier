package spike.aprv.abi;

import java.security.SecureRandom;
import java.util.List;
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
 * Spike only. The Java bridge for ABI v1 on Endive (build-time compiled,
 * ByteArrayMemory). Lifecycle of {@link #call}: alloc, copy input,
 * aprv_call, bounds-check the result range, copy the result out,
 * aprv_result_free, dealloc the input. No guest pointer leaves it. A trap
 * surfaces as an Endive exception and the caller must discard this
 * instance. One instance per thread.
 */
public final class AprvAbi {
    public static final int ABI_VERSION = 1;
    public static final int VERIFY_RECEIPT = 1;
    public static final int VERIFY_SIGNED_DATA = 2;
    public static final int ENDPOINT_PRODUCTION = 3;
    public static final int ENDPOINT_SANDBOX = 4;

    /** The module and this bridge disagree on the ABI version. */
    public static final class AbiMismatchException extends RuntimeException {
        AbiMismatchException(int module, int caller) {
            super("APRV Wasm ABI mismatch: module=" + module + ", caller=" + caller);
        }
    }

    private final Instance instance;
    private final Memory memory;
    private final ExportFunction alloc, dealloc, call, resultPtr, resultLen, resultFree, abiVersion;
    private final int moduleVersion;
    public long clockCalls, randomCalls;

    public AprvAbi() {
        SecureRandom rng = new SecureRandom();
        HostFunction clock = new HostFunction("aprv", "clock_now_ms", FunctionType.of(List.of(), List.of(ValType.F64)),
                (inst, args) -> {
                    clockCalls++;
                    return new long[] {Value.doubleToLong((double) System.currentTimeMillis())};
                });
        HostFunction random = new HostFunction("aprv", "random_get",
                FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)), (inst, args) -> {
                    randomCalls++;
                    long p = Integer.toUnsignedLong((int) args[0]), n = Integer.toUnsignedLong((int) args[1]);
                    if (p + n > (long) inst.memory().pages() * Memory.PAGE_SIZE) {
                        throw new TrapException("aprv.random_get out of bounds");
                    }
                    byte[] b = new byte[(int) n];
                    rng.nextBytes(b);
                    inst.memory().write((int) p, b);
                    return new long[] {0};
                });
        instance = Instance.builder(AbiModule.load())
                .withMachineFactory(AbiModule::create)
                .withMemoryFactory(ByteArrayMemory::new)
                .withImportValues(ImportValues.builder().addFunction(clock, random).build())
                .build();
        memory = instance.memory();
        alloc = instance.export("aprv_alloc");
        dealloc = instance.export("aprv_dealloc");
        call = instance.export("aprv_call");
        resultPtr = instance.export("aprv_result_ptr");
        resultLen = instance.export("aprv_result_len");
        resultFree = instance.export("aprv_result_free");
        abiVersion = instance.export("aprv_abi_version");
        instance.export("_initialize").apply();
        moduleVersion = (int) abiVersion.apply()[0];
        if (moduleVersion != ABI_VERSION) {
            throw new AbiMismatchException(moduleVersion, ABI_VERSION);
        }
    }

    public ExportFunction export(String name) {
        return instance.export(name);
    }

    public Memory memory() {
        return memory;
    }

    public long memoryBytes() {
        return (long) memory.pages() * Memory.PAGE_SIZE;
    }

    public byte[] call(int operation, byte[] input) {
        return call(ABI_VERSION, operation, input);
    }

    /** The whole lifecycle; {@code abi} other than 1 only for the ABI tests. */
    public byte[] call(int abi, int operation, byte[] input) {
        int len = input.length;
        int in = (int) alloc.apply(len)[0];
        if (in == 0) {
            throw new IllegalStateException("aprv_alloc(" + len + ") failed");
        }
        // After a trap the instance is discarded, so nothing more runs in it.
        boolean done = false;
        try {
            memory.write(in, input);
            int h;
            try {
                h = (int) call.apply(abi, operation, in, len)[0];
            } catch (RuntimeException e) {
                if (abi != moduleVersion) {
                    throw new AbiMismatchException(moduleVersion, abi);
                }
                throw e;
            }
            long p = Integer.toUnsignedLong((int) resultPtr.apply(h)[0]);
            long n = Integer.toUnsignedLong((int) resultLen.apply(h)[0]);
            if (p + n > memoryBytes()) {
                throw new IllegalStateException("result out of bounds");
            }
            byte[] out = memory.readBytes((int) p, (int) n);
            resultFree.apply(h);
            done = true;
            return out;
        } finally {
            if (done) {
                dealloc.apply(in, len);
            }
        }
    }
}
