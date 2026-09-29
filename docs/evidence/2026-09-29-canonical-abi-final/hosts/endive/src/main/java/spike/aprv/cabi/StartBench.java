package spike.aprv.cabi;

import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import run.endive.runtime.ByteArrayMemory;
import run.endive.runtime.ExportFunction;
import run.endive.runtime.HostFunction;
import run.endive.runtime.ImportValues;
import run.endive.runtime.Instance;
import run.endive.wasm.types.FunctionType;
import run.endive.wasm.types.ValType;
import run.endive.wasm.types.Value;

/**
 * Spike only (2026-09-29, round 13). Start-up of one fresh JVM on Endive:
 * the ABI v1 module (V1Module, ABI v1's call lifecycle, as ABI v1's
 * AprvAbi.java) or the canonical-ABI module (AprvCabi, init with the
 * built-in roots). Prints the JVM's uptime at main, the instantiate time,
 * the first and second g5 verify, and the uptime at the first result.
 * scripts/endive.sh startup runs it RUNS times per module, interleaved.
 *   java -cp ... spike.aprv.cabi.StartBench v1|cabi CASES.jsonl
 */
public final class StartBench {
    private static double ms(long ns) {
        return ns / 1e6;
    }

    /** ABI v1: aprv_alloc, aprv_call(1, op, ptr, len), aprv_result_ptr/len/free, aprv_dealloc. */
    private static String v1Call(Instance inst, int op, byte[] in) {
        int p = (int) inst.export("aprv_alloc").apply(in.length)[0];
        inst.memory().write(p, in);
        long h = inst.export("aprv_call").apply(1, op, p, in.length)[0];
        byte[] out = inst.memory().readBytes((int) inst.export("aprv_result_ptr").apply(h)[0],
                (int) inst.export("aprv_result_len").apply(h)[0]);
        inst.export("aprv_result_free").apply(h);
        inst.export("aprv_dealloc").apply(p, in.length);
        return new String(out, StandardCharsets.UTF_8);
    }

    private static Instance v1Instance() {
        SecureRandom rng = new SecureRandom();
        HostFunction clock = new HostFunction("aprv", "clock_now_ms", FunctionType.of(List.of(), List.of(ValType.F64)),
                (inst, args) -> new long[] {Value.doubleToLong((double) System.currentTimeMillis())});
        HostFunction random = new HostFunction("aprv", "random_get",
                FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)), (inst, args) -> {
                    byte[] b = new byte[(int) args[1]];
                    rng.nextBytes(b);
                    inst.memory().write((int) args[0], b);
                    return new long[] {0};
                });
        Instance inst = Instance.builder(V1Module.load())
                .withMachineFactory(V1Module::create)
                .withMemoryFactory(ByteArrayMemory::new)
                .withImportValues(ImportValues.builder().addFunction(clock, random).build())
                .build();
        inst.export("_initialize").apply();
        return inst;
    }

    public static void main(String[] args) throws Exception {
        long atMain = ManagementFactory.getRuntimeMXBean().getUptime();
        byte[] g5 = null;
        for (String l : Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            if (l.contains("\"receipt/verify-genuine-sandbox-g5-against-apple-roots\"")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> r = (Map<String, Object>) Json.parse(l);
                g5 = Base64.getDecoder().decode((String) r.get("b64"));
            }
        }
        final byte[] in = g5;
        long t0 = System.nanoTime();
        String first, second;
        long t1, t2, atFirst;
        if (args[0].equals("v1")) {
            Instance inst = v1Instance();
            t1 = System.nanoTime();
            first = v1Call(inst, 1, in);
            t2 = System.nanoTime();
            atFirst = ManagementFactory.getRuntimeMXBean().getUptime();
            second = v1Call(inst, 1, in);
        } else {
            AprvCabi g = new AprvCabi();
            g.init(new byte[0]);
            t1 = System.nanoTime();
            first = g.verifyReceipt(System.currentTimeMillis(), in);
            t2 = System.nanoTime();
            atFirst = ManagementFactory.getRuntimeMXBean().getUptime();
            second = g.verifyReceipt(System.currentTimeMillis(), in);
        }
        long t3 = System.nanoTime();
        if (!first.contains("\"verified\":true") || !second.contains("\"verified\":true")) {
            throw new IllegalStateException(first);
        }
        System.out.printf("{\"module\":\"%s\",\"uptime_at_main_ms\":%d,\"instantiate_and_init_ms\":%.1f,\"first_g5_ms\":%.1f,\"second_g5_ms\":%.1f,\"uptime_at_first_result_ms\":%d}%n",
                args[0].equals("v1") ? "ABI v1" : "canonical ABI", atMain, ms(t1 - t0), ms(t2 - t1), ms(t3 - t2), atFirst);
    }
}
