package ch;

import com.dylibso.chicory.compiler.MachineFactoryCompiler;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Bench {
    public static void main(String[] a) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get(a[0])), StandardCharsets.US_ASCII).replaceAll("\\s", "");
        WasmModule m = Parser.parse(Bench.class.getResourceAsStream("/aprv_wasi.wasm"));
        WasiPreview1 wasi = WasiPreview1.builder().withOptions(WasiOptions.builder().build()).build();
        long t0 = System.nanoTime();
        Instance.Builder b = Instance.builder(m).withImportValues(ImportValues.builder().addFunction(wasi.toHostFunctions()).build());
        if (a.length > 1 && a[1].equals("aot")) b = b.withMachineFactory(MachineFactoryCompiler::compile);
        Instance inst = b.build();
        System.out.println("mode=" + (a.length > 1 ? a[1] : "interpreter") + " instantiate ms=" + (System.nanoTime() - t0) / 1_000_000);
        ExportFunction alloc = inst.export("aprv_alloc"), free = inst.export("aprv_dealloc"), verify = inst.export("aprv_verify_receipt_b64");
        byte[] bid = "dev.bonzer.weeka.app".getBytes(StandardCharsets.UTF_8), rec = b64.getBytes(StandardCharsets.US_ASCII);
        int n = a.length > 1 && a[1].equals("aot") ? 300 : 5;
        String out = null;
        for (int round = 0; round < 2; round++) {
            long t = System.nanoTime();
            for (int i = 0; i < n; i++) {
                int bp = (int) alloc.apply(bid.length)[0]; inst.memory().write(bp, bid);
                int rp = (int) alloc.apply(rec.length)[0]; inst.memory().write(rp, rec);
                long r = verify.apply(bp, bid.length, rp, rec.length)[0];
                int p = (int) (r >>> 32), l = (int) r;
                out = inst.memory().readString(p, l);
                free.apply(p, l); free.apply(bp, bid.length); free.apply(rp, rec.length);
            }
            System.out.println((round == 0 ? "warmup " : "measured ") + (System.nanoTime() - t) / n / 1000 + " us/op -> " + out);
        }
    }
}
