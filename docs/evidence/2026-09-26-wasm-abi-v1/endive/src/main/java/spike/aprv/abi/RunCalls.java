package spike.aprv.abi;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import run.endive.wasm.WasmEngineException;

/**
 * Spike only (ABI v1). The Java twin of js/run-calls.mjs: runs calls.jsonl
 * (py/abi_calls.py) through the module on Endive, one instance, discarded
 * and replaced after a trap. Output rows are byte-identical in format to
 * the Node runner's ({"id","out"}, {"id","trap"} or {"id","map"}).
 *   java -cp ... spike.aprv.abi.RunCalls calls.jsonl > out.jsonl
 */
public final class RunCalls {
    private RunCalls() {}

    public static void main(String[] args) throws Exception {
        AprvAbi abi = new AprvAbi();
        long traps = 0, instances = 1, rows = 0, clock = 0, random = 0;
        try (BufferedReader in = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8);
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), 1 << 20)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> c = (Map<String, Object>) Json.parse(line);
                String id = Json.quote((String) c.get("id"));
                rows++;
                if (!c.containsKey("op")) {
                    out.write("{\"id\":" + id + ",\"map\":" + Json.quote((String) c.get("map")) + "}\n");
                    continue;
                }
                int op = ((Long) c.get("op")).intValue();
                byte[] input = Base64.getDecoder().decode((String) c.get("input"));
                try {
                    byte[] result = abi.call(op, input);
                    out.write("{\"id\":" + id + ",\"out\":" + Json.quote(new String(result, StandardCharsets.UTF_8)) + "}\n");
                } catch (WasmEngineException | AprvAbi.AbiMismatchException e) {
                    traps++;
                    clock += abi.clockCalls;
                    random += abi.randomCalls;
                    abi = new AprvAbi();
                    instances++;
                    out.write("{\"id\":" + id + ",\"trap\":" + Json.quote(String.valueOf(e.getMessage())) + "}\n");
                }
            }
        }
        clock += abi.clockCalls;
        random += abi.randomCalls;
        System.err.println("{\"host\":\"endive\",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"calls\":{\"aprv.clock_now_ms\":" + clock + ",\"aprv.random_get\":" + random + "},\"traps\":" + traps
                + ",\"instances\":" + instances + ",\"rows\":" + rows + "}");
    }
}
