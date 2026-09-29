package spike.aprv.cabi;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import run.endive.wasm.WasmEngineException;

/**
 * Spike only (round 13). Runs a canonical-ABI calls file (py/calls_bytes.py)
 * through AprvCabi: one instance per init config, discarded after a trap.
 * Output rows are in the Node runner's format ({"id","out"}, {"id","trap"}
 * or {"id","map"}). Json is ABI v1's minimal JSON (copied at build time).
 *   java -cp ... spike.aprv.cabi.RunCalls calls.jsonl > out.jsonl
 */
public final class RunCalls {
    private RunCalls() {}

    public static void main(String[] args) throws Exception {
        Map<String, AprvCabi> inst = new HashMap<>();
        long traps = 0, rows = 0, created = 0;
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
                if (c.containsKey("map")) {
                    out.write("{\"id\":" + id + ",\"map\":" + Json.quote((String) c.get("map")) + "}\n");
                    continue;
                }
                String config = (String) c.get("config");
                AprvCabi g = inst.get(config);
                String answer = null;
                if (g == null) {
                    g = new AprvCabi();
                    created++;
                    String ok = g.init(config.getBytes(StandardCharsets.UTF_8));
                    if (ok.equals("{\"ok\":true}")) {
                        inst.put(config, g);
                    } else {
                        answer = ok; // init refused the config: that is the row's answer
                    }
                }
                long now = c.get("now") == null ? System.currentTimeMillis() : (Long) c.get("now");
                byte[] text = Base64.getDecoder().decode((String) c.get("b64"));
                try {
                    if (answer == null) {
                        switch ((String) c.get("fn")) {
                            case "verify-receipt": answer = g.verifyReceipt(now, text); break;
                            case "verify-signed-data": answer = g.verifySignedData(now, text); break;
                            default: answer = g.verifyReceiptEndpoint(((Long) c.get("env")).intValue(), now, text);
                        }
                    }
                    out.write("{\"id\":" + id + ",\"out\":" + Json.quote(answer) + "}\n");
                } catch (WasmEngineException e) {
                    traps++;
                    inst.remove(config);
                    out.write("{\"id\":" + id + ",\"trap\":" + Json.quote(String.valueOf(e.getMessage())) + "}\n");
                }
            }
        }
        System.err.println("{\"host\":\"endive 1.1.0\",\"java\":" + Json.quote(System.getProperty("java.version"))
                + ",\"rows\":" + rows + ",\"traps\":" + traps + ",\"instances\":" + created + "}");
    }
}
