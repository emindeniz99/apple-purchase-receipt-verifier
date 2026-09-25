package aprvj;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The JVM side of the differential: reads the same JSON-lines requests the
 * ctypes harness sends through the .so, calls {@link Bridge} in this JVM,
 * and prints one JSON line per request: {"id", "code", "json"}.
 *
 * <pre>java -cp bridge.jar:verifier.jar:deps/* aprvj.OracleCli requests.jsonl &gt; jvm.jsonl</pre>
 *
 * Verifiers are built once per distinct (kind, options) pair, as the
 * native harness does.
 */
public final class OracleCli {

    private OracleCli() {}

    public static void main(String[] args) throws Exception {
        ObjectMapper json = new ObjectMapper();
        Map<String, Object> verifiers = new HashMap<String, Object>();
        PrintStream out = new PrintStream(System.out, false, "UTF-8");
        BufferedReader in = new BufferedReader(new InputStreamReader(
                args.length == 0 ? System.in : Files.newInputStream(Paths.get(args[0])), StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.trim().isEmpty()) {
                continue;
            }
            JsonNode request = json.readTree(line);
            String kind = request.get("kind").asText();
            String options = request.path("options").asText(null);
            Bridge.Result result;
            if ("selfcheck".equals(kind)) {
                result = Bridge.selfCheck();
            } else {
                String key = kind + "\u0000" + options;
                Object verifier = verifiers.get(key);
                Bridge.Result constructorFailure = null;
                if (verifier == null) {
                    try {
                        if ("receipt".equals(kind)) {
                            verifier = Bridge.newReceiptVerifier(options);
                        } else if ("jws".equals(kind)) {
                            verifier = Bridge.newJwsVerifier(options);
                        } else if ("endpoint".equals(kind)) {
                            verifier = Bridge.newEndpoint(options);
                        } else {
                            throw new IllegalArgumentException("unknown kind " + kind);
                        }
                        verifiers.put(key, verifier);
                    } catch (Throwable t) {
                        constructorFailure = Bridge.failure(t);
                    }
                }
                byte[] input = Base64.getDecoder().decode(request.path("input").asText(""));
                if (constructorFailure != null) {
                    result = constructorFailure;
                } else if ("receipt".equals(kind)) {
                    byte[] guid = request.hasNonNull("guidHex") ? unhex(request.get("guidHex").asText()) : null;
                    result = Bridge.verifyReceipt(verifier, input, request.path("base64").asBoolean(false), guid);
                } else if ("jws".equals(kind)) {
                    result = Bridge.verifyJws(verifier, new String(input, StandardCharsets.UTF_8), request.path("op").asInt());
                } else {
                    result = Bridge.verifyReceiptJson(verifier, new String(input, StandardCharsets.UTF_8));
                }
            }
            Map<String, Object> row = new LinkedHashMap<String, Object>();
            row.put("id", request.get("id").asText());
            row.put("code", Integer.valueOf(result.code));
            row.put("json", result.json);
            out.println(json.writeValueAsString(row));
        }
        out.flush();
    }

    static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
