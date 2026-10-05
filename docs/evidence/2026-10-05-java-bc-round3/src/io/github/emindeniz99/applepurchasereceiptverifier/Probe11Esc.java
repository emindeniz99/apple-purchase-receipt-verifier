package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Probe11: JWS header whose x5c entries / alg use legal JSON escapes (\/ \u002b \u0045). */
public class Probe11Esc {
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        TestPki pki = TestPki.jws();
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        String payload = "{\"signedDate\":" + System.currentTimeMillis() + ",\"environment\":\"Sandbox\"}";
        List<String> x5c = pki.x5c();
        int slashes = 0; for (String s : x5c) for (char c : s.toCharArray()) if (c == '/') slashes++;
        System.out.println("slashes in x5c: " + slashes + " plus signs: " + x5c.get(0).chars().filter(c -> c == '+').count());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("h0-plain", "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", x5c) + "\"]}");
        List<String> esc = new ArrayList<>(); for (String s : x5c) esc.add(s.replace("/", "\\/"));
        headers.put("h1-slash-escaped", "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", esc) + "\"]}");
        List<String> esc2 = new ArrayList<>(); for (String s : x5c) esc2.add(s.replace("+", "\\u002b"));
        headers.put("h2-plus-u-escaped", "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", esc2) + "\"]}");
        headers.put("h3-alg-u-escaped", "{\"alg\":\"ES\\u0032\\u0035\\u0036\",\"x5c\":[\"" + String.join("\",\"", x5c) + "\"]}");
        headers.put("h4-key-u-escaped", "{\"\\u0061lg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", x5c) + "\"]}");
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String jws = pki.signJwsWithHeader(e.getValue(), payload);
            Files.write(out.resolve(e.getKey() + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(jws);
            System.out.println("JAVA " + e.getKey() + ": " + (r.verified() ? "ok" : r.failure().reason()));
        }
    }
}
