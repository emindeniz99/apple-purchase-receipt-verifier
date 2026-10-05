package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Probe14: JWS x5c entries with bytes after the certificate's DER (leaf, intermediate, root); a second certificate appended; a root slot holding leaf and root. */
public class Probe14Trail {
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    static byte[] cat(byte[]... p) { int n = 0; for (byte[] x : p) n += x.length; byte[] r = new byte[n]; int o = 0; for (byte[] x : p) { System.arraycopy(x, 0, r, o, x.length); o += x.length; } return r; }
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        TestPki pki = TestPki.jws();
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        String payload = "{\"signedDate\":" + System.currentTimeMillis() + ",\"environment\":\"Sandbox\"}";
        byte[] L = pki.leaf.getEncoded(), I = pki.intermediate.getEncoded(), R = pki.root.getEncoded();
        Map<String, List<byte[]>> variants = new LinkedHashMap<>();
        variants.put("t0-plain", Arrays.asList(L, I, R));
        variants.put("t1-leaf-trailing-zero", Arrays.asList(cat(L, new byte[]{0}), I, R));
        variants.put("t2-leaf-trailing-garbage", Arrays.asList(cat(L, "GARBAGE-BYTES".getBytes()), I, R));
        variants.put("t3-inter-trailing-zero", Arrays.asList(L, cat(I, new byte[]{0}), R));
        variants.put("t4-root-trailing-zero", Arrays.asList(L, I, cat(R, new byte[]{0})));
        variants.put("t5-leaf-then-second-cert", Arrays.asList(cat(L, I), I, R));
        variants.put("t6-root-slot-holds-leaf-and-root", Arrays.asList(L, I, cat(L, R)));
        variants.put("t7-inter-trailing-many", Arrays.asList(L, cat(I, new byte[5000]), R));
        for (Map.Entry<String, List<byte[]>> e : variants.entrySet()) {
            List<String> x = new ArrayList<>(); for (byte[] c : e.getValue()) x.add(b64(c));
            String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", x) + "\"]}";
            String jws = pki.signJwsWithHeader(header, payload);
            Files.write(out.resolve(e.getKey() + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(jws);
            System.out.println("JAVA " + e.getKey() + ": " + (r.verified() ? "ok" : r.failure().reason() + " / " + r.failure().message()));
        }
    }
}
