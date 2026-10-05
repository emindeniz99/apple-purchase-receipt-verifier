package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Probe10: re-signed JWS whose header/payload JSON text is randomly edited; Java verdicts vs core. */
public class Probe10JwsFuzz {
    static final String[] TOK = {"{", "}", "[", "]", "\"", ",", ":", "\\", " ", "\n", "\t", "0", "1", "9", "e", "E", ".", "-", "+", "null", "true", "false", "\\u0000", "\\ud800", "\\u00e9", "/", "\\/", "\u00e9", "\u2028", "\"alg\":\"ES256\",", "\"x5c\":[],", "//", "/*", "'", "NaN", "Infinity", "01", "-0", "1e400", "\"signedDate\":", "\"environment\":\"Sandbox\","};
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        int n = Integer.parseInt(a[1]); long seed = Long.parseLong(a[2]);
        TestPki pki = TestPki.jws();
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        long now = System.currentTimeMillis();
        String baseHeader = "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", pki.x5c()) + "\"]}";
        String basePayload = "{\"signedDate\":" + now + ",\"environment\":\"Sandbox\",\"data\":{\"environment\":\"Production\",\"x\":[1,2,{\"y\":null}]},\"transactionId\":\"123\"}";
        Random r = new Random(seed);
        PrintWriter tsv = new PrintWriter(Files.newBufferedWriter(out.resolve("java.tsv")));
        int escaped = 0;
        for (int i = 0; i < n; i++) {
            boolean hdr = r.nextBoolean();
            String base = hdr ? baseHeader : basePayload;
            StringBuilder sb = new StringBuilder(base);
            int edits = 1 + r.nextInt(3);
            for (int e = 0; e < edits; e++) {
                int p = r.nextInt(sb.length() + 1);
                // keep edits near the structural part for the header (x5c blobs are long)
                if (hdr && r.nextInt(3) != 0) p = r.nextInt(Math.min(sb.length() + 1, 40));
                int k = r.nextInt(3);
                String tok = TOK[r.nextInt(TOK.length)];
                if (k == 0) sb.insert(p, tok);
                else if (k == 1 && p < sb.length()) sb.delete(p, Math.min(sb.length(), p + 1 + r.nextInt(3)));
                else if (p < sb.length()) { sb.delete(p, p + 1); sb.insert(p, tok); }
            }
            String h = hdr ? sb.toString() : baseHeader, p = hdr ? basePayload : sb.toString();
            String jws;
            try { jws = pki.signJwsWithHeader(h, p); } catch (Exception ex) { continue; }
            String id = String.format("j%05d", i);
            Files.write(out.resolve(id + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            String verdict;
            try { VerificationResult<JsonPayload> res = v.verifySignedData(jws); verdict = res.verified() ? "ok:" + res.payload().environment() : res.failure().reason().toString(); }
            catch (Throwable t) { verdict = "ESCAPED " + t; escaped++; }
            tsv.println(id + "\t" + verdict + "\t" + (hdr ? "H" : "P") + "\t" + sb.toString().replace("\n", "\\n").replace("\t", "\\t").replaceAll("[A-Za-z0-9+/=]{60,}", "<b64>"));
        }
        tsv.close();
        System.out.println("escaped=" + escaped);
    }
}
