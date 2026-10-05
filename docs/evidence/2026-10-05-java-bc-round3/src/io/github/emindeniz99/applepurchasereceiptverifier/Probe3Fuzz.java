package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Probe3: mutation fuzz of genuine public receipts; Java verdicts to a TSV, bodies to files for the core. */
public class Probe3Fuzz {
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        int n = Integer.parseInt(a[1]); long seed = Long.parseLong(a[2]);
        String[] names = {"receipt-sandbox-g5", "receipt-sandbox-legacy", "receipt-xcode-with-purchases"};
        Verifier v = Verifier.create(Config.defaults());
        Random r = new Random(seed);
        PrintWriter tsv = new PrintWriter(Files.newBufferedWriter(out.resolve("java.tsv")));
        for (int i = 0; i < n; i++) {
            String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/" + names[i % 2] + ".b64")), StandardCharsets.US_ASCII).trim();
            byte[] der = Base64.getDecoder().decode(src);
            byte[] m = der.clone();
            int kind = r.nextInt(6);
            String what;
            switch (kind) {
                case 0: { int p = r.nextInt(m.length); m[p] ^= (1 << r.nextInt(8)); what = "flip@" + p; break; }
                case 1: { int p = r.nextInt(Math.min(m.length, 400)); m[p] = (byte) r.nextInt(256); what = "set-header@" + p; break; }
                case 2: { int p = r.nextInt(m.length); int len = 1 + r.nextInt(8); m = cat(Arrays.copyOf(m, p), Arrays.copyOfRange(m, Math.min(m.length, p + len), m.length)); what = "del@" + p + "+" + len; break; }
                case 3: { int p = r.nextInt(m.length); m = Arrays.copyOf(m, p); what = "trunc@" + p; break; }
                case 4: { int p = r.nextInt(Math.min(m.length, 300)); m[p] = (byte) (m[p] ^ 0x20); what = "xor20@" + p; break; }
                default: { int p = r.nextInt(Math.min(m.length, 2000)); byte[] ins = new byte[1 + r.nextInt(4)]; r.nextBytes(ins); m = cat(Arrays.copyOf(m, p), cat(ins, Arrays.copyOfRange(m, p, m.length))); what = "ins@" + p; }
            }
            String b64 = Base64.getEncoder().encodeToString(m);
            String id = String.format("f%05d", i);
            Files.write(out.resolve(id + ".b64"), b64.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<ReceiptPayload> res = v.verifyReceipt(b64);
            tsv.println(id + "\t" + (res.verified() ? "ok" : res.failure().reason()) + "\t" + what);
        }
        tsv.close();
    }
    static byte[] cat(byte[] x, byte[] y) { byte[] z = Arrays.copyOf(x, x.length + y.length); System.arraycopy(y, 0, z, x.length, y.length); return z; }
}
