package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Probe13: 24 threads, genuine + hostile mix, 15 s; any genuine input answering anything but ok is a bug. */
public class Probe13Conc {
    public static void main(String[] a) throws Exception {
        String g5 = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        String legacy = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-legacy.b64")), StandardCharsets.US_ASCII).trim();
        TestPki pki = TestPki.jws();
        String jws = pki.signJws(TestPki.claims("signedDate", System.currentTimeMillis(), "environment", "Sandbox"));
        Verifier v = Verifier.create(Config.defaults());
        Verifier v2 = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        byte[] der = Base64.getDecoder().decode(g5);
        AtomicLong okG = new AtomicLong(), bad = new AtomicLong(), hostile = new AtomicLong(), errors = new AtomicLong();
        ConcurrentHashMap<String, AtomicLong> verdicts = new ConcurrentHashMap<>();
        long end = System.currentTimeMillis() + 15000;
        ExecutorService ex = Executors.newFixedThreadPool(24);
        List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < 24; t++) {
            final int tid = t;
            fs.add(ex.submit(() -> {
                Random r = new Random(tid);
                while (System.currentTimeMillis() < end) {
                    try {
                        int k = r.nextInt(6);
                        if (k == 0) { if (v.verifyReceipt(g5).verified()) okG.incrementAndGet(); else bad.incrementAndGet(); }
                        else if (k == 1) { if (v.verifyReceipt(legacy).verified()) okG.incrementAndGet(); else bad.incrementAndGet(); }
                        else if (k == 2) { if (v2.verifySignedData(jws).verified()) okG.incrementAndGet(); else bad.incrementAndGet(); }
                        else if (k == 3) { if (v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + g5 + "\"}").startsWith("{\"status\":0")) okG.incrementAndGet(); else bad.incrementAndGet(); }
                        else {
                            byte[] m = der.clone(); m[r.nextInt(m.length)] ^= (byte) (1 << r.nextInt(8));
                            VerificationResult<ReceiptPayload> res = v.verifyReceipt(Base64.getEncoder().encodeToString(m));
                            hostile.incrementAndGet();
                            String key = res.verified() ? "ok" : res.failure().reason().toString();
                            verdicts.computeIfAbsent(key, x -> new AtomicLong()).incrementAndGet();
                        }
                    } catch (Throwable th) { errors.incrementAndGet(); th.printStackTrace(); }
                }
            }));
        }
        for (Future<?> f : fs) f.get();
        ex.shutdown();
        System.out.println("genuine ok=" + okG + " genuine-not-ok=" + bad + " hostile=" + hostile + " thrown=" + errors + " hostile verdicts=" + verdicts);
    }
}
