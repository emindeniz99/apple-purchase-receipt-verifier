package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Probe12: endpoint _pst rendering of many dates (years 0000-9999) from a signed receipt, Java vs core. */
public class Probe12Tz {
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        int files = Integer.parseInt(a[1]); long seed = Long.parseLong(a[2]);
        TestPki pki = TestPki.receipt(new Date(1704067200000L), new Date(2524608000000L));
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        final long NOW = 1735000000000L;
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).clock(java.time.Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC)).build());
        Random r = new Random(seed);
        for (int f = 0; f < files; f++) {
            List<byte[]> inApps = new ArrayList<>();
            for (int k = 0; k < 20; k++) {
                int year; int mode = r.nextInt(4);
                if (mode == 0) year = r.nextInt(10000); else if (mode == 1) year = 1883 + r.nextInt(200); else if (mode == 2) year = 1900 + r.nextInt(140); else year = 2000 + r.nextInt(100);
                LocalDateTime t = LocalDateTime.of(year, 1 + r.nextInt(12), 1, r.nextInt(24), r.nextInt(60), r.nextInt(60)).plusDays(r.nextInt(28));
                String date = String.format("%04d-%02d-%02dT%02d:%02d:%02dZ", t.getYear(), t.getMonthValue(), t.getDayOfMonth(), t.getHour(), t.getMinute(), t.getSecond());
                // pin near DST edges on a share of samples
                if (r.nextInt(5) == 0 && year >= 1918 && year <= 2040) {
                    LocalDateTime d = LocalDateTime.of(year, r.nextBoolean() ? 3 : 11, 1 + r.nextInt(14), 8 + r.nextInt(3), r.nextInt(60), 0);
                    date = String.format("%04d-%02d-%02dT%02d:%02d:%02dZ", d.getYear(), d.getMonthValue(), d.getDayOfMonth(), d.getHour(), d.getMinute(), d.getSecond());
                }
                inApps.add(TestPki.inAppPurchase(1, "p" + k, "t" + f + "-" + k, "o" + k, date, date));
            }
            byte[] payload = TestPki.receiptPayload("com.example.app", "1.0", new byte[]{1}, new byte[20], "2024-08-06T12:00:00Z", inApps);
            byte[] rec = pki.signReceipt(payload, new Date(1722945600000L));
            String b64 = Base64.getEncoder().encodeToString(rec);
            String id = String.format("t%04d", f);
            Files.write(out.resolve(id + ".b64"), b64.getBytes(StandardCharsets.US_ASCII));
            String resp = v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + b64 + "\"}");
            Files.write(out.resolve(id + ".java.json"), resp.getBytes(StandardCharsets.UTF_8));
        }
    }
}
