package spike;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import uniffi.aprv_uniffi.AppReceipt;
import uniffi.aprv_uniffi.Environment;
import uniffi.aprv_uniffi.InAppPurchase;
import uniffi.aprv_uniffi.JwsVerifier;
import uniffi.aprv_uniffi.VerifyReceiptEndpoint;
import uniffi.aprv_uniffi.VerifyReceiptResult;

public final class ObjectsDemo {
    static final String F = "../../../../fixtures/";

    public static void main(String[] args) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get(F + "public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
        String body = "{\"receipt-data\":\"" + b64 + "\"}";

        try (VerifyReceiptEndpoint prod = new VerifyReceiptEndpoint(Environment.PRODUCTION, null)) {
            long t0 = System.nanoTime();
            VerifyReceiptResult result = prod.verifyReceiptResult(body);   // verification happens HERE, once
            long verifyUs = (System.nanoTime() - t0) / 1000;

            // result is a handle to the Rust object; render it as often as you like
            long t1 = System.nanoTime();
            String asProd = null, asSandbox = null;
            for (int i = 0; i < 1000; i++) {
                asProd = result.toJson();
                asSandbox = result.toJsonIn(Environment.SANDBOX);
            }
            long renderUs = (System.nanoTime() - t1) / 1000 / 2000;
            System.out.println("verify once: " + verifyUs + " us, each toJson/toJsonIn: " + renderUs + " us (no re-verification)");
            System.out.println("toJson()            -> " + asProd);
            System.out.println("toJsonIn(SANDBOX)   -> " + asSandbox.substring(0, 70) + "...");

            // receipt() copies the nested record (lists included) into plain Java objects
            AppReceipt r = result.receipt();
            InAppPurchase first = r.getInAppPurchases().get(0);
            System.out.println("receipt: " + r.getBundleId() + ", " + r.getInAppPurchases().size() + " IAPs, first=" + first.getProductId()
                    + " purchased=" + first.getPurchaseDateMs());

            // the copy is editable (Kotlin 'var'), but it is YOUR copy: the Rust result is untouched
            r.setBundleId("evil.app");
            first.setProductId("free.stuff");
            System.out.println("edited copy: " + r.getBundleId() + " / " + r.getInAppPurchases().get(0).getProductId());
            System.out.println("rust still:  " + result.receipt().getBundleId() + " / "
                    + result.receipt().getInAppPurchases().get(0).getProductId()
                    + "  toJsonIn unchanged: " + result.toJsonIn(Environment.SANDBOX).equals(asSandbox));
            result.close();
        }

        // a Map returned from Rust
        try (JwsVerifier j = new JwsVerifier("com.example.app", Arrays.asList(Environment.SANDBOX), null,
                Arrays.asList(Files.readAllBytes(Paths.get(F + "generated/jws-root.der"))))) {
            Map<String, String> claims = j.verifyRawMap(new String(Files.readAllBytes(Paths.get(F + "generated/transaction.jws")), "UTF-8").trim());
            System.out.println("map: " + claims.getClass().getName() + ", " + claims.size() + " claims, productId=" + claims.get("productId"));
            try {
                claims.put("price", "0");
                System.out.println("map is mutable: put worked, price=" + claims.get("price"));
            } catch (UnsupportedOperationException e) {
                System.out.println("map is read-only: " + e);
            }
        }
    }
}
