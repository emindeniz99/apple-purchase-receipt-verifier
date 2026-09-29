package spike;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import uniffi.aprv_uniffi.AppReceipt;
import uniffi.aprv_uniffi.Environment;
import uniffi.aprv_uniffi.JwsVerifier;
import uniffi.aprv_uniffi.Reason;
import uniffi.aprv_uniffi.ReceiptVerifier;
import uniffi.aprv_uniffi.TransactionPayload;
import uniffi.aprv_uniffi.VerifyException;

public final class Smoke {
    static final String F = "../../../../fixtures/";

    static byte[] read(String p) throws Exception {
        return Files.readAllBytes(Paths.get(F + p));
    }

    public static void main(String[] args) throws Exception {
        System.out.println("java.version=" + System.getProperty("java.version"));
        byte[] root = read("generated/receipt-root.der");
        // try-with-resources: generated class is AutoCloseable
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", Arrays.asList(root))) {
            AppReceipt r = v.verify(read("generated/receipt.der"));
            System.out.println("receipt ok: " + r.getBundleId() + " iaps=" + r.getInAppPurchases().size()
                    + " created=" + r.getCreationDateMs());
        }
        // Kotlin default argument is invisible to Java: null must be passed explicitly
        String b64 = new String(read("public-receipts/receipt-sandbox-g5.b64"), "US-ASCII").replaceAll("\\s", "");
        try (ReceiptVerifier g = new ReceiptVerifier("dev.bonzer.weeka.app", null)) {
            long t = System.nanoTime();
            int n = 300;
            AppReceipt r = null;
            for (int i = 0; i < n; i++) r = g.verifyBase64(b64);
            System.out.println("genuine g5 ok: iaps=" + r.getInAppPurchases().size() + " "
                    + (System.nanoTime() - t) / n / 1000 + " us/op incl. warmup+FFI");
        }
        // checked exception, typed reason
        try (ReceiptVerifier v = new ReceiptVerifier("com.other.app", Arrays.asList(root))) {
            v.verify(read("generated/receipt.der"));
            throw new AssertionError("must fail");
        } catch (VerifyException.Verification e) {
            System.out.println("error ok: " + (e.getReason() == Reason.WRONG_BUNDLE_ID) + " " + e.getDetail());
        }
        // appAppleId is kotlin.ULong? -> Java can only pass null or a boxed kotlin.ULong
        try (JwsVerifier j = new JwsVerifier("com.example.app", Arrays.asList(Environment.SANDBOX), null,
                Arrays.asList(read("generated/jws-root.der")))) {
            TransactionPayload p = j.verifyTransaction(new String(read("generated/transaction.jws"), "UTF-8").trim());
            System.out.println("jws ok: " + p.getProductId() + " signed=" + p.getSignedDate());
        }
        System.out.println("ALL OK");
    }
}
