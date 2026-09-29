package spike.jni;
import java.nio.file.*;
public final class Bench {
  public static void main(String[] a) throws Exception {
    String b64 = new String(Files.readAllBytes(Paths.get("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
    try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app"); ReceiptVerifier w = new ReceiptVerifier("com.other.app")) {
      System.out.println("java " + System.getProperty("java.version") + " ok: " + v.verifyBase64(b64));
      try { w.verifyBase64(b64); } catch (VerificationException e) { System.out.println("error ok: " + e.getMessage()); }
      for (int i = 0; i < 10000; i++) v.verifyBase64(b64);
      for (int r = 1; r <= 3; r++) { long t = System.nanoTime(); for (int i = 0; i < 10000; i++) v.verifyBase64(b64);
        System.out.println("hand-written JNI round " + r + ": receipt " + (System.nanoTime() - t) / 10000 / 1000 + " us"); }
    }
  }
}
