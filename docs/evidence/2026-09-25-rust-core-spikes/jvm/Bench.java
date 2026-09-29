package spike;
import java.nio.file.*;
import java.util.*;
import uniffi.aprv_uniffi.*;
public final class Bench {
  public static void main(String[] a) throws Exception {
    String F = "../../../../fixtures/";
    String b64 = new String(Files.readAllBytes(Paths.get(F + "public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
    try (ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app", null)) {
      for (int i = 0; i < 500; i++) v.verifyBase64(b64);
      long t = System.nanoTime(); int n = 1000; for (int i = 0; i < n; i++) v.verifyBase64(b64);
      System.out.println("uniffi-kotlin receipt g5 " + (System.nanoTime() - t) / n / 1000 + " us/op, java " + System.getProperty("java.version"));
    }
    try (JwsVerifier j = new JwsVerifier("com.example.app", Arrays.asList(Environment.SANDBOX), null, Arrays.asList(Files.readAllBytes(Paths.get(F + "generated/jws-root.der"))))) {
      String jws = new String(Files.readAllBytes(Paths.get(F + "generated/transaction.jws")), "UTF-8").trim();
      for (int i = 0; i < 500; i++) j.verifyTransaction(jws);
      long t = System.nanoTime(); int n = 1000; for (int i = 0; i < n; i++) j.verifyTransaction(jws);
      System.out.println("uniffi-kotlin jws " + (System.nanoTime() - t) / n / 1000 + " us/op");
    }
  }
}
