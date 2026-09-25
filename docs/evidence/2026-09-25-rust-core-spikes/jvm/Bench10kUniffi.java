package spike;
import java.nio.file.*;
import java.util.*;
import uniffi.aprv_uniffi.*;
public final class Bench10k {
  public static void main(String[] a) throws Exception {
    String F = "../../../../fixtures/";
    String b64 = new String(Files.readAllBytes(Paths.get(F + "public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
    ReceiptVerifier v = new ReceiptVerifier("dev.bonzer.weeka.app", null);
    JwsVerifier j = new JwsVerifier("com.example.app", Arrays.asList(Environment.SANDBOX), null, Arrays.asList(Files.readAllBytes(Paths.get(F + "generated/jws-root.der"))));
    String jws = new String(Files.readAllBytes(Paths.get(F + "generated/transaction.jws")), "UTF-8").trim();
    for (int i = 0; i < 10000; i++) { v.verifyBase64(b64); j.verifyTransaction(jws); }
    for (int round = 1; round <= 3; round++) {
      long t = System.nanoTime(); for (int i = 0; i < 10000; i++) v.verifyBase64(b64); long rUs = (System.nanoTime() - t) / 10000 / 1000;
      t = System.nanoTime(); for (int i = 0; i < 10000; i++) j.verifyTransaction(jws); long jUs = (System.nanoTime() - t) / 10000 / 1000;
      System.out.println("rust via uniffi   round " + round + ": receipt " + rUs + " us, jws " + jUs + " us");
    }
  }
}
