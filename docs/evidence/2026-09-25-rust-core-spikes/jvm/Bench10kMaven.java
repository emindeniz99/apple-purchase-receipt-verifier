package cur;
import io.github.emindeniz99.applepurchasereceiptverifier.*;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.cert.*;
import java.util.*;
public final class Bench10k {
  public static void main(String[] a) throws Exception {
    String F = "../../../../fixtures/";
    String b64 = new String(Files.readAllBytes(Paths.get(F + "public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
    ReceiptVerifier v = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app");
    X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Paths.get(F + "generated/jws-root.der"))));
    JwsVerifier j = new JwsVerifier(Collections.singleton(root), "com.example.app", EnumSet.of(Environment.SANDBOX));
    String jws = new String(Files.readAllBytes(Paths.get(F + "generated/transaction.jws")), "UTF-8").trim();
    for (int i = 0; i < 10000; i++) { v.verify(b64); j.verifyTransaction(jws); }
    for (int round = 1; round <= 3; round++) {
      long t = System.nanoTime(); for (int i = 0; i < 10000; i++) v.verify(b64); long rUs = (System.nanoTime() - t) / 10000 / 1000;
      t = System.nanoTime(); for (int i = 0; i < 10000; i++) j.verifyTransaction(jws); long jUs = (System.nanoTime() - t) / 10000 / 1000;
      System.out.println("maven 0.6.0 (BC)  round " + round + ": receipt " + rUs + " us, jws " + jUs + " us");
    }
  }
}
