package spike;
import java.nio.file.*;
import uniffi.aprv_uniffi.*;
public final class JsonBench {
  public static void main(String[] a) throws Exception {
    String b64 = new String(Files.readAllBytes(Paths.get("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
    String body = "{\"receipt-data\":\"" + b64 + "\"}";
    try (VerifyReceiptEndpoint e = new VerifyReceiptEndpoint(Environment.SANDBOX, null)) {
      String out = null; for (int i = 0; i < 2000; i++) out = e.verifyReceiptJson(body);
      long t = System.nanoTime(); int n = 10000; for (int i = 0; i < n; i++) out = e.verifyReceiptJson(body);
      System.out.println("in-process UniFFI verifyReceiptJson (Sandbox, status 0): " + (System.nanoTime() - t) / n / 1000 + " us/op, response " + out.length() + " chars");
    }
  }
}
