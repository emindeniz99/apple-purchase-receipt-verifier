import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/** Java's verdict on each receipt variants.mjs wrote, under the default roots. Args: the variants directory. */
public class JavaVerdicts {
  public static void main(String[] a) throws Exception {
    Verifier v = Verifier.create(Config.defaults());
    for (String n : new String[] {"gost94", "md2", "whirlpool", "streebog256", "streebog512", "dstu256", "dstu384", "dstu512"}) {
      byte[] der = Files.readAllBytes(Paths.get(a[0], n + ".der"));
      VerificationResult<ReceiptPayload> r = v.verifyReceipt(Base64.getEncoder().encodeToString(der));
      System.out.println("java " + n + ": " + (r.failure() == null ? "ok" : r.failure().reason() + " / " + r.failure().message()));
    }
  }
}
