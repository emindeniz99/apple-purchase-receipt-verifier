import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

/** Prints the Java implementation's answer for every .b64 file in a directory. Usage: OurVerdicts <dir>. */
public class OurVerdicts {
    public static void main(String[] args) throws Exception {
        Verifier verifier = Verifier.create(Config.defaults());
        File[] files = new File(args[0]).listFiles((d, n) -> n.endsWith(".b64"));
        Arrays.sort(files);
        for (File f : files) {
            String b64 = new String(Files.readAllBytes(f.toPath()), "US-ASCII").trim();
            VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64);
            String answer = result.verified() ? "ok" : result.failure().reason().name();
            System.out.println(f.getName().replace(".b64", "") + "\t" + answer);
        }
    }
}
