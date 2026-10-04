import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * How deep do genuine Apple receipts nest, as BouncyCastle's
 * org.bouncycastle.asn1.max_cons_depth counts it, and does the 9-deep probe
 * Verifier.create parses fail at exactly the same bound?
 *
 * Usage: java -cp <library + bcprov/bcutil/bcpkix + jackson-core + this> DepthSweep <fixtures dir>
 *
 * The verifier is built before the bound is lowered: from this change on,
 * Verifier.create itself refuses a bound below 9.
 */
public final class DepthSweep {
    private static final String PROPERTY = "org.bouncycastle.asn1.max_cons_depth";

    public static void main(String[] args) throws Exception {
        Path receipts = Paths.get(args[0], "public-receipts");
        String[] names = {"receipt-sandbox-legacy", "receipt-sandbox-g5", "receipt-xcode-with-purchases"};
        String[] inputs = new String[names.length];
        for (int i = 0; i < names.length; i++) {
            inputs[i] = new String(Files.readAllBytes(receipts.resolve(names[i] + ".b64")), StandardCharsets.US_ASCII)
                    .trim();
        }
        Verifier verifier = Verifier.create(Config.defaults());
        for (int bound = 6; bound <= 11; bound++) {
            System.setProperty(PROPERTY, Integer.toString(bound));
            StringBuilder line = new StringBuilder("max_cons_depth=" + bound + ":");
            for (int i = 0; i < names.length; i++) {
                line.append(' ').append(names[i]).append('=').append(verdict(verifier, inputs[i]));
            }
            line.append(" probe9=").append(parses(nested(9)) ? "parses" : "refused");
            line.append(" create=").append(creates() ? "ok" : "IllegalStateException");
            System.out.println(line);
        }
        System.clearProperty(PROPERTY);
    }

    private static String verdict(Verifier verifier, String base64) {
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
        return result.verified() ? "ok" : result.failure().reason().name();
    }

    /** {@code levels} definite-length SEQUENCEs around INTEGER 0, as DefaultVerifier.requireReceiptNesting builds. */
    static byte[] nested(int levels) {
        byte[] der = {0x02, 0x01, 0x00};
        for (int i = 0; i < levels; i++) {
            byte[] outer = new byte[der.length + 2];
            outer[0] = 0x30;
            outer[1] = (byte) der.length;
            System.arraycopy(der, 0, outer, 2, der.length);
            der = outer;
        }
        return der;
    }

    private static boolean parses(byte[] der) {
        try {
            ASN1Primitive.fromByteArray(der);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean creates() {
        try {
            Verifier.create(Config.defaults());
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }
}
