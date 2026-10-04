import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.util.Base64;

/**
 * Which bcprov does Verifier.create accept, and what does each one's ASN.1
 * parser do with 400,000 nested indefinite-length SEQUENCEs? Run once per bcprov jar, with
 * bcutil and bcpkix 1.86 and the library unchanged.
 *
 * Usage: java -cp <library + bcprov-X + bcutil/bcpkix 1.86 + jackson-core + this> FloorCheck
 */
public final class FloorCheck {
    public static void main(String[] args) {
        System.out.println("provider: " + new org.bouncycastle.jce.provider.BouncyCastleProvider().getInfo());
        try {
            Verifier.create(Config.defaults());
            System.out.println("create: accepted");
        } catch (IllegalStateException e) {
            System.out.println("create: refused: " + e.getMessage());
        }
        // create now refuses an old bcprov, so verifyReceipt cannot be reached
        // on one. The envelope parse it would have run first is
        // ASN1Primitive.fromByteArray (ReceiptCore.verifyDer), so drive that.
        int levels = 400_000;
        byte[] der = new byte[levels * 4];
        for (int i = 0; i < levels; i++) {
            der[2 * i] = 0x30;
            der[2 * i + 1] = (byte) 0x80;
        }
        System.out.println("deep input: " + Base64.getEncoder().encodeToString(der).length() + " base64 chars");
        try {
            org.bouncycastle.asn1.ASN1Primitive.fromByteArray(der);
            System.out.println("deep parse: accepted");
        } catch (java.io.IOException | RuntimeException e) {
            System.out.println("deep parse: refused (" + e.getClass().getName() + ")");
        } catch (StackOverflowError e) {
            System.out.println("deep parse: StackOverflowError");
        }
    }
}
