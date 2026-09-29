import uniffi.aprv_uniffi.ReceiptVerifier;
import uniffi.aprv_uniffi.VerifyException;
import java.util.Collections;
import java.util.List;

public final class NativeSmokeUniffi {
    public static void main(String[] args) {
        System.out.println("java.version=" + System.getProperty("java.version"));
        List<byte[]> badRoot = Collections.singletonList(new byte[]{1, 2, 3});
        try {
            ReceiptVerifier v = new ReceiptVerifier("com.example.app", badRoot);
            v.close();
            System.out.println("FAIL bad root: no exception");
            System.exit(1);
        } catch (Exception e) {
            if (e instanceof VerifyException.Config) {
                System.out.println("PASS bad root: VerifyException.Config: " + ((VerifyException.Config) e).getDetail());
            } else throw new RuntimeException(e);
        }
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app", null)) {
            try {
                v.verifyBase64("not-a-real-receipt");
                System.out.println("FAIL malformed verify: no exception");
                System.exit(1);
            } catch (Exception e) {
                if (e instanceof VerifyException.Verification ve) {
                    System.out.println("PASS malformed verify: " + ve.getReason() + ": " + ve.getDetail());
                } else throw new RuntimeException(e);
            }
        }
        System.out.println("ALL OK");
    }
}
