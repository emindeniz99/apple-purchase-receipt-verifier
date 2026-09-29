import bakeoff.jni.*;
import java.util.Collections;

public final class NativeSmoke {
    public static void main(String[] a) throws Exception {
        System.out.println("java " + System.getProperty("java.version"));
        try {
            new ReceiptVerifier("com.example.app", Collections.singletonList(new byte[]{1, 2, 3})).close();
            System.out.println("FAIL bad root: no exception");
            System.exit(1);
        } catch (ConfigurationException e) {
            System.out.println("PASS bad root: ConfigurationException: " + e.getMessage());
        }
        try (ReceiptVerifier v = new ReceiptVerifier("com.example.app")) {
            try {
                v.verifyBase64("not-a-real-receipt");
                System.out.println("FAIL malformed verify: no exception");
                System.exit(1);
            } catch (VerificationException e) {
                System.out.println("PASS malformed verify: " + e.reason() + ": " + e.getMessage());
            }
        }
        System.out.println("ALL OK");
    }
}
