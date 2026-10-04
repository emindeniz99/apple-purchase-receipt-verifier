import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.TestPki;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.util.Base64;

/**
 * What does a cap-sized receipt that no pinned root vouches for cost before
 * the library refuses it? The payload is one SET of {@code n} distinct
 * unknown attributes (a 3-byte INTEGER type, version 1, an empty OCTET
 * STRING; 12 bytes each) with no creation date (type 12), so the pre-trust
 * walk reads every one. TestPki signs it; the default Apple roots do not
 * trust TestPki, so the verdict is UNTRUSTED_CHAIN and every millisecond is
 * spent before trust.
 *
 * Usage: java -cp <library + its test classes (TestPki) + dependencies + this> HostileCost [n]
 * n defaults to 190,000: 2,280,005 payload bytes, just under the 3,145,728
 * base64 cap once signed.
 *
 * Adapted from the probe the 2026-10 Java review used (Hostile.java).
 */
public final class HostileCost {
    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 190_000;
        ByteArrayOutputStream attributes = new ByteArrayOutputStream();
        for (int i = 0; i < n; i++) {
            int type = 100_000 + i;
            attributes.write(new byte[] {
                0x30, 0x0A,
                0x02, 0x03, (byte) (type >> 16), (byte) (type >> 8), (byte) type,
                0x02, 0x01, 0x01,
                0x04, 0x00
            });
        }
        byte[] body = attributes.toByteArray();
        ByteArrayOutputStream set = new ByteArrayOutputStream();
        set.write(0x31);
        set.write(length(body.length));
        set.write(body);
        byte[] payload = set.toByteArray();
        String base64 = Base64.getEncoder().encodeToString(TestPki.receipt().signReceipt(payload));
        System.out.printf("attributes=%d payload bytes=%d base64 chars=%d (cap 3145728)%n",
                n, payload.length, base64.length());

        Verifier verifier = Verifier.create(Config.defaults());
        VerificationResult<ReceiptPayload> result = null;
        for (int i = 0; i < 30; i++) {
            result = verifier.verifyReceipt(base64);
        }
        System.out.println("verdict: " + result.failure().reason());
        int calls = 20;
        long allocated = allocated();
        long start = System.nanoTime();
        for (int i = 0; i < calls; i++) {
            verifier.verifyReceipt(base64);
        }
        long elapsed = System.nanoTime() - start;
        System.out.printf("per call over %d calls: %.1f ms, %.0f MB allocated%n",
                calls, elapsed / 1e6 / calls, (allocated() - allocated) / 1e6 / calls);
    }

    private static long allocated() {
        return ((com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean())
                .getThreadAllocatedBytes(Thread.currentThread().getId());
    }

    /** A minimal DER length. */
    private static byte[] length(int n) {
        if (n < 128) {
            return new byte[] {(byte) n};
        }
        int bytes = n < 1 << 8 ? 1 : n < 1 << 16 ? 2 : n < 1 << 24 ? 3 : 4;
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = 0; i < bytes; i++) {
            out[bytes - i] = (byte) (n >> (8 * i));
        }
        return out;
    }
}
