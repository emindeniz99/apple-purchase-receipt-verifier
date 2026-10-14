import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import java.util.Arrays;

/** Cost of one OID equality at the longest OID BouncyCastle admits, so the
 *  "a million comparisons, a few milliseconds" estimate can be checked
 *  without building a colliding table. */
public class OidEqualsCost {
    public static void main(String[] a) throws Exception {
        for (int len : new int[] {8, 300, 3000, 4000}) {
            // DER OID with `len` content bytes: 0x06 LL..., arcs 1.3, then (len-2) bytes 0x7f (each a one-byte arc 127)
            byte[] contents = new byte[len];
            contents[0] = 0x2b; // 1.3
            Arrays.fill(contents, 1, len, (byte) 0x7f);
            byte[] c2 = contents.clone(); c2[len - 1] = 0x7e; // differs in the last arc only
            ASN1Primitive o1 = ASN1Primitive.fromByteArray(der(contents));
            ASN1Primitive o2 = ASN1Primitive.fromByteArray(der(c2));
            // warm
            for (int i = 0; i < 200000; i++) { if (o1.equals(o2)) throw new AssertionError(); }
            long t0 = System.nanoTime();
            int n = 1_000_000;
            for (int i = 0; i < n; i++) { if (o1.equals(o2)) throw new AssertionError(); }
            long eq = System.nanoTime() - t0;
            t0 = System.nanoTime();
            int h = 0;
            for (int i = 0; i < 2000; i++) { h += o1.hashCode(); }
            long hc = System.nanoTime() - t0;
            System.out.printf("OID content %d bytes: 1e6 equals = %d ms; 2000 hashCode = %d ms (%d)%n", len, eq / 1_000_000, hc / 1_000_000, h & 1);
        }
    }
    static byte[] der(byte[] contents) {
        int l = contents.length;
        byte[] out;
        if (l < 128) { out = new byte[2 + l]; out[0] = 6; out[1] = (byte) l; System.arraycopy(contents, 0, out, 2, l); }
        else { out = new byte[4 + l]; out[0] = 6; out[1] = (byte) 0x82; out[2] = (byte) (l >> 8); out[3] = (byte) l; System.arraycopy(contents, 0, out, 4, l); }
        return out;
    }
}
