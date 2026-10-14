import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Encodes fresh DERSets in a hot loop and checks each encoding against the
 * first one, which ran in the interpreter. Prints the first iteration whose
 * bytes differ. Args: iterations (default 2,000,000).
 */
public class DerSetRepro {
    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2_000_000;
        byte[][] want = new byte[3][];
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            int k = i % 3;
            byte[] got = build(k).getEncoded(ASN1Encoding.DER);
            if (want[k] == null) {
                want[k] = got;
                System.out.println("shape " + k + " reference: " + hex(got, 12) + " len=" + got.length);
            } else if (!Arrays.equals(want[k], got)) {
                System.out.printf("MISMATCH at iteration %d (%.1fs) shape %d%n  want %s%n  got  %s%n",
                        i, (System.nanoTime() - t0) / 1e9, k, hex(want[k], 24), hex(got, 24));
                System.exit(1);
            }
        }
        System.out.printf("OK %d iterations %.1fs%n", n, (System.nanoTime() - t0) / 1e9);
    }

    static DERSet build(int k) {
        switch (k) {
            case 0: // one element: a receipt attribute (type, version, value)
                return new DERSet(new DERSequence(new ASN1Encodable[] {
                    new ASN1Integer(9999), new ASN1Integer(1), new DEROctetString(new byte[16])
                }));
            case 1: // an RDN: SET { SEQ { OID, UTF8 } }
                return new DERSet(new DERSequence(new ASN1Encodable[] {
                    new ASN1ObjectIdentifier("2.5.4.3"), new DERUTF8String("Fake WWDR CA")
                }));
            default: { // more than 16 elements
                ASN1Encodable[] e = new ASN1Encodable[20];
                for (int j = 0; j < e.length; j++) e[j] = new ASN1Integer(j);
                return new DERSet(e);
            }
        }
    }

    static String hex(byte[] b, int max) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < Math.min(max, b.length); i++) s.append(String.format("%02x ", b[i] & 0xff));
        return s.toString().trim();
    }
}
