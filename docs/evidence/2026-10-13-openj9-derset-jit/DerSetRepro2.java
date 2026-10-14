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
 * Profile shape of the test suite: DERSets almost always encoded inside a
 * parent (so their length is already cached when encode runs), and rarely a
 * fresh DERSet encoded on its own (length not cached yet). Checks the rare
 * case against its interpreted reference. Args: iterations, rare-every.
 */
public class DerSetRepro2 {
    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 20_000_000;
        int every = args.length > 1 ? Integer.parseInt(args[1]) : 1000;
        byte[] want = fresh().getEncoded(ASN1Encoding.DER);
        System.out.println("reference " + hex(want, 8));
        long t0 = System.nanoTime();
        long sink = 0;
        for (int i = 0; i < n; i++) {
            if (i % every == 0) {
                byte[] got = fresh().getEncoded(ASN1Encoding.DER);
                if (!Arrays.equals(want, got)) {
                    System.out.printf("MISMATCH at iteration %d (%.1fs): got %s%n", i, (System.nanoTime() - t0) / 1e9,
                            hex(got, 8));
                    System.exit(1);
                }
            } else {
                // A Name: SEQ of RDN SETs; the parent computes each SET's length first.
                ASN1Encodable[] rdns = new ASN1Encodable[3];
                for (int j = 0; j < 3; j++) {
                    rdns[j] = new DERSet(new DERSequence(new ASN1Encodable[] {
                        new ASN1ObjectIdentifier("2.5.4.3"), new DERUTF8String("CN" + (i & 7))
                    }));
                }
                sink += new DERSequence(rdns).getEncoded(ASN1Encoding.DER).length;
            }
        }
        System.out.printf("OK %d iterations %.1fs (%d)%n", n, (System.nanoTime() - t0) / 1e9, sink);
    }

    static DERSet fresh() {
        return new DERSet(new DERSequence(new ASN1Encodable[] {
            new ASN1Integer(9999), new ASN1Integer(1), new DEROctetString(new byte[16])
        }));
    }

    static String hex(byte[] b, int max) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < Math.min(max, b.length); i++) s.append(String.format("%02x ", b[i] & 0xff));
        return s.toString().trim();
    }
}
