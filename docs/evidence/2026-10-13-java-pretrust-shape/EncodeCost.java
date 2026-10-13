import org.bouncycastle.asn1.*;

/** Re-encoding cost of a parsed nested value: DER vs DL, definite vs indefinite input. */
public class EncodeCost {
    static ASN1Encodable bulk(int depth, boolean set, boolean ber, int target) throws Exception {
        ASN1Encodable node = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(node);
            v.add(new ASN1Integer(1));
            node = set ? (ber ? new BERSet(v) : new DLSet(v)) : (ber ? new BERSequence(v) : new DLSequence(v));
        }
        int one = node.toASN1Primitive().getEncoded(ber ? "BER" : "DL").length;
        ASN1EncodableVector all = new ASN1EncodableVector();
        for (int i = 0; i < target / one; i++) all.add(node);
        return ber ? new BERSequence(all) : new DLSequence(all);
    }

    public static void main(String[] a) throws Exception {
        for (int depth : new int[] {1, 30, 60}) {
            for (String kind : new String[] {"seq", "set"}) {
                for (boolean ber : new boolean[] {false, true}) {
                    byte[] in = bulk(depth, kind.equals("set"), ber, 2_300_000).toASN1Primitive().getEncoded(ber ? "BER" : "DL");
                    StringBuilder sb = new StringBuilder(String.format("depth=%2d %s %s in=%d", depth, kind, ber ? "BER" : "DL ", in.length));
                    for (String enc : new String[] {"DL", "DER"}) {
                        long best = Long.MAX_VALUE;
                        for (int r = 0; r < 3; r++) {
                            ASN1Primitive p = ASN1Primitive.fromByteArray(in);
                            long t = System.nanoTime();
                            p.getEncoded(enc);
                            best = Math.min(best, System.nanoTime() - t);
                        }
                        sb.append(String.format("  %s %d ms", enc, best / 1_000_000));
                    }
                    long bp = Long.MAX_VALUE;
                    for (int r = 0; r < 3; r++) { long t = System.nanoTime(); ASN1Primitive.fromByteArray(in); bp = Math.min(bp, System.nanoTime() - t); }
                    sb.append(String.format("  parse %d ms", bp / 1_000_000));
                    System.out.println(sb);
                }
            }
        }
    }
}
