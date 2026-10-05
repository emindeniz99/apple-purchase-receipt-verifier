package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.asn1.*;

/** Probe6: does a max-nesting (BC bound 64) hostile input overflow small thread stacks, escaping the error mapping? */
public class Probe6Stack {
    static ASN1Encodable nest(int depth, ASN1Encodable inner) { ASN1Encodable x = inner; for (int i = 0; i < depth; i++) x = new DERSequence(x); return x; }
    static ASN1Sequence replace(ASN1Sequence s, int idx, ASN1Encodable e) { ASN1EncodableVector vec = new ASN1EncodableVector(); for (int i = 0; i < s.size(); i++) vec.add(i == idx ? e : s.getObjectAt(i)); return new DLSequence(vec); }
    public static void main(String[] a) throws Exception {
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        ASN1Sequence ci = (ASN1Sequence) ASN1Primitive.fromByteArray(Base64.getDecoder().decode(src));
        ASN1Sequence sd = ASN1Sequence.getInstance(((ASN1TaggedObject) ci.getObjectAt(1)).getBaseObject());
        ASN1Set sis = (ASN1Set) sd.getObjectAt(4); ASN1Sequence si = (ASN1Sequence) sis.getObjectAt(0);
        final Map<String, String> inputs = new LinkedHashMap<>();
        for (int depth : new int[]{55}) {
            // digestAlgorithms parameters nested `depth` deep in the SignerInfo digestAlgorithm (unsigned, pre-trust)
            ASN1EncodableVector alg = new ASN1EncodableVector(); alg.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")); alg.add(nest(depth, new ASN1Integer(0)));
            ASN1Sequence si2 = replace(si, 2, new DERSequence(alg));
            ASN1Sequence sd2 = replace(sd, 4, new DERSet(si2));
            ASN1Sequence ci2 = replace(ci, 1, new DERTaggedObject(0, sd2));
            inputs.put("sigalg-params-nest-" + depth, Base64.getEncoder().encodeToString(ci2.getEncoded("DER")));
            // embedded cert-set: append an unsigned attribute with deep nesting, as a [0] certificate-slot extra (a nested SEQUENCE where a cert should be)
            ASN1Set certs = ASN1Set.getInstance((ASN1TaggedObject) sd.getObjectAt(3), false);
            ASN1EncodableVector cv = new ASN1EncodableVector(); for (int i = 0; i < certs.size(); i++) cv.add(certs.getObjectAt(i)); cv.add(nest(depth, new ASN1Integer(0)));
            ASN1Sequence sd3 = replace(sd, 3, new DERTaggedObject(false, 0, new DERSet(cv)));
            ASN1Sequence ci3 = replace(ci, 1, new DERTaggedObject(0, sd3));
            inputs.put("certbag-nest-" + depth, Base64.getEncoder().encodeToString(ci3.getEncoded("DER")));
        }
        Verifier v = Verifier.create(Config.defaults());
        for (int kb : new int[]{136, 144, 152, 160, 168, 176, 184}) {
            for (Map.Entry<String, String> e : inputs.entrySet()) {
                final String[] res = new String[1];
                Thread t = new Thread(null, () -> {
                    try { VerificationResult<ReceiptPayload> r = v.verifyReceipt(e.getValue()); res[0] = r.verified() ? "ok" : r.failure().reason().toString(); }
                    catch (Throwable th) { res[0] = "ESCAPED " + th.getClass().getName(); }
                }, "t", kb * 1024L);
                t.start(); t.join();
                System.out.println("stack=" + kb + "k " + e.getKey() + " -> " + res[0]);
            }
        }
    }
}
