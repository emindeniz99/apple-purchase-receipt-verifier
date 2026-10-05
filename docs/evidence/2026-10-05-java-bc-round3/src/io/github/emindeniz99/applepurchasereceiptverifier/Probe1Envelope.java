package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.asn1.*;

/** Probe1: Apple-signed public sandbox receipt with unsigned envelope fields altered. */
public class Probe1Envelope {
    static Path out;
    static Verifier v = Verifier.create(Config.defaults());

    static ASN1Sequence replace(ASN1Sequence s, int idx, ASN1Encodable e) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < s.size(); i++) vec.add(i == idx ? e : s.getObjectAt(i));
        return new DLSequence(vec);
    }

    static void emit(String name, ASN1Encodable root) throws Exception {
        byte[] der = root.toASN1Primitive().getEncoded("DER");
        String b64 = Base64.getEncoder().encodeToString(der);
        Files.write(out.resolve(name + ".b64"), b64.getBytes(StandardCharsets.US_ASCII));
        VerificationResult<ReceiptPayload> r = v.verifyReceipt(b64);
        System.out.println("JAVA " + name + ": " + (r.verified() ? "ok" : r.failure().reason()));
    }

    public static void main(String[] a) throws Exception {
        out = Paths.get(a[0]);
        Files.createDirectories(out);
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        byte[] der = Base64.getDecoder().decode(src);
        ASN1Sequence ci = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        ASN1TaggedObject tag = (ASN1TaggedObject) ci.getObjectAt(1);
        ASN1Sequence sd = ASN1Sequence.getInstance(tag.getBaseObject());
        for (int i = 0; i < sd.size(); i++) System.out.println("sd[" + i + "] " + sd.getObjectAt(i).getClass().getSimpleName());
        emit("m0-unchanged", ci);
        // M1 outer content type
        emit("m1-outer-oid-data", replace(ci, 0, new ASN1ObjectIdentifier("1.2.840.113549.1.7.1")));
        emit("m1b-outer-oid-bogus", replace(ci, 0, new ASN1ObjectIdentifier("1.2.3.4")));
        // M2 version
        emit("m2-version-0", wrapSd(ci, replace(sd, 0, new ASN1Integer(0))));
        emit("m2b-version-99", wrapSd(ci, replace(sd, 0, new ASN1Integer(99))));
        // M3 digestAlgorithms empty
        emit("m3-digestalgs-empty", wrapSd(ci, replace(sd, 1, new DERSet())));
        // M4 encap content type
        ASN1Sequence enc = (ASN1Sequence) sd.getObjectAt(2);
        emit("m4-econtent-type-bogus", wrapSd(ci, replace(sd, 2, replace(enc, 0, new ASN1ObjectIdentifier("1.2.3.4")))));
        // M5 SignerInfo version
        ASN1Set sis = (ASN1Set) sd.getObjectAt(sd.size() - 1);
        ASN1Sequence si = (ASN1Sequence) sis.getObjectAt(0);
        emit("m5-signerinfo-version-7", wrapSd(ci, replace(sd, sd.size() - 1, new DERSet(replace(si, 0, new ASN1Integer(7))))));
        // M6 digestAlgorithms lists only sha512 (signer uses other)
        ASN1EncodableVector alg = new ASN1EncodableVector();
        alg.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3"));
        emit("m6-digestalgs-sha512-only", wrapSd(ci, replace(sd, 1, new DERSet(new DERSequence(alg)))));
        // M7 signatureAlgorithm label changed to sha256WithRSA while digestAlgorithm sha1
        System.out.println("si fields: " + si.size());
        for (int i = 0; i < si.size(); i++) System.out.println(" si[" + i + "] " + si.getObjectAt(i));
        ASN1EncodableVector sa = new ASN1EncodableVector();
        sa.add(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")); sa.add(DERNull.INSTANCE);
        emit("m7-sigalg-label-sha256rsa", wrapSd(ci, replace(sd, sd.size() - 1, new DERSet(replace(si, si.size() - 2, new DERSequence(sa))))));
        // M8 sigalg label = ecdsa
        ASN1EncodableVector sb = new ASN1EncodableVector();
        sb.add(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
        emit("m8-sigalg-label-ecdsa", wrapSd(ci, replace(sd, sd.size() - 1, new DERSet(replace(si, si.size() - 2, new DERSequence(sb))))));
        // M9 sigalg label = pkcs1 rsaEncryption (1.2.840.113549.1.1.1)
        ASN1EncodableVector sc = new ASN1EncodableVector();
        sc.add(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1")); sc.add(DERNull.INSTANCE);
        emit("m9-sigalg-label-rsaEncryption", wrapSd(ci, replace(sd, sd.size() - 1, new DERSet(replace(si, si.size() - 2, new DERSequence(sc))))));
    }

    static ASN1Encodable wrapSd(ASN1Sequence ci, ASN1Sequence newSd) {
        return replace(ci, 1, new DERTaggedObject(0, newSd));
    }
}
