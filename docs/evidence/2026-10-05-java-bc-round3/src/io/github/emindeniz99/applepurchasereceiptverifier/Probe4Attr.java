package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.asn1.*;

/** Probe4: genuinely signed (test PKI) receipts whose attribute envelope shape is defective. */
public class Probe4Attr {
    static Path out; static Verifier v; static TestPki pki;
    static ASN1Encodable attr(ASN1Encodable type, ASN1Encodable version, ASN1Encodable value) {
        return new DERSequence(new ASN1Encodable[] {type, version, value});
    }
    static ASN1Encodable good(int t, byte[] v) { return attr(new ASN1Integer(t), new ASN1Integer(1), new DEROctetString(v)); }
    static void emit(String name, ASN1Encodable... attrs) throws Exception {
        byte[] payload = new DERSet(attrs).getEncoded();
        byte[] rec = pki.signReceipt(payload);
        String b64 = Base64.getEncoder().encodeToString(rec);
        Files.write(out.resolve(name + ".b64"), b64.getBytes(StandardCharsets.US_ASCII));
        VerificationResult<ReceiptPayload> r = v.verifyReceipt(b64);
        System.out.println("JAVA " + name + ": " + (r.verified() ? "ok " + r.payload().toJson().substring(0, 60) : r.failure().reason()));
    }
    public static void main(String[] a) throws Exception {
        out = Paths.get(a[0]); Files.createDirectories(out);
        pki = TestPki.receipt();
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        ASN1Encodable date = good(12, new DERIA5String(java.time.Instant.now().minusSeconds(3600).toString().substring(0,19) + "Z").getEncoded());
        ASN1Encodable bundle = good(2, new DERUTF8String("com.example.app").getEncoded());
        emit("a0-baseline", date, bundle);
        ASN1Integer two = new ASN1Integer(2);
        emit("a1-version-utf8", date, attr(two, new DERUTF8String("1"), new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a2-version-null", date, attr(two, DERNull.INSTANCE, new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a3-version-bool", date, attr(two, ASN1Boolean.TRUE, new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a4-version-huge", date, attr(two, new ASN1Integer(BigInteger.ONE.shiftLeft(200)), new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a5-version-negative", date, attr(two, new ASN1Integer(-5), new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a6-version-octets", date, attr(two, new DEROctetString(new byte[]{1}), new DEROctetString(new DERUTF8String("com.x").getEncoded())));
        emit("a7-version-before-date", attr(two, new DERUTF8String("1"), new DEROctetString(new DERUTF8String("com.x").getEncoded())), date);
        emit("a8-type-is-oid", date, attr(new ASN1ObjectIdentifier("1.2.3"), new ASN1Integer(1), new DEROctetString(new byte[]{1})));
        emit("a9-value-utf8-not-octet", date, attr(two, new ASN1Integer(1), new DERUTF8String("com.x")));
        emit("a10-attr-is-set", date, new DERSet(new ASN1Encodable[]{two, new ASN1Integer(1), new DEROctetString(new byte[]{1})}));
        emit("a11-attr-only-two-fields", date, new DERSequence(new ASN1Encodable[]{two, new ASN1Integer(1)}));
        emit("a12-attr-is-integer", date, new ASN1Integer(7));
        emit("a13-attr-after-date-bad", date, attr(two, new DERUTF8String("1"), new DEROctetString(new byte[]{1})), bundle);
    }
}
