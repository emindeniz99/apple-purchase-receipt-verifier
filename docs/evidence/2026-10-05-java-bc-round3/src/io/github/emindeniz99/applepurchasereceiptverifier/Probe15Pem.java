package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;

/** Probe15: x5c entries that are PEM text or a PKCS#7 certs-only bundle rather than a DER certificate. */
public class Probe15Pem {
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        TestPki pki = TestPki.jws();
        Files.write(out.resolve("root.der"), pki.root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        String payload = "{\"signedDate\":" + System.currentTimeMillis() + ",\"environment\":\"Sandbox\"}";
        byte[] L = pki.leaf.getEncoded(), I = pki.intermediate.getEncoded(), R = pki.root.getEncoded();
        byte[] leafPem = ("-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(L) + "\n-----END CERTIFICATE-----\n").getBytes(StandardCharsets.US_ASCII);
        // certs-only PKCS#7 holding the leaf
        ASN1EncodableVector certs = new ASN1EncodableVector(); certs.add(ASN1Primitive.fromByteArray(L));
        SignedData sd = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(certs), null, new DERSet());
        byte[] p7 = new ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded("DER");
        Map<String, List<byte[]>> variants = new LinkedHashMap<>();
        variants.put("u1-leaf-as-pem", Arrays.asList(leafPem, I, R));
        variants.put("u2-leaf-as-pkcs7-certs-only", Arrays.asList(p7, I, R));
        for (Map.Entry<String, List<byte[]>> e : variants.entrySet()) {
            List<String> x = new ArrayList<>(); for (byte[] c : e.getValue()) x.add(b64(c));
            String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + String.join("\",\"", x) + "\"]}";
            String jws = pki.signJwsWithHeader(header, payload);
            Files.write(out.resolve(e.getKey() + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(jws);
            System.out.println("JAVA " + e.getKey() + ": " + (r.verified() ? "ok" : r.failure().reason() + " / " + r.failure().message()));
        }
    }
}
