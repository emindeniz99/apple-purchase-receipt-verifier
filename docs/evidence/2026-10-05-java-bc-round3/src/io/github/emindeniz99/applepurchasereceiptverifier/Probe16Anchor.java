package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/** Probe16: trust anchor (root) validity window vs the chain instant: root expired at signedDate, rest valid. */
public class Probe16Anchor {
    static KeyPair ec() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); return g.generateKeyPair(); }
    public static byte[] p1363(byte[] der) throws Exception { org.bouncycastle.asn1.ASN1Sequence s = org.bouncycastle.asn1.ASN1Sequence.getInstance(der); byte[] out = new byte[64]; for (int i = 0; i < 2; i++) { byte[] b = org.bouncycastle.asn1.ASN1Integer.getInstance(s.getObjectAt(i)).getValue().toByteArray(); int o = b.length > 32 ? b.length - 32 : 0; int l = b.length - o; System.arraycopy(b, o, out, i * 32 + 32 - l, l); } return out; }
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        Date from = new Date(1577836800000L);      // 2020-01-01
        Date rootTo = new Date(1893456000000L);    // 2030-01-01
        Date restTo = new Date(2208988800000L);    // 2040-01-01
        KeyPair rk = ec(), ik = ec(), lk = ec();
        X509Certificate root = TestPki.cert("CN=Anchor Test Root", rk, "CN=Anchor Test Root", rk.getPrivate(), true, null, from, rootTo, "SHA256withECDSA");
        X509Certificate inter = TestPki.cert("CN=Anchor Test WWDR", ik, "CN=Anchor Test Root", rk.getPrivate(), true, "1.2.840.113635.100.6.2.1", from, restTo, "SHA256withECDSA");
        X509Certificate leaf = TestPki.cert("CN=Anchor Test Leaf", lk, "CN=Anchor Test WWDR", ik.getPrivate(), false, "1.2.840.113635.100.6.11.1", from, restTo, "SHA256withECDSA");
        Files.write(out.resolve("root.der"), root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
        long[] dates = {1704067200000L /*2024*/, 2024000000000L /*2034-06*/, 2051222400000L /*2035-01-01+*/};
        // 2034 is after the root's 2030 expiry
        for (long signed : new long[]{1704067200000L, 1950000000000L}) {
            String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(leaf.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(inter.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(root.getEncoded()) + "\"]}";
            String payload = "{\"signedDate\":" + signed + ",\"environment\":\"Sandbox\"}";
            String input = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(lk.getPrivate()); s.update(input.getBytes(StandardCharsets.US_ASCII));
            String jws = input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(p1363(s.sign()));
            String name = "anchor-signed-" + signed;
            Files.write(out.resolve(name + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(jws);
            System.out.println("JAVA " + name + " (root notAfter 2030-01-01): " + (r.verified() ? "ok" : r.failure().reason()));
        }
    }
}
