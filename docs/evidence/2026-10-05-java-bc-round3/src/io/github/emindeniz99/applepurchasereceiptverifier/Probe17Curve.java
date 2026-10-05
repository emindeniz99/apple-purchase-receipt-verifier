package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Probe17: ES256 JWS whose leaf key is not on P-256 (32-byte-order curves, 64-byte raw signatures). */
public class Probe17Curve {
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        Provider bc = new BouncyCastleProvider();
        Date from = new Date(System.currentTimeMillis() - 86400000L), to = new Date(System.currentTimeMillis() + 86400000L * 365);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair rk = g.generateKeyPair(), ik = g.generateKeyPair();
        X509Certificate root = TestPki.cert("CN=Curve Root", rk, "CN=Curve Root", rk.getPrivate(), true, null, from, to, "SHA256withECDSA");
        X509Certificate inter = TestPki.cert("CN=Curve WWDR", ik, "CN=Curve Root", rk.getPrivate(), true, "1.2.840.113635.100.6.2.1", from, to, "SHA256withECDSA");
        Files.write(out.resolve("root.der"), root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
        for (String curve : new String[]{"secp256r1", "secp256k1", "brainpoolP256r1", "secp384r1"}) {
            KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", bc); kg.initialize(new ECGenParameterSpec(curve)); KeyPair lk = kg.generateKeyPair();
            X509Certificate leaf = TestPki.cert("CN=Curve Leaf " + curve, lk, "CN=Curve WWDR", ik.getPrivate(), false, "1.2.840.113635.100.6.11.1", from, to, "SHA256withECDSA");
            String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(leaf.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(inter.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(root.getEncoded()) + "\"]}";
            String payload = "{\"signedDate\":" + System.currentTimeMillis() + ",\"environment\":\"Sandbox\"}";
            String input = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            Signature s = Signature.getInstance("SHA256withPLAIN-ECDSA", bc); s.initSign(lk.getPrivate()); s.update(input.getBytes(StandardCharsets.US_ASCII));
            byte[] sig = s.sign();
            String jws = input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
            String name = "curve-" + curve;
            Files.write(out.resolve(name + ".jws"), jws.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(jws);
            System.out.println("JAVA " + name + " (sig " + sig.length + " bytes): " + (r.verified() ? "ok" : r.failure().reason()));
        }
    }
}
