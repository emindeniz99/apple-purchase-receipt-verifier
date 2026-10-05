package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Probe18: certificate profile variants on the JWS chain (all genuinely signed by the pinned root/intermediate). */
public class Probe18Profile {
    static KeyPair ec() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); return g.generateKeyPair(); }
    static long serial = 1000;
    interface Ext { void apply(X509v3CertificateBuilder b) throws Exception; }
    static X509Certificate cert(String subj, KeyPair kp, String issuer, PrivateKey ik, Ext ext) throws Exception {
        Date from = new Date(System.currentTimeMillis() - 86400000L), to = new Date(System.currentTimeMillis() + 86400000L * 365);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(serial++), from, to, new X500Name(subj), kp.getPublic());
        ext.apply(b);
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withECDSA").build(ik);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }
    static String jws(X509Certificate leaf, X509Certificate inter, X509Certificate root, PrivateKey lk) throws Exception {
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(leaf.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(inter.getEncoded()) + "\",\"" + Base64.getEncoder().encodeToString(root.getEncoded()) + "\"]}";
        String payload = "{\"signedDate\":" + System.currentTimeMillis() + ",\"environment\":\"Sandbox\"}";
        String input = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(lk); s.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(Probe16Anchor.p1363(s.sign()));
    }
    static final ASN1ObjectIdentifier LEAF = new ASN1ObjectIdentifier("1.2.840.113635.100.6.11.1"), INTER = new ASN1ObjectIdentifier("1.2.840.113635.100.6.2.1");
    public static void main(String[] a) throws Exception {
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        KeyPair rk = ec(), ik = ec(), lk = ec();
        X509Certificate root = cert("CN=Prof Root", rk, "CN=Prof Root", rk.getPrivate(), b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)); });
        Files.write(out.resolve("root.der"), root.getEncoded());
        Verifier v = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
        JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
        Map<String, Ext> interExt = new LinkedHashMap<>(), leafExt = new LinkedHashMap<>();
        Ext okInter = b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)); b.addExtension(INTER, false, DERNull.INSTANCE); };
        Ext okLeaf = b -> b.addExtension(LEAF, false, DERNull.INSTANCE);
        List<String[]> rows = new ArrayList<>();
        // name, inter ext, leaf ext
        Map<String, Object[]> cases = new LinkedHashMap<>();
        cases.put("p0-baseline", new Object[]{okInter, okLeaf});
        cases.put("p1-inter-no-basicconstraints-but-keycertsign", new Object[]{(Ext) b -> { b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE); }, okLeaf});
        cases.put("p2-leaf-akid-mismatch", new Object[]{okInter, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20})); }});
        cases.put("p3-inter-has-skid-leaf-akid-other", new Object[]{(Ext) b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE); b.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new byte[]{9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9})); }, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new byte[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1})); }});
        cases.put("p4-inter-critical-policies-with-qualifier", new Object[]{(Ext) b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE);
            b.addExtension(Extension.certificatePolicies, true, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4"), new DERSequence(new PolicyQualifierInfo("https://example.com/cps"))))); }, okLeaf});
        cases.put("p5-inter-policyconstraints-require-explicit-0", new Object[]{(Ext) b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE);
            b.addExtension(Extension.policyConstraints, true, new DERSequence(new DERTaggedObject(false, 0, new ASN1Integer(0)))); }, okLeaf});
        cases.put("p6-leaf-is-ca-pathlen-0", new Object[]{okInter, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0)); }});
        cases.put("p7-leaf-unknown-critical-ext", new Object[]{okInter, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(new ASN1ObjectIdentifier("1.2.3.4.5"), true, DERNull.INSTANCE); }});
        cases.put("p8-leaf-marker-critical", new Object[]{okInter, (Ext) b -> b.addExtension(LEAF, true, DERNull.INSTANCE)});
        cases.put("p9-leaf-keyusage-keycertsign-only", new Object[]{okInter, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); }});
        cases.put("p10-leaf-eku-serverauth-only", new Object[]{okInter, (Ext) b -> { b.addExtension(LEAF, false, DERNull.INSTANCE); b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)); }});
        cases.put("p11-inter-eku-codesigning-only", new Object[]{(Ext) b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE); b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning)); }, okLeaf});
        cases.put("p12-inter-nameconstraints-exclude-leaf-cn", new Object[]{(Ext) b -> { b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign)); b.addExtension(INTER, false, DERNull.INSTANCE);
            b.addExtension(Extension.nameConstraints, true, new NameConstraints(null, new GeneralSubtree[]{new GeneralSubtree(new GeneralName(GeneralName.directoryName, new X500Name("CN=Prof Leaf")))})); }, okLeaf});
        for (Map.Entry<String, Object[]> e : cases.entrySet()) {
            KeyPair ik2 = ec();
            X509Certificate inter = cert("CN=Prof WWDR", ik2, "CN=Prof Root", rk.getPrivate(), (Ext) e.getValue()[0]);
            KeyPair lk2 = ec();
            X509Certificate leaf = cert("CN=Prof Leaf", lk2, "CN=Prof WWDR", ik2.getPrivate(), (Ext) e.getValue()[1]);
            String j = jws(leaf, inter, root, lk2.getPrivate());
            Files.write(out.resolve(e.getKey() + ".jws"), j.getBytes(StandardCharsets.US_ASCII));
            VerificationResult<JsonPayload> r = v.verifySignedData(j);
            System.out.println("JAVA " + e.getKey() + ": " + (r.verified() ? "ok" : r.failure().reason()));
        }
    }
}
