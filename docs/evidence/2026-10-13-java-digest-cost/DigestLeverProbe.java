package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;

/**
 * args: mode (sweep|cold|warm) digestOid signerInfos [valueBytes]
 * Keyless: the SignerInfos name the test PKI's genuine leaf but are signed by an unrelated key.
 */
public class DigestLeverProbe {
  static final int CAP_DER = 3145728 / 4 * 3;

  static byte[] build(TestPki pki, KeyPair attacker, String oid, int count, int value) throws Exception {
    byte[] payload = TestPki.singleAttributePayload(9999, new byte[value]);
    X509CertificateHolder leaf = new X509CertificateHolder(pki.leaf.getEncoded());
    X509CertificateHolder inter = new X509CertificateHolder(pki.intermediate.getEncoded());
    ASN1EncodableVector attrs = new ASN1EncodableVector();
    attrs.add(new org.bouncycastle.asn1.cms.Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(TestPki.BC).build(attacker.getPrivate());
    for (int i = 0; i < count; i++) {
      gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build())
          .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attrs)))
          .setContentDigest(new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)))
          .build(cs, leaf));
    }
    gen.addCertificates(new CollectionStore<X509CertificateHolder>(Arrays.asList(leaf, inter)));
    return gen.generate(new CMSProcessableByteArray(payload), true).getEncoded("DER");
  }

  static byte[] atCap(TestPki pki, KeyPair attacker, String oid, int count) throws Exception {
    byte[] small = build(pki, attacker, oid, count, 1000);
    int overhead = small.length - 1000 + 16;
    int value = CAP_DER - overhead;
    byte[] der = build(pki, attacker, oid, count, value);
    value -= der.length - CAP_DER + 16;
    der = build(pki, attacker, oid, count, value);
    if (der.length > CAP_DER) throw new IllegalStateException("over cap " + der.length);
    return der;
  }

  public static void main(String[] a) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048);
    KeyPair attacker = g.generateKeyPair();
    TestPki pki = TestPki.receipt();
    Verifier v = Checks.verifier(pki);
    String mode = a[0];
    int count = Integer.parseInt(a[2]);
    for (String oid : a[1].split(",")) {
      byte[] der;
      try { der = atCap(pki, attacker, oid, count); } catch (Exception e) { System.out.println(oid + " cannot build: " + e); continue; }
      String b64 = Base64.getEncoder().encodeToString(der);
      int runs = mode.equals("cold") ? 1 : 6;
      long best = Long.MAX_VALUE, first = 0; String verdict = "";
      for (int i = 0; i < runs; i++) {
        long t = System.nanoTime();
        VerificationResult<ReceiptPayload> r = v.verifyReceipt(b64);
        long ms = (System.nanoTime() - t) / 1_000_000;
        if (i == 0) first = ms;
        if (i > 0 || runs == 1) best = Math.min(best, ms);
        verdict = r.failure() == null ? "ACCEPTED" : r.failure().reason() + " / " + r.failure().message()
            + (r.failure().cause() != null ? " / " + r.failure().cause() : "");
      }
      System.out.printf("%s n=%d b64=%d first=%d ms best-warm=%d ms [%s]%n", oid, count, b64.length(), first, best, verdict);
    }
  }
}
