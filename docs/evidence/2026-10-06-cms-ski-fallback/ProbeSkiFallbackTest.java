package io.github.emindeniz99.applepurchasereceiptverifier;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.junit.jupiter.api.Test;

/**
 * Writes probe-rfc.der and probe-ms.der (with their roots) into the
 * directory named by -Dprobe.out and prints Java's verdict on each. See
 * README.md beside this file.
 */
class ProbeSkiFallbackTest {
    @Test
    void probe() throws Exception {
        String out = System.getProperty("probe.out");
        run(out, "rfc", false);
        run(out, "ms", true);
    }

    private static void run(String out, String tag, boolean outlookKeyId) throws Exception {
        StandardShapeFixtures f = new StandardShapeFixtures();
        Class<?> c = StandardShapeFixtures.class;
        Method keys = c.getDeclaredMethod("keys", String.class);
        Method inter = c.getDeclaredMethod("intermediate", KeyPair.class, Extension.class);
        Method cert = c.getDeclaredMethod(
                "certificate",
                String.class,
                KeyPair.class,
                String.class,
                PrivateKey.class,
                Date.class,
                boolean.class,
                String.class,
                Extension.class);
        Method signer = c.getDeclaredMethod("signer", PrivateKey.class);
        Method receipt = c.getDeclaredMethod(
                "receipt", KeyPair.class, X509CertificateHolder.class, byte[].class, Date.class, List.class);
        for (Method m : new Method[] {keys, inter, cert, signer, receipt}) {
            m.setAccessible(true);
        }
        KeyPair interKeys = (KeyPair) keys.invoke(null, "RSA");
        X509CertificateHolder in = (X509CertificateHolder) inter.invoke(f, interKeys, null);
        KeyPair leafKeys = (KeyPair) keys.invoke(null, "RSA");
        byte[] keyId = outlookKeyId
                ? MessageDigest.getInstance("SHA-1").digest(leafKeys.getPublic().getEncoded())
                : new JcaX509ExtensionUtils()
                        .createSubjectKeyIdentifier(leafKeys.getPublic())
                        .getKeyIdentifier();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Standard WWDR CA"),
                BigInteger.valueOf(9999),
                new Date(1704067200000L),
                new Date(1717200000000L),
                new X500Name("CN=Standard Receipt Signing"),
                leafKeys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyId));
        b.addExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.6.11.1"), false, DERNull.INSTANCE);
        X509CertificateHolder expired = b.build((ContentSigner) signer.invoke(null, interKeys.getPrivate()));
        X509CertificateHolder renewedNoSki = (X509CertificateHolder) cert.invoke(
                f,
                "CN=Standard Receipt Signing",
                leafKeys,
                "CN=Standard WWDR CA",
                interKeys.getPrivate(),
                new Date(1717200000000L),
                false,
                "1.2.840.113635.100.6.11.1",
                null);
        if (renewedNoSki.getExtension(Extension.subjectKeyIdentifier) != null) {
            throw new AssertionError("has SKI");
        }
        byte[] r = (byte[]) receipt.invoke(
                null,
                leafKeys,
                null,
                keyId,
                null,
                Arrays.<ASN1Encodable>asList(
                        expired.toASN1Structure(), renewedNoSki.toASN1Structure(), in.toASN1Structure()));
        Files.write(Paths.get(out, "probe-" + tag + ".der"), r);
        Files.write(Paths.get(out, "probe-" + tag + "-root.der"), f.receiptRoot.getEncoded());
        X509Certificate root = new JcaX509CertificateConverter().getCertificate(f.receiptRoot);
        try {
            Checks.receipt(Checks.verifier(root), r);
            System.out.println("PROBE java " + tag + ": ok");
        } catch (VerificationException e) {
            System.out.println("PROBE java " + tag + ": " + e.reason());
        }
    }
}
