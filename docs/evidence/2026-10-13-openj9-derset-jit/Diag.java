package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

/** Layer-by-layer self-checks, run inside the test JVM after a test class, to see what broke. */
public final class Diag {
    static int bad = 0;
    static Verifier early;

    static void check(String what, boolean ok, String detail) {
        if (!ok) bad++;
        System.out.println("  DIAG " + (ok ? "ok  " : "BAD ") + what + (ok ? "" : " :: " + detail));
    }

    public static void run(String tag) {
        bad = 0;
        System.out.println("DIAG-BEGIN " + tag);
        try {
            // 1. Digests.
            byte[] abc = "abc".getBytes("US-ASCII");
            String want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            SHA256Digest d = new SHA256Digest();
            d.update(abc, 0, 3);
            byte[] out = new byte[32];
            d.doFinal(out, 0);
            check("BC SHA256Digest(abc)", Hex.toHexString(out).equals(want), Hex.toHexString(out));
            byte[] big = new byte[1 << 20];
            for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 31 + 7);
            String jdk = Hex.toHexString(MessageDigest.getInstance("SHA-256", "SUN").digest(big));
            String bc = Hex.toHexString(MessageDigest.getInstance("SHA-256", BouncyCastle.PROVIDER).digest(big));
            check("SHA-256 1MiB BC == SUN", jdk.equals(bc), "sun=" + jdk + " bc=" + bc);
            String jdk1 = Hex.toHexString(MessageDigest.getInstance("SHA-1", "SUN").digest(big));
            String bc1 = Hex.toHexString(MessageDigest.getInstance("SHA-1", BouncyCastle.PROVIDER).digest(big));
            check("SHA-1 1MiB BC == SUN", jdk1.equals(bc1), "sun=" + jdk1 + " bc=" + bc1);

            // 2. BigInteger arithmetic: modPow against a square-and-multiply reference.
            BigInteger m = new BigInteger(
                    "c7f1a3b9e2d4568790abcdef1234567890fedcba0987654321abcdef0123456789abcdef0123456789abcdef"
                            + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
                    16);
            BigInteger b = new BigInteger("123456789abcdef0fedcba9876543210", 16);
            BigInteger e = BigInteger.valueOf(65537);
            BigInteger ref = BigInteger.ONE;
            BigInteger base = b.mod(m);
            for (int i = e.bitLength() - 1; i >= 0; i--) {
                ref = ref.multiply(ref).mod(m);
                if (e.testBit(i)) ref = ref.multiply(base).mod(m);
            }
            check("BigInteger.modPow == square-multiply", b.modPow(e, m).equals(ref), "");

            // 3. ASN.1 encoder known answers.
            byte[] seq = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                        new ASN1Integer(1), new DEROctetString(new byte[200]), new ASN1Integer(-129)
                    })
                    .getEncoded(ASN1Encoding.DER);
            String seqHex = Hex.toHexString(seq);
            check("DER SEQ{INT 1, OCTET[200], INT -129} header",
                    seqHex.startsWith("3081d2020101048200c8") || seqHex.startsWith("3081d2020101" + "0481c8"),
                    seqHex.substring(0, Math.min(40, seqHex.length())) + " len=" + seq.length);
            byte[] longOctets = new DEROctetString(new byte[70000]).getEncoded();
            check("DER OCTET[70000] header", Hex.toHexString(Arrays.copyOf(longOctets, 5)).equals("0483011170")
                    && longOctets.length == 70005,
                    Hex.toHexString(Arrays.copyOf(longOctets, 8)) + " len=" + longOctets.length);
            String setHex = Hex.toHexString(new org.bouncycastle.asn1.DERSet(new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                        new ASN1Integer(9999), new ASN1Integer(1), new DEROctetString(new byte[16])
                    })).getEncoded(ASN1Encoding.DER));
            check("DER SET{SEQ{9999,1,OCTET[16]}} == 311b3019...", setHex.startsWith("311b3019"), setHex.substring(0, 16));
            ASN1Primitive back = ASN1Primitive.fromByteArray(seq);
            check("DER round trip", Arrays.equals(back.getEncoded(ASN1Encoding.DER), seq), "");

            // 3b. A TestPki receipt, as UnauthenticatedKeyCostTest.signedData builds and parses it.
            try {
                byte[] receipt = TestPki.receipt().signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
                String dump = System.getProperty("diag.dump");
                if (dump != null) {
                    java.nio.file.Files.write(java.nio.file.Paths.get(dump + "-" + tag.replace(' ', '_') + ".der"), receipt);
                }
                try {
                    org.bouncycastle.asn1.cms.ContentInfo.getInstance(receipt);
                    check("TestPki receipt parses (len " + receipt.length + ")", true, "");
                } catch (Exception ex) {
                    check("TestPki receipt parses (len " + receipt.length + ")", false, ex + " / " + ex.getCause());
                }
            } catch (Throwable t) {
                check("TestPki receipt build", false, t.toString());
            }

            // 3c. Genuine sandbox receipts through a verifier built at the first
            // DIAG (before any failure) and through one built now with the
            // runtime probe off: does a broken JVM fail closed?
            String dir = System.getProperty("aprv.fixtures.dir") + "/public-receipts/";
            if (early == null) early = Verifier.create(Config.builder().build());
            Verifier late = Verifier.create(Config.builder().runtimeProbe(false).build());
            for (String name : new String[] {"receipt-sandbox-legacy.b64", "receipt-sandbox-g5.b64"}) {
                String b64 = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dir + name)), "US-ASCII").trim();
                VerificationResult<ReceiptPayload> ra = early.verifyReceipt(b64);
                VerificationResult<ReceiptPayload> rb = late.verifyReceipt(b64);
                check(name + " verifies (verifier built before / after)", ra.verified() && rb.verified(),
                        "before=" + (ra.verified() ? "verified" : ra.failure().reason()) + " after="
                                + (rb.verified() ? "verified" : rb.failure().reason()));
            }

            // 4a. Have the cached roots' bytes changed since the class loaded?
            String[] fields = {"APPLE_INC_ROOT", "APPLE_ROOT_CA_G2", "APPLE_ROOT_CA_G3"};
            int idx = 0;
            for (X509Certificate root : AppleRootCerts.roots()) {
                java.lang.reflect.Field f = AppleRootCerts.class.getDeclaredField(fields[idx++]);
                f.setAccessible(true);
                byte[] fresh = java.util.Base64.getDecoder().decode((String) f.get(null));
                byte[] cached = root.getEncoded();
                StringBuilder diffs = new StringBuilder();
                int n = 0;
                for (int i = 0; i < Math.min(fresh.length, cached.length); i++) {
                    if (fresh[i] != cached[i]) {
                        if (n < 24) diffs.append(String.format(" @%d:%02x->%02x", i, fresh[i] & 0xff, cached[i] & 0xff));
                        n++;
                    }
                }
                check(fields[idx - 1] + ": cached getEncoded() == bundled constant", n == 0 && fresh.length == cached.length,
                        "len " + fresh.length + "/" + cached.length + ", " + n + " bytes differ:" + diffs
                                + " | sig differs=" + !Arrays.equals(root.getSignature(),
                                        Certificate.getInstance(fresh).getSignature().getOctets())
                                + " tbs differs=" + !Arrays.equals(root.getTBSCertificate(),
                                        Certificate.getInstance(fresh).getTBSCertificate().getEncoded(ASN1Encoding.DER))
                                + " class=" + root.getClass().getName());
            }

            // 4. Apple roots: TBS re-encoding, raw RSA, and both providers.
            for (X509Certificate root : AppleRootCerts.roots()) {
                String cn = root.getSubjectX500Principal().getName().replaceAll(".*CN=([^,]+).*", "$1");
                Certificate c = Certificate.getInstance(root.getEncoded());
                byte[] tbsJdk = root.getTBSCertificate();
                byte[] tbsBc = c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
                check(cn + ": BC TBS re-encode == original", Arrays.equals(tbsJdk, tbsBc),
                        "orig len=" + tbsJdk.length + " bc len=" + tbsBc.length + " firstdiff="
                                + firstDiff(tbsJdk, tbsBc));
                byte[] whole = c.getEncoded(ASN1Encoding.DER);
                check(cn + ": BC cert re-encode == original", Arrays.equals(whole, root.getEncoded()),
                        "firstdiff=" + firstDiff(whole, root.getEncoded()));
                String alg = root.getSigAlgName();
                try {
                    Signature s = Signature.getInstance(alg, "SunRsaSign".equals(providerFor(alg)) ? "SunRsaSign" : "SunEC");
                    s.initVerify(root.getPublicKey());
                    s.update(tbsJdk);
                    check(cn + ": JDK " + alg + " verify(original TBS)", s.verify(root.getSignature()), "");
                } catch (Exception ex) {
                    check(cn + ": JDK verify", false, ex.toString());
                }
                try {
                    Signature s = Signature.getInstance(alg, BouncyCastle.PROVIDER);
                    s.initVerify(root.getPublicKey());
                    s.update(tbsJdk);
                    check(cn + ": BC " + alg + " verify(original TBS)", s.verify(root.getSignature()), "");
                } catch (Exception ex) {
                    check(cn + ": BC verify", false, ex.toString());
                }
                try {
                    root.verify(root.getPublicKey(), BouncyCastle.PROVIDER);
                    check(cn + ": X509Certificate.verify(BC) (probeRuntime)", true, "");
                } catch (Exception ex) {
                    check(cn + ": X509Certificate.verify(BC) (probeRuntime)", false, ex.toString());
                }
                if (alg.contains("RSA")) {
                    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(root.getPublicKey().getEncoded());
                    RSAPublicKey k = RSAPublicKey.getInstance(spki.parsePublicKey());
                    BigInteger em = new BigInteger(1, root.getSignature()).modPow(k.getPublicExponent(), k.getModulus());
                    byte[] emb = em.toByteArray();
                    String h = Hex.toHexString(emb);
                    String dig = Hex.toHexString(MessageDigest.getInstance(alg.startsWith("SHA1") ? "SHA-1"
                            : alg.startsWith("SHA384") ? "SHA-384" : alg.startsWith("SHA512") ? "SHA-512" : "SHA-256", "SUN")
                            .digest(tbsJdk));
                    check(cn + ": raw RSA (BigInteger.modPow) recovers PKCS#1 + digest",
                            (h.startsWith("1ffff") || h.startsWith("01ffff")) && h.endsWith(dig), "em=" + h.substring(0, 16) + "..." + h.substring(h.length() - 16));
                }
            }
        } catch (Throwable t) {
            check("diag threw", false, t.toString());
        }
        System.out.println("DIAG-END " + tag + " bad=" + bad);
    }

    static String providerFor(String alg) {
        return alg.contains("RSA") ? "SunRsaSign" : "SunEC";
    }

    static int firstDiff(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) if (a[i] != b[i]) return i;
        return a.length == b.length ? -1 : Math.min(a.length, b.length);
    }
}
