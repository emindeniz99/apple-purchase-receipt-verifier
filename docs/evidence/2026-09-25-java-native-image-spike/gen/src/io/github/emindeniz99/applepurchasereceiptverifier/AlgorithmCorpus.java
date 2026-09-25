package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Spike-only generator, compiled against the repository's test classes
 * (TestPki is package-private, hence this package). Prints JSON-lines
 * requests for OracleCli / run_native.py: receipts and JWS whose signer and
 * chain use signature algorithms the conformance fixtures do not, each under
 * its own generated root. The library's contract is "any signer algorithm
 * under the pinned chain" (ReceiptVerifier.verifyCmsSignature), so every
 * receipt here should verify on the JVM; the question is whether the native
 * image, built from traced metadata, agrees.
 *
 *   java -cp test-classes:verifier.jar:deps/*:this io.github...AlgorithmCorpus > algorithms.jsonl
 */
public final class AlgorithmCorpus {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String BUNDLE = "com.example.algorithms";

    public static void main(String[] args) throws Exception {
        // Generator only: lets TestPki's provider-less JcaContentSignerBuilder
        // reach BC's RIPEMD160withRSA and Ed25519. The verifier never sees it.
        java.security.Security.addProvider(TestPki.BC);
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        Instant creation = Instant.now().minusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.0", new byte[] {1, 2, 3, 4}, new byte[20], creation.toString(),
                Collections.<byte[]>emptyList());

        // --- receipts: {id, signer key, signer algorithm, chain algorithm}
        Object[][] receipts = {
            {"rsa-sha256", "RSA", "SHA256withRSA", "SHA256withRSA"},
            {"rsa-sha1", "RSA", "SHA1withRSA", "SHA256withRSA"},
            {"rsa-sha224", "RSA", "SHA224withRSA", "SHA256withRSA"},
            {"rsa-sha384", "RSA", "SHA384withRSA", "SHA256withRSA"},
            {"rsa-sha512", "RSA", "SHA512withRSA", "SHA256withRSA"},
            {"rsa-sha3-256", "RSA", "SHA3-256withRSA", "SHA256withRSA"},
            {"rsa-md5", "RSA", "MD5withRSA", "SHA256withRSA"},
            {"rsa-ripemd160", "RSA", "RIPEMD160withRSA", "SHA256withRSA"},
            {"rsa-pss-sha256", "RSA", "SHA256withRSAandMGF1", "SHA256withRSA"},
            {"ec-p256-sha256", "EC-P256", "SHA256withECDSA", "SHA256withRSA"},
            {"ec-p384-sha384", "EC-P384", "SHA384withECDSA", "SHA256withRSA"},
            {"ec-p521-sha512", "EC-P521", "SHA512withECDSA", "SHA256withRSA"},
            {"ed25519", "Ed25519", "Ed25519", "SHA256withRSA"},
            {"chain-rsa-sha512", "RSA", "SHA256withRSA", "SHA512withRSA"},
            {"chain-rsa-sha384", "RSA", "SHA256withRSA", "SHA384withRSA"},
            {"chain-rsa-pss", "RSA", "SHA256withRSA", "SHA256withRSAandMGF1"},
        };
        for (Object[] r : receipts) {
            KeyPair rootKp = keyPair("RSA");
            KeyPair interKp = keyPair("RSA");
            KeyPair signerKp = keyPair((String) r[1]);
            String chainAlg = (String) r[3];
            X509Certificate root = TestPki.cert("CN=Alg Root " + r[0], rootKp, "CN=Alg Root " + r[0],
                    rootKp.getPrivate(), true, null, notBefore, notAfter, chainAlg);
            X509Certificate inter = TestPki.cert("CN=Alg CA " + r[0], interKp, "CN=Alg Root " + r[0],
                    rootKp.getPrivate(), true, null, notBefore, notAfter, chainAlg);
            X509Certificate signer = TestPki.cert("CN=Alg Signer " + r[0], signerKp, "CN=Alg CA " + r[0],
                    interKp.getPrivate(), false, "1.2.840.113635.100.6.11.1", notBefore, notAfter, chainAlg);
            List<X509CertificateHolder> embedded = Arrays.asList(
                    new X509CertificateHolder(signer.getEncoded()), new X509CertificateHolder(inter.getEncoded()));
            byte[] der = TestPki.signReceiptAs(payload, Date.from(creation), signerKp.getPrivate(), (String) r[2],
                    new X509CertificateHolder(signer.getEncoded()), embedded);
            Map<String, Object> options = new LinkedHashMap<String, Object>();
            options.put("bundleId", BUNDLE);
            options.put("roots", Collections.singletonList(TestPki.b64(root.getEncoded())));
            emit("algorithms/receipt/" + r[0], "receipt", options, der, 0);
        }

        // --- JWS: ES256 leaf signature (the verifier requires it), chain algorithms vary
        Object[][] jws = {
            {"chain-ec-sha256", "EC-P256", "SHA256withECDSA"},
            {"chain-ec-p384-sha384", "EC-P384", "SHA384withECDSA"},
            {"chain-ec-p521-sha512", "EC-P521", "SHA512withECDSA"},
            {"chain-rsa-sha256", "RSA", "SHA256withRSA"},
            {"chain-rsa-sha512", "RSA", "SHA512withRSA"},
            {"chain-rsa-pss", "RSA", "SHA256withRSAandMGF1"},
        };
        long signedDate = System.currentTimeMillis() - 3_600_000L;
        for (Object[] j : jws) {
            KeyPair rootKp = keyPair((String) j[1]);
            KeyPair interKp = keyPair((String) j[1]);
            KeyPair leafKp = keyPair("EC-P256");
            String alg = (String) j[2];
            X509Certificate root = TestPki.cert("CN=JWS Root " + j[0], rootKp, "CN=JWS Root " + j[0],
                    rootKp.getPrivate(), true, null, notBefore, notAfter, alg);
            X509Certificate inter = TestPki.cert("CN=JWS CA " + j[0], interKp, "CN=JWS Root " + j[0],
                    rootKp.getPrivate(), true, "1.2.840.113635.100.6.2.1", notBefore, notAfter, alg);
            X509Certificate leaf = TestPki.cert("CN=JWS Leaf " + j[0], leafKp, "CN=JWS CA " + j[0],
                    interKp.getPrivate(), false, "1.2.840.113635.100.6.11.1", notBefore, notAfter, alg);
            Map<String, Object> header = new LinkedHashMap<String, Object>();
            header.put("alg", "ES256");
            header.put("x5c", Arrays.asList(
                    TestPki.b64(leaf.getEncoded()), TestPki.b64(inter.getEncoded()), TestPki.b64(root.getEncoded())));
            Map<String, Object> claims = new LinkedHashMap<String, Object>();
            claims.put("bundleId", "com.example.app");
            claims.put("environment", "Sandbox");
            claims.put("transactionId", "1");
            claims.put("signedDate", Long.valueOf(signedDate));
            String input = TestPki.b64url(JSON.writeValueAsBytes(header)) + "."
                    + TestPki.b64url(JSON.writeValueAsBytes(claims));
            Signature es256 = Signature.getInstance("SHA256withECDSA");
            es256.initSign(leafKp.getPrivate());
            es256.update(input.getBytes(StandardCharsets.US_ASCII));
            String token = input + "." + TestPki.b64url(p1363(es256.sign()));
            Map<String, Object> options = new LinkedHashMap<String, Object>();
            options.put("bundleId", "com.example.app");
            options.put("acceptedEnvironments", Collections.singletonList("Sandbox"));
            options.put("appAppleId", null);
            options.put("roots", Collections.singletonList(TestPki.b64(root.getEncoded())));
            emit("algorithms/jws/" + j[0], "jws", options, token.getBytes(StandardCharsets.US_ASCII), 0);
        }
    }

    private static KeyPair keyPair(String kind) throws Exception {
        if (kind.equals("RSA")) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        }
        if (kind.equals("Ed25519")) {
            return KeyPairGenerator.getInstance("Ed25519", TestPki.BC).generateKeyPair();
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(
                kind.equals("EC-P256") ? "secp256r1" : kind.equals("EC-P384") ? "secp384r1" : "secp521r1"));
        return g.generateKeyPair();
    }

    private static byte[] p1363(byte[] der) throws Exception {
        ASN1Sequence seq = ASN1Sequence.getInstance(new ASN1InputStream(der).readObject());
        byte[] out = new byte[64];
        pad(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(), out, 0);
        pad(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue(), out, 32);
        return out;
    }

    private static void pad(BigInteger v, byte[] out, int offset) {
        byte[] b = v.toByteArray();
        int start = b.length > 32 ? b.length - 32 : 0;
        int len = b.length - start;
        System.arraycopy(b, start, out, offset + 32 - len, len);
    }

    private static void emit(String id, String kind, Map<String, Object> options, byte[] input, int op)
            throws Exception {
        Map<String, Object> row = new LinkedHashMap<String, Object>();
        row.put("id", id);
        row.put("kind", kind);
        row.put("options", JSON.writeValueAsString(options));
        row.put("input", Base64.getEncoder().encodeToString(input));
        row.put("base64", Boolean.FALSE);
        row.put("guidHex", null);
        row.put("op", Integer.valueOf(op));
        System.out.println(JSON.writeValueAsString(row));
    }

    private AlgorithmCorpus() {}
}
