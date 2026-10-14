package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Disposable probe. Prints only labels, verdicts, byte counts and durations. */
public final class VendorProbe {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private static final long NOW = System.currentTimeMillis();
    private static int assertions;
    private static long serial;

    private static final class Pki {
        final List<X509Certificate> chain = new ArrayList<>(); // leaf first, root last
        final KeyPair leafKey;
        final Verifier verifier;

        Pki(int intermediateCount, int leafBits) throws Exception {
            KeyPair issuer = key(256);
            String issuerName = "CN=Probe Root";
            X509Certificate root = cert(issuerName, issuer, issuerName, issuer, true, null);
            chain.add(root);
            for (int i = 0; i < intermediateCount; i++) {
                KeyPair subject = key(256);
                String name = "CN=Probe CA " + i;
                chain.add(0, cert(name, subject, issuerName, issuer, true, AppleTrust.INTERMEDIATE_OID));
                issuer = subject;
                issuerName = name;
            }
            leafKey = key(leafBits);
            chain.add(0, cert("CN=Probe Leaf", leafKey, issuerName, issuer, false, AppleTrust.SIGNING_LEAF_OID));
            verifier = Verifier.create(Config.builder().roots(Collections.singleton(root))
                    .clock(Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC)).build());
            PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            params.setDate(new Date(NOW));
            CertPathValidator.getInstance("PKIX", BC).validate(
                    CertificateFactory.getInstance("X.509", BC).generateCertPath(
                            chain.subList(0, chain.size() - 1)), params);
            check(chain.get(0).getExtensionValue(AppleTrust.SIGNING_LEAF_OID) != null, "leaf marker");
            check(chain.get(1).getExtensionValue(AppleTrust.INTERMEDIATE_OID) != null, "issuer marker");
        }

        String jws(String alg, String jca, String payload, boolean includeRoot) throws Exception {
            StringBuilder header = new StringBuilder("{\"alg\":\"").append(alg).append("\",\"x5c\":[");
            int count = chain.size() - (includeRoot ? 0 : 1);
            for (int i = 0; i < count; i++) {
                if (i != 0) header.append(',');
                header.append('"').append(b64(chain.get(i).getEncoded())).append('"');
            }
            header.append("]}");
            String input = url(header.toString().getBytes(StandardCharsets.UTF_8)) + "."
                    + url(payload.getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance(jca, BC);
            signer.initSign(leafKey.getPrivate());
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(jca, BC);
            verifier.initVerify(leafKey.getPublic());
            verifier.update(input.getBytes(StandardCharsets.US_ASCII));
            check(verifier.verify(signature), "independent signature control");
            return input + "." + url(signature);
        }

        String cms(String algorithm) throws Exception {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(
                    new JcaContentSignerBuilder(algorithm).setProvider(BC).build(leafKey.getPrivate()),
                    new X509CertificateHolder(chain.get(0).getEncoded())));
            gen.addCertificates(new JcaCertStore(chain));
            return b64(gen.generate(new CMSProcessableByteArray(new DERSet().getEncoded()), true).getEncoded());
        }
    }

    private static KeyPair key(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", BC);
        gen.initialize(new ECGenParameterSpec(bits == 384 ? "secp384r1" : "secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, KeyPair key, String issuer, KeyPair issuerKey,
            boolean ca, String marker) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(++serial), new Date(NOW - 86400000L), new Date(NOW + 86400000L),
                new X500Name(subject), key.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (marker != null) b.addExtension(new ASN1ObjectIdentifier(marker), false, DERNull.INSTANCE);
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(
                new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(issuerKey.getPrivate())));
    }

    private static void check(boolean condition, String label) {
        assertions++;
        if (!condition) throw new AssertionError(label);
    }

    private static String b64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    private static String url(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }

    private static void result(String label, VerificationResult<?> result, boolean expected) {
        check(result.verified() == expected, label);
        if (!expected) {
            check(result.payload() == null, label + " no payload");
            check(result.failure().reason() != Reason.INTERNAL_ERROR, label + " no internal error");
            check(result.failure().reason() != Reason.UNREADABLE_PAYLOAD, label + " no payload alarm");
        }
        System.out.println(label + "=" + (result.verified() ? "VERIFIED" : result.failure().reason().name()));
    }

    private static String signature(String jws, byte[] bytes) {
        return jws.substring(0, jws.lastIndexOf('.') + 1) + url(bytes);
    }

    private static void invalidSignatures(Pki pki, String jws) {
        BigInteger n = ((java.security.interfaces.ECPublicKey) pki.leafKey.getPublic()).getParams().getOrder();
        BigInteger[] values = {BigInteger.ZERO, BigInteger.ONE, n.subtract(BigInteger.ONE), n};
        int rejected = 0;
        for (BigInteger r : values) for (BigInteger s : values) {
            byte[] raw = new byte[64];
            put(r, raw, 0);
            put(s, raw, 32);
            VerificationResult<?> result = pki.verifier.verifySignedData(signature(jws, raw));
            check(!result.verified() && result.payload() == null
                    && result.failure().reason() == Reason.INVALID_SIGNATURE, "ECDSA boundary");
            rejected++;
        }
        System.out.println("ecdsa_boundary_rejections=" + rejected);
    }

    private static void put(BigInteger value, byte[] output, int offset) {
        byte[] bytes = value.toByteArray();
        int count = Math.min(32, bytes.length);
        System.arraycopy(bytes, bytes.length - count, output, offset + 32 - count, count);
    }

    private static void scaling(Pki pki) throws Exception {
        for (int padding : new int[] {8192, 32768, 131072, 180000}) {
            char[] chars = new char[padding];
            Arrays.fill(chars, 'x');
            String token = pki.jws("ES256", "SHA256withPLAIN-ECDSA", "{\"padding\":\"" + new String(chars) + "\"}", true);
            byte[] sig = Base64.getUrlDecoder().decode(token.substring(token.lastIndexOf('.') + 1));
            sig[0] ^= 1;
            final String bad = signature(token, sig);
            for (int i = 0; i < 30; i++) check(!pki.verifier.verifySignedData(bad).verified(), "warm refusal");
            long start = System.nanoTime();
            for (int i = 0; i < 50; i++) {
                VerificationResult<?> r = pki.verifier.verifySignedData(bad);
                check(!r.verified() && r.failure().reason() == Reason.INVALID_SIGNATURE, "timed refusal");
            }
            System.out.printf(java.util.Locale.ROOT, "bad_jws_bytes=%d mean_ms=%.3f%n", bad.length(),
                    (System.nanoTime() - start) / 50000000.0);
        }
    }

    public static void main(String[] args) throws Exception {
        Pki regular = new Pki(1, 256);
        Pki stronger = new Pki(1, 384);
        Pki extraCa = new Pki(2, 256);
        String control = regular.jws("ES256", "SHA256withPLAIN-ECDSA", "{}", true);
        result("jws_es256_three_certs", regular.verifier.verifySignedData(control), true);
        result("jws_es256_without_root", regular.verifier.verifySignedData(
                regular.jws("ES256", "SHA256withPLAIN-ECDSA", "{}", false)), false);
        result("jws_es384_three_certs", stronger.verifier.verifySignedData(
                stronger.jws("ES384", "SHA384withPLAIN-ECDSA", "{}", true)), false);
        result("jws_es256_four_certs", extraCa.verifier.verifySignedData(
                extraCa.jws("ES256", "SHA256withPLAIN-ECDSA", "{}", true)), false);
        result("jws_es256_extra_ca_without_root", extraCa.verifier.verifySignedData(
                extraCa.jws("ES256", "SHA256withPLAIN-ECDSA", "{}", false)), false);
        result("cms_ecdsa_sha384", stronger.verifier.verifyReceipt(stronger.cms("SHA384withECDSA")), true);
        result("cms_ecdsa_extra_ca", extraCa.verifier.verifyReceipt(extraCa.cms("SHA256withECDSA")), true);
        Verifier apple = Verifier.create(Config.defaults());
        result("foreign_jws_default_roots", apple.verifySignedData(control), false);
        result("foreign_cms_default_roots", apple.verifyReceipt(regular.cms("SHA256withECDSA")), false);
        result("jws_wrong_pinned_root", stronger.verifier.verifySignedData(control), false);
        String[] parts = control.split("\\.");
        result("jws_header_tamper", regular.verifier.verifySignedData(
                url(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8)
                        .replace("\"ES256\"", "\"ES256\",\"extra\":true").getBytes(StandardCharsets.UTF_8))
                        + "." + parts[1] + "." + parts[2]), false);
        result("jws_payload_tamper", regular.verifier.verifySignedData(parts[0] + "."
                + url("{\"extra\":true}".getBytes(StandardCharsets.UTF_8)) + "." + parts[2]), false);
        invalidSignatures(regular, control);
        scaling(regular);
        for (String file : new String[] {"receipt-sandbox-legacy.b64", "receipt-sandbox-g5.b64"}) {
            String receipt = new String(Files.readAllBytes(Paths.get(args[0], "fixtures", "public-receipts", file)),
                    StandardCharsets.US_ASCII).trim();
            result(file + "_control", apple.verifyReceipt(receipt), true);
        }
        System.out.println("assertions=" + assertions);
    }
}
