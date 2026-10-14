package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic keys stay in memory. Output contains verdicts, counts and durations only. */
public final class VendorReviewProbe {
    private static final Date AT = new Date();
    private static int serial = 1;
    private static int assertions;
    private static int negativeChecks;

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastle.PROVIDER);
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static X500Name name(String value) {
        return name(new DERPrintableString(value));
    }

    private static X500Name name(ASN1Encodable value) {
        return new X500Name(new RDN[] {new RDN(BCStyle.CN, value)});
    }

    private static X509Certificate certificate(X500Name subject, KeyPair key,
            X500Name issuer, KeyPair issuerKey, boolean ca, String marker) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(serial++), new Date(AT.getTime() - 86400000L),
                new Date(AT.getTime() + 86400000L), subject, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (marker != null) {
            builder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier(marker), false, DERNull.INSTANCE);
        }
        return new JcaX509CertificateConverter().setProvider(BouncyCastle.PROVIDER).getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastle.PROVIDER).build(issuerKey.getPrivate())));
    }

    private static final class Pki {
        final KeyPair rootKey = ec("secp256r1");
        final KeyPair intermediateKey = ec("secp256r1");
        final KeyPair leafKey;
        final X509Certificate root;
        final List<X509Certificate> path = new ArrayList<>();
        final Verifier verifier;

        Pki(String curve, boolean extraCa, boolean intermediateCa, boolean leafMarker,
                X500Name intermediateSubject, X500Name leafIssuer) throws Exception {
            leafKey = ec(curve);
            X500Name rootName = name("Review Root");
            root = certificate(rootName, rootKey, rootName, rootKey, true, null);
            KeyPair issuerKey = rootKey;
            X500Name issuer = rootName;
            X509Certificate upper = null;
            if (extraCa) {
                issuerKey = ec("secp256r1");
                issuer = name("Review Upper CA");
                upper = certificate(issuer, issuerKey, rootName, rootKey, true, null);
            }
            X509Certificate intermediate = certificate(intermediateSubject, intermediateKey,
                    issuer, issuerKey, intermediateCa, AppleTrust.INTERMEDIATE_OID);
            X509Certificate leaf = certificate(name("Review Leaf"), leafKey, leafIssuer,
                    intermediateKey, false, leafMarker ? AppleTrust.SIGNING_LEAF_OID : null);
            path.add(leaf);
            path.add(intermediate);
            if (upper != null) {
                path.add(upper);
            }
            verifier = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
        }

        Pki(String curve, boolean extraCa) throws Exception {
            this(curve, extraCa, true, true, name("Review Intermediate"), name("Review Intermediate"));
        }

        boolean pkix() throws Exception {
            CertPath certPath = CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER)
                    .generateCertPath(path);
            PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            params.setDate(AT);
            params.addCertPathChecker(AppleTrust.HANDLED_CRITICAL_EXTENSIONS);
            try {
                CertPathValidator.getInstance("PKIX", BouncyCastle.PROVIDER).validate(certPath, params);
                return true;
            } catch (java.security.GeneralSecurityException e) {
                return false;
            }
        }

        String token(String alg, String signatureName, boolean includeRoot) throws Exception {
            List<X509Certificate> carried = new ArrayList<>(path);
            if (includeRoot) {
                carried.add(root);
            }
            StringBuilder header = new StringBuilder("{\"alg\":\"").append(alg).append("\",\"x5c\":[");
            for (X509Certificate cert : carried) {
                if (header.charAt(header.length() - 1) != '[') {
                    header.append(',');
                }
                header.append('"').append(Base64.getEncoder().encodeToString(cert.getEncoded())).append('"');
            }
            header.append("]}");
            String input = url(header.toString().getBytes(StandardCharsets.UTF_8)) + "."
                    + url("{\"probe\":true}".getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance(signatureName, BouncyCastle.PROVIDER);
            signer.initSign(leafKey.getPrivate());
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            byte[] signature = signer.sign();
            Signature checker = Signature.getInstance(signatureName, BouncyCastle.PROVIDER);
            checker.initVerify(path.get(0).getPublicKey());
            checker.update(input.getBytes(StandardCharsets.US_ASCII));
            require(checker.verify(signature), "independent signature control");
            return input + "." + url(signature);
        }

        byte[] receipt() throws Exception {
            List<X509CertificateHolder> holders = new ArrayList<>();
            for (X509Certificate cert : path) {
                holders.add(new X509CertificateHolder(cert.getEncoded()));
            }
            return TestPki.signReceiptAs(new DERSet().getEncoded(), AT, leafKey.getPrivate(),
                    "SHA256withECDSA", holders.get(0), holders);
        }
    }

    private static String url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void require(boolean condition, String label) {
        assertions++;
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    private static String verdict(VerificationResult<?> result) {
        return result.verified() ? "VERIFIED" : result.failure().reason().name();
    }

    private static void refused(VerificationResult<?> result) {
        negativeChecks++;
        require(!result.verified() && result.payload() == null, "unsigned input accepted");
        require(result.failure().reason() != Reason.INTERNAL_ERROR
                && result.failure().reason() != Reason.UNREADABLE_PAYLOAD, "unexpected refusal reason");
    }

    private static void jwsProbes() throws Exception {
        Pki p256 = new Pki("secp256r1", false);
        String token = p256.token("ES256", "SHA256withPLAIN-ECDSA", true);
        require(p256.pkix(), "control PKIX");
        require(p256.verifier.verifySignedData(token).verified(), "control JWS");
        System.out.println("jws-control pkix=true signature=true result=VERIFIED");
        String omitted = p256.token("ES256", "SHA256withPLAIN-ECDSA", false);
        require(p256.verifier.verifySignedData(omitted).failure().reason() == Reason.MALFORMED, "two-entry result");
        System.out.println("jws-root-omitted entries=2 pkix=true signature=true result="
                + verdict(p256.verifier.verifySignedData(omitted)));
        Pki deeper = new Pki("secp256r1", true);
        require(deeper.pkix(), "four-entry PKIX");
        String four = deeper.token("ES256", "SHA256withPLAIN-ECDSA", true);
        require(deeper.verifier.verifySignedData(four).failure().reason() == Reason.MALFORMED, "four-entry result");
        System.out.println("jws-extra-ca entries=4 pkix=true signature=true result="
                + verdict(deeper.verifier.verifySignedData(four)));
        Pki p384 = new Pki("secp384r1", false);
        require(p384.pkix(), "ES384 PKIX");
        String es384 = p384.token("ES384", "SHA384withPLAIN-ECDSA", true);
        require(p384.verifier.verifySignedData(es384).failure().reason() == Reason.MALFORMED, "ES384 result");
        System.out.println("jws-es384 entries=3 pkix=true signature=true result="
                + verdict(p384.verifier.verifySignedData(es384)));
        Verifier apple = Verifier.create(Config.defaults());
        refused(apple.verifySignedData(token));
        Pki foreign = new Pki("secp256r1", false);
        refused(p256.verifier.verifySignedData(foreign.token("ES256", "SHA256withPLAIN-ECDSA", true)));
        Pki nonCa = new Pki("secp256r1", false, false, true,
                name("Review Intermediate"), name("Review Intermediate"));
        refused(nonCa.verifier.verifySignedData(nonCa.token("ES256", "SHA256withPLAIN-ECDSA", true)));
        Pki markerless = new Pki("secp256r1", false, true, false,
                name("Review Intermediate"), name("Review Intermediate"));
        refused(markerless.verifier.verifySignedData(markerless.token("ES256", "SHA256withPLAIN-ECDSA", true)));
        String[] parts = token.split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        for (int i = 0; i < signature.length; i++) {
            byte[] corrupted = signature.clone();
            corrupted[i] ^= 1;
            refused(p256.verifier.verifySignedData(parts[0] + "." + parts[1] + "." + url(corrupted)));
        }
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        for (int i = 0; i < payload.length; i++) {
            byte[] corrupted = payload.clone();
            corrupted[i] ^= 1;
            refused(p256.verifier.verifySignedData(parts[0] + "." + url(corrupted) + "." + parts[2]));
        }
    }

    private static void nameProbes() throws Exception {
        for (ASN1Encodable encoding : Arrays.asList(new DERPrintableString("Review Intermediate"),
                new DERUTF8String("Review Intermediate"), new DERBMPString("Review Intermediate"),
                new DERT61String("Review Intermediate"))) {
            Pki pki = new Pki("secp256r1", false, true, true,
                    name("Review Intermediate"), name(encoding));
            boolean pkix = pki.pkix();
            boolean linearEqual = BCStrictStyle.INSTANCE.areEqual(
                    X500Name.getInstance(pki.path.get(0).getIssuerX500Principal().getEncoded()),
                    X500Name.getInstance(pki.path.get(1).getSubjectX500Principal().getEncoded()));
            require(pkix && linearEqual, "PKIX and linear-name controls");
            byte[] cms = pki.receipt();
            require(new CMSSignedData(cms).getSignerInfos().getSigners().iterator().next().verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastle.PROVIDER)
                            .build(pki.path.get(0).getPublicKey())), "independent CMS signature");
            String receipt = Base64.getEncoder().encodeToString(cms);
            System.out.println("issuer-encoding " + encoding.getClass().getSimpleName()
                    + " pkix=" + pkix + " principal-equal="
                    + pki.path.get(0).getIssuerX500Principal().equals(pki.path.get(1).getSubjectX500Principal())
                    + " linear-equal=" + linearEqual
                    + " cms-signature=true receipt=" + verdict(pki.verifier.verifyReceipt(receipt))
                    + " jws=" + verdict(pki.verifier.verifySignedData(
                            pki.token("ES256", "SHA256withPLAIN-ECDSA", true))));
            refused(Verifier.create(Config.defaults()).verifyReceipt(receipt));
        }
        X500Name original = new X500Name(new RDN[] {new RDN(new AttributeTypeAndValue[] {
                new AttributeTypeAndValue(BCStyle.CN, new DERPrintableString("Short")),
                new AttributeTypeAndValue(BCStyle.OU, new DERPrintableString("Longer"))})});
        X500Name equivalent = new X500Name(new RDN[] {new RDN(new AttributeTypeAndValue[] {
                new AttributeTypeAndValue(BCStyle.CN, new DERBMPString("Short")),
                new AttributeTypeAndValue(BCStyle.OU, new DERPrintableString("Longer"))})});
        Pki pki = new Pki("secp256r1", false, true, true, original, original);
        byte[] bytes = pki.receipt();
        ContentInfo ci = ContentInfo.getInstance(ASN1Primitive.fromByteArray(bytes));
        SignedData data = SignedData.getInstance(ci.getContent());
        SignerInfo old = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
        SignerInfo edited = new SignerInfo(new SignerIdentifier(new IssuerAndSerialNumber(
                equivalent, pki.path.get(0).getSerialNumber())), old.getDigestAlgorithm(),
                old.getAuthenticatedAttributes(), old.getDigestEncryptionAlgorithm(),
                old.getEncryptedDigest(), old.getUnauthenticatedAttributes());
        SignedData replacement = new SignedData(data.getDigestAlgorithms(), data.getEncapContentInfo(),
                data.getCertificates(), data.getCRLs(), new DERSet(edited));
        String changed = Base64.getEncoder().encodeToString(new ContentInfo(ci.getContentType(), replacement).getEncoded());
        require(pki.pkix() && pki.verifier.verifyReceipt(Base64.getEncoder().encodeToString(bytes)).verified(),
                "multivalued name control");
        System.out.println("multivalued-sid principal-equal="
                + new javax.security.auth.x500.X500Principal(original.getEncoded()).equals(
                        new javax.security.auth.x500.X500Principal(equivalent.getEncoded()))
                + " strict-equal=" + BCStrictStyle.INSTANCE.areEqual(original, equivalent)
                + " receipt=" + verdict(pki.verifier.verifyReceipt(changed)));
    }

    private static void collisionProbes() throws Exception {
        Pki pki = new Pki("secp256r1", false);
        String token = pki.token("ES256", "SHA256withPLAIN-ECDSA", true);
        String[] parts = token.split("\\.");
        String base = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        for (int count : new int[] {64, 256, 1024, 4096}) {
            for (boolean collide : new boolean[] {false, true}) {
                StringBuilder header = new StringBuilder(base.substring(0, base.length() - 1));
                for (int i = 0; i < count; i++) {
                    StringBuilder key = new StringBuilder();
                    for (int bit = 0; bit < 12; bit++) {
                        key.append((i & (1 << bit)) == 0 ? "Aa" : "B@");
                    }
                    header.append(",\"").append(collide ? key.toString() : "key" + i).append("\":null");
                }
                header.append('}');
                String input = url(header.toString().getBytes(StandardCharsets.UTF_8)) + "." + parts[1] + "."
                        + url(new byte[64]);
                for (int i = 0; i < 20; i++) {
                    refused(pki.verifier.verifySignedData(input));
                }
                long start = System.nanoTime();
                VerificationResult<JsonPayload> result = null;
                for (int i = 0; i < 20; i++) {
                    result = pki.verifier.verifySignedData(input);
                    refused(result);
                }
                double millis = (System.nanoTime() - start) / 20000000.0;
                System.out.printf(Locale.ROOT, "json-names count=%d collide=%s bytes=%d result=%s mean-ms=%.3f%n",
                        count, collide, input.length(), verdict(result), millis);
            }
        }
    }

    private static void selfIssuedProbe() throws Exception {
        TestPki pki = TestPki.deepReceipt(1, 6);
        Verifier verifier = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        byte[] cms = pki.signReceipt(new DERSet().getEncoded());
        SignedData data = SignedData.getInstance(new CMSSignedData(cms).toASN1Structure().getContent());
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(Base64.getEncoder().encodeToString(cms));
        System.out.println("self-issued-tail below-anchor=8 embedded=" + data.getCertificates().size()
                + " result=" + verdict(result));
    }

    public static void main(String[] args) throws Exception {
        jwsProbes();
        nameProbes();
        collisionProbes();
        selfIssuedProbe();
        Verifier apple = Verifier.create(Config.defaults());
        int genuine = 0;
        for (String file : Arrays.asList("receipt-sandbox-legacy.b64", "receipt-sandbox-g5.b64")) {
            String receipt = new String(Files.readAllBytes(Paths.get(args[0], file)), StandardCharsets.US_ASCII).trim();
            require(apple.verifyReceipt(receipt).verified(), "sandbox control");
            genuine++;
        }
        System.out.println("sandbox-controls verified=" + genuine);
        System.out.println("negative-checks=" + negativeChecks + " assertions=" + assertions);
    }
}
