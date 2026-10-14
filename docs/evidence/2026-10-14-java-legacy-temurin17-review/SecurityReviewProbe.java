package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.*;
import java.util.*;
import java.security.MessageDigest;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;

/** Review-only security experiments. No receipt values are printed. */
public final class SecurityReviewProbe {
    private static int checks;
    private static SignedData unpack(byte[] b) throws Exception {
        return SignedData.getInstance(ContentInfo.getInstance(ASN1Primitive.fromByteArray(b)).getContent());
    }
    private static byte[] pack(SignedData sd, ContentInfo content, ASN1Set certs, ASN1Set signers) throws Exception {
        return new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(
                sd.getDigestAlgorithms(), content, certs, sd.getCRLs(), signers)).getEncoded(ASN1Encoding.DL);
    }
    private static SignerInfo change(SignerInfo s, ASN1Set signed, byte[] sig, ASN1Set unsigned) {
        return new SignerInfo(s.getSID(), s.getDigestAlgorithm(), signed,
                s.getDigestEncryptionAlgorithm(), new DEROctetString(sig), unsigned);
    }
    private static String verdict(Verifier v, byte[] b) {
        VerificationResult<?> r = v.verifyReceipt(Base64.getEncoder().encodeToString(b));
        if (!r.verified() && r.payload() != null) throw new AssertionError("failure exposes payload");
        if (!r.verified() && r.failure().reason() == Reason.INTERNAL_ERROR) throw new AssertionError("internal error");
        return r.verified() ? "VERIFIED" : r.failure().reason().name();
    }
    private static void expect(Verifier v, byte[] b, boolean accepted) {
        String result = verdict(v, b);
        if (result.equals("VERIFIED") != accepted) throw new AssertionError("unexpected verdict: " + result);
        checks++;
    }
    private static byte[] fixture(Path dir, String name) throws Exception {
        return Base64.getDecoder().decode(new String(Files.readAllBytes(dir.resolve(name + ".b64")),
                java.nio.charset.StandardCharsets.US_ASCII).trim());
    }
    private static void binding(Verifier v, byte[] original, String name) throws Exception {
        expect(v, original, true);
        SignedData sd = unpack(original);
        SignerInfo signer = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        byte[] payload = ASN1OctetString.getInstance(sd.getEncapContentInfo().getContent()).getOctets();
        // Every payload mutation retains the original signature and certificate bag.
        for (int i = 0; i < Math.min(128, payload.length); i++) {
            byte[] altered = payload.clone();
            altered[(int)((long)i * payload.length / Math.min(128, payload.length))] ^= 1;
            expect(v, pack(sd, new ContentInfo(sd.getEncapContentInfo().getContentType(),
                    new DEROctetString(altered)), sd.getCertificates(), sd.getSignerInfos()), false);
        }
        byte[] sig = signer.getEncryptedDigest().getOctets();
        for (int i = 0; i < sig.length; i++) {
            byte[] altered = sig.clone(); altered[i] ^= 1;
            expect(v, pack(sd, sd.getEncapContentInfo(), sd.getCertificates(), new DLSet(change(
                    signer, signer.getAuthenticatedAttributes(), altered, signer.getUnauthenticatedAttributes()))), false);
        }
        expect(v, pack(sd, new ContentInfo(sd.getEncapContentInfo().getContentType(), null),
                sd.getCertificates(), sd.getSignerInfos()), false);
        // Splitting the OCTET STRING changes its transport representation, not signed bytes.
        int middle = payload.length / 2;
        BEROctetString chunks = new BEROctetString(new ASN1OctetString[] {
                new DEROctetString(Arrays.copyOfRange(payload, 0, middle)),
                new DEROctetString(Arrays.copyOfRange(payload, middle, payload.length))});
        expect(v, pack(sd, new ContentInfo(sd.getEncapContentInfo().getContentType(), chunks),
                sd.getCertificates(), sd.getSignerInfos()), true);
        expect(v, pack(sd, sd.getEncapContentInfo(), new DLSet(), sd.getSignerInfos()), false);
        if (signer.getAuthenticatedAttributes() != null) {
            byte[] altered = payload.clone(); altered[altered.length - 1] ^= 1;
            ASN1EncodableVector patched = new ASN1EncodableVector();
            for (ASN1Encodable e : signer.getAuthenticatedAttributes()) {
                Attribute a = Attribute.getInstance(e);
                patched.add(a.getAttrType().equals(CMSAttributes.messageDigest)
                        ? new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(
                                MessageDigest.getInstance("SHA-256").digest(altered)))) : a);
            }
            expect(v, pack(sd, new ContentInfo(sd.getEncapContentInfo().getContentType(),
                    new DEROctetString(altered)), sd.getCertificates(), new DLSet(change(signer,
                            new DERSet(patched), sig, signer.getUnauthenticatedAttributes()))), false);
            for (ASN1ObjectIdentifier target : new ASN1ObjectIdentifier[] {
                    CMSAttributes.messageDigest, CMSAttributes.contentType, CMSAttributes.cmsAlgorithmProtect}) {
                ASN1EncodableVector duplicate = new ASN1EncodableVector();
                for (ASN1Encodable e : signer.getAuthenticatedAttributes()) {
                    duplicate.add(e);
                    if (Attribute.getInstance(e).getAttrType().equals(target)) duplicate.add(e);
                }
                expect(v, pack(sd, sd.getEncapContentInfo(), sd.getCertificates(), new DLSet(change(
                        signer, new DERSet(duplicate), sig, signer.getUnauthenticatedAttributes()))), false);
            }
        }
        System.out.println(name + " binding checks complete; cumulative=" + checks);
    }
    // Ten birthday collisions compose into 1024 equal hashes. All octets are
    // single-octet OID arcs; a long common prefix makes equality expensive.
    private static List<ASN1ObjectIdentifier> collisions(int length) {
        Random rng = new Random(0x5ec01234L);
        byte[][][] choices = new byte[10][2][];
        int state = length + 1;
        for (int stage = 0; stage < 10; stage++) {
            Map<Integer, byte[]> seen = new HashMap<>();
            for (int attempt = 0; ; attempt++) {
                if (attempt == 2_000_000) throw new AssertionError("collision search bound");
                byte[] block = new byte[6];
                int h = state;
                for (int j = 0; j < block.length; j++) {
                    block[j] = (byte) rng.nextInt(128); h = h * 257 ^ block[j];
                }
                byte[] prior = seen.putIfAbsent(h, block);
                if (prior != null && !Arrays.equals(prior, block)) {
                    choices[stage][0] = prior; choices[stage][1] = block; state = h; break;
                }
            }
        }
        List<ASN1ObjectIdentifier> result = new ArrayList<>();
        Set<ASN1ObjectIdentifier> distinct = new HashSet<>();
        Integer expected = null;
        for (int i = 0; i < 1000; i++) {
            byte[] content = new byte[length]; Arrays.fill(content, (byte)127); content[0] = 43;
            for (int stage = 0; stage < 10; stage++) for (int j = 0; j < 6; j++) {
                content[length - 1 - stage * 6 - j] = choices[stage][(i >>> stage) & 1][j];
            }
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.fromContents(content);
            if (expected == null) expected = oid.hashCode();
            if (expected != oid.hashCode() || !distinct.add(oid)) throw new AssertionError("invalid collision set");
            result.add(oid);
        }
        return result;
    }
    private static void costs(Path fixtures, Path scratch) throws Exception {
        Verifier v = Verifier.create(Config.defaults());
        SignedData sd = unpack(fixture(fixtures, "receipt-sandbox-g5"));
        SignerInfo signer = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        List<ASN1ObjectIdentifier> oids = collisions(2300);
        System.out.println("generated 1000 distinct 2300-octet OIDs with identical BC hashCode");
        for (boolean collide : new boolean[] {false, true}) for (int count : new int[] {250, 500, 1000}) {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            for (int i = 0; i < count; i++) {
                ASN1ObjectIdentifier oid = oids.get(i);
                if (!collide) {
                    byte[] content = new byte[2300]; Arrays.fill(content, (byte)127); content[0] = 43;
                    content[2298] = (byte)(i / 128); content[2299] = (byte)(i % 128);
                    oid = ASN1ObjectIdentifier.fromContents(content);
                }
                attributes.add(new Attribute(oid, new DLSet(DERNull.INSTANCE)));
            }
            byte[] der = pack(sd, sd.getEncapContentInfo(), sd.getCertificates(), new DLSet(change(signer,
                    signer.getAuthenticatedAttributes(), signer.getEncryptedDigest().getOctets(), new DLSet(attributes))));
            String b64 = Base64.getEncoder().encodeToString(der);
            if (b64.length() > ReceiptCore.MAX_RECEIPT_BYTES) throw new AssertionError("input exceeds cap");
            for (int warm = 0; warm < 5; warm++) expect(v, der, true);
            long start = System.nanoTime();
            for (int run = 0; run < 10; run++) {
                if (!v.verifyReceipt(b64).verified()) throw new AssertionError("unsigned OIDs changed verdict");
            }
            System.out.printf(Locale.ROOT, "collisions=%s count=%d b64=%d mean=%.1f ms VERIFIED%n",
                    collide, count, b64.length(), (System.nanoTime()-start)/10e6);
            if (collide && count == 1000) Files.write(scratch.resolve("colliding-unsigned.b64"),
                    b64.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
    }
    // Sign deliberately malformed EMSA-PKCS1-v1_5 blocks with our own key.
    // Flipping an existing RSA signature only tests generic signature failure;
    // these cases exercise DigestInfo and padding checks after RSA succeeds.
    private static void rsaEncoding() throws Exception {
        TestPki pki = TestPki.receipt();
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair key = generator.generateKeyPair();
        java.security.cert.X509Certificate cert = TestPki.cert("CN=Security Review Signer", key,
                "CN=Fake WWDR CA", pki.intermediateKey, false, AppleTrust.SIGNING_LEAF_OID,
                pki.leaf.getNotBefore(), pki.leaf.getNotAfter(), "SHA256withRSA");
        Verifier verifier = Checks.verifier(pki);
        byte[] payload = TestPki.singleAttributePayload(9999, new byte[] {1, 2, 3});
        for (String digestName : new String[] {"SHA-1", "SHA-256"}) {
        org.bouncycastle.asn1.x509.AlgorithmIdentifier sha256 = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                digestName.equals("SHA-1") ? org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1
                        : org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        byte[] digest = MessageDigest.getInstance(digestName).digest(payload);
        byte[] digestInfo = new org.bouncycastle.asn1.x509.DigestInfo(sha256, digest).getEncoded();
        java.security.interfaces.RSAPrivateKey privateKey = (java.security.interfaces.RSAPrivateKey)key.getPrivate();
        int size = (privateKey.getModulus().bitLength() + 7) / 8;
        byte[] proper = new byte[size]; proper[1] = 1;
        Arrays.fill(proper, 2, size - digestInfo.length - 1, (byte)255);
        System.arraycopy(digestInfo, 0, proper, size - digestInfo.length, digestInfo.length);
        ASN1Set certs = new DLSet(new ASN1Encodable[] {
                ASN1Primitive.fromByteArray(cert.getEncoded()),
                ASN1Primitive.fromByteArray(pki.intermediate.getEncoded()),
                ASN1Primitive.fromByteArray(pki.root.getEncoded())});
        org.bouncycastle.cert.X509CertificateHolder holder = new org.bouncycastle.cert.X509CertificateHolder(cert.getEncoded());
        SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber()));
        int before = checks;
        for (int test = -1; test < digest.length + 4; test++) {
            byte[] block = proper.clone();
            if (test >= 0 && test < digest.length) block[size - digest.length + test] ^= 1;
            if (test == digest.length) block[1] = 2; // encryption block type instead of signature
            if (test == digest.length + 1) block[3] = 0; // early end of padding
            if (test == digest.length + 2) block[size - digestInfo.length - 1] = (byte)255; // no separator
            if (test == digest.length + 3) block[size - digestInfo.length] ^= 1; // wrong DigestInfo tag
            byte[] integer = new java.math.BigInteger(1, block).modPow(
                    privateKey.getPrivateExponent(), privateKey.getModulus()).toByteArray();
            byte[] signature = new byte[size];
            int copy = Math.min(size, integer.length);
            System.arraycopy(integer, integer.length - copy, signature, size - copy, copy);
            SignerInfo signer = new SignerInfo(sid, sha256, (ASN1Set)null,
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                    new DEROctetString(signature), null);
            SignedData sd = new SignedData(new DLSet(sha256),
                    new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(payload)), certs, null, new DLSet(signer));
            expect(verifier, new ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded(), test == -1);
        }
        System.out.println("RSA " + digestName + " DigestInfo and padding: " + (checks - before) + " checks complete");
        }
    }
    public static void main(String[] args) throws Exception {
        Path fixtures = Paths.get(args[1]);
        if (args[0].equals("costs")) { costs(fixtures, Paths.get(args[2])); return; }
        Verifier apple = Verifier.create(Config.defaults());
        for (String name : new String[] {"receipt-sandbox-legacy", "receipt-sandbox-g5"}) {
            binding(apple, fixture(fixtures, name), name);
        }
        TestPki pki = TestPki.receipt();
        byte[] synthetic = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[] {1, 2, 3}));
        expect(apple, synthetic, false);
        binding(Checks.verifier(pki), synthetic, "synthetic signed attributes");
        rsaEncoding();
        System.out.println("PASS " + checks + " checks; zero signature bypasses, leaked failed payloads or INTERNAL_ERROR results");
    }
}
