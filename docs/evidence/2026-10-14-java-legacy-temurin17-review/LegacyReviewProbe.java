package io.github.emindeniz99.applepurchasereceiptverifier;

import com.sun.management.ThreadMXBean;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Locale;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;

/** Review-only probe. Prints verdicts, sizes and allocation; never receipt fields. */
public final class LegacyReviewProbe {
    private static volatile Object sink;

    public static void main(String[] args) throws Exception {
        if (args[0].equals("acceptance")) {
            acceptance(args[1]);
        } else if (args[0].equals("date-equivalence")) {
            int compared = 0;
            int dates = 0;
            for (byte[] der : ReceiptContentInfoTest.corpus()) {
                byte[] payload;
                try {
                    SignedData sd = signedData(der);
                    payload = ASN1OctetString.getInstance(sd.getEncapContentInfo().getContent()).getOctets();
                } catch (Exception e) { continue; }
                Long current = ReceiptDecoder.readCreationDate(payload);
                if (!java.util.Objects.equals(current, scanDate(payload))) throw new AssertionError("different date");
                compared++;
                if (current != null) dates++;
            }
            if (compared < 100 || dates < 100) throw new AssertionError("insufficient corpus coverage");
            System.out.println("date scan equivalence: " + compared + " payloads, " + dates + " non-null dates, zero differences");
        } else if (args[0].equals("date-cost")) {
            byte[] der = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(args[1])));
            SignedData sd = signedData(der);
            byte[] payload = ASN1OctetString.getInstance(sd.getEncapContentInfo().getContent()).getOctets();
            Long original = ReceiptDecoder.readCreationDate(payload);
            if (!java.util.Objects.equals(original, scanDate(payload))) throw new AssertionError("different date");
            measure("current readCreationDate", () -> ReceiptDecoder.readCreationDate(payload));
            measure("review-only scan, no maps", () -> scanDate(payload));
        } else {
            throw new IllegalArgumentException(args[0]);
        }
    }

    private static void acceptance(String root) throws Exception {
        Verifier verifier = Verifier.create(Config.defaults());
        for (String name : new String[] {"receipt-sandbox-legacy", "receipt-sandbox-g5"}) {
            String text = new String(Files.readAllBytes(Paths.get(root, name + ".b64")), StandardCharsets.US_ASCII).trim();
            String original = verdict(verifier.verifyReceipt(text));
            if (!original.equals("VERIFIED")) throw new AssertionError(name + ": " + original);
            System.out.println(name + " unchanged: " + original);
            Verifier later = Verifier.create(Config.builder()
                    .clock(Clock.fixed(Instant.parse("2040-01-01T00:00:00Z"), ZoneOffset.UTC)).build());
            String future = verdict(later.verifyReceipt(text));
            if (!future.equals("VERIFIED")) throw new AssertionError("clock changes acceptance");
            System.out.println(name + " clock after root expiry: " + future);
            SignedData sd = signedData(Base64.getDecoder().decode(text));
            SignerInfo signer = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
            for (int count : new int[] {1000, 1001}) {
                ASN1EncodableVector attrs = new ASN1EncodableVector();
                for (int i = 0; i < count; i++) {
                    attrs.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999." + i), new DLSet(DERNull.INSTANCE)));
                }
                SignerInfo changed = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                        signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                        signer.getEncryptedDigest(), new DLSet(attrs));
                String v = verdict(verifier.verifyReceipt(Base64.getEncoder().encodeToString(repack(sd, new DLSet(changed)))));
                if (!v.equals(count == 1000 ? "VERIFIED" : "MALFORMED")) throw new AssertionError("unexpected cap result: " + v);
                System.out.println(name + " same signature, " + count + " unsigned attributes: " + v);
            }
            byte[] sig = signer.getEncryptedDigest().getOctets().clone();
            sig[0] ^= 1;
            SignerInfo corrupt = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                    signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                    new DEROctetString(sig), signer.getUnauthenticatedAttributes());
            String v = verdict(verifier.verifyReceipt(Base64.getEncoder().encodeToString(repack(sd, new DLSet(corrupt)))));
            if (!v.equals("INVALID_SIGNATURE")) throw new AssertionError("corrupt signature: " + v);
            System.out.println(name + " corrupt signature: " + v);
        }
    }

    private static SignedData signedData(byte[] der) throws Exception {
        return SignedData.getInstance(ContentInfo.getInstance(ASN1Primitive.fromByteArray(der)).getContent());
    }

    private static byte[] repack(SignedData sd, ASN1Set signers) throws Exception {
        return new ContentInfo(CMSObjectIdentifiers.signedData,
                new SignedData(sd.getDigestAlgorithms(), sd.getEncapContentInfo(),
                        sd.getCertificates(), sd.getCRLs(), signers)).getEncoded(ASN1Encoding.DL);
    }

    private static String verdict(VerificationResult<?> result) {
        return result.verified() ? "VERIFIED" : result.failure().reason().name();
    }

    /** Same full top-level validation, first date wins; intentionally retains no attribute maps. */
    private static Long scanDate(byte[] payload) {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(payload);
            if (parsed instanceof ASN1OctetString) parsed = ASN1Primitive.fromByteArray(((ASN1OctetString) parsed).getOctets());
            ASN1Set set = ASN1Set.getInstance(parsed);
            byte[] date = null;
            boolean found = false;
            for (ASN1Encodable entry : set) {
                ASN1Sequence seq = ASN1Sequence.getInstance(entry);
                if (seq.size() < 3) return null;
                int type = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
                if (type < 0) return null;
                byte[] value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                if (type == 12 && !found) { date = value; found = true; }
            }
            if (date == null) return null;
            ASN1Primitive value = ASN1Primitive.fromByteArray(date);
            if (value instanceof ASN1IA5String) {
                for (byte b : ((ASN1IA5String) value).getOctets()) if (b < 0) return null;
            } else if (!(value instanceof ASN1UTF8String)) return null;
            return ReceiptDecoder.parseDate(((ASN1String) value).getString());
        } catch (Exception e) { return null; }
    }

    private interface Call { Object run(); }

    private static void measure(String name, Call call) {
        ThreadMXBean bean = (ThreadMXBean) ManagementFactory.getThreadMXBean();
        bean.setThreadAllocatedMemoryEnabled(true);
        for (int i = 0; i < 5; i++) sink = call.run();
        long id = Thread.currentThread().getId();
        long before = bean.getThreadAllocatedBytes(id), start = System.nanoTime();
        int n = 8;
        for (int i = 0; i < n; i++) sink = call.run();
        System.out.printf(Locale.ROOT, "%s: %.2f ms, %.2f MiB allocated per call%n", name,
                (System.nanoTime() - start) / 1e6 / n, (bean.getThreadAllocatedBytes(id) - before) / 1048576.0 / n);
    }
}
