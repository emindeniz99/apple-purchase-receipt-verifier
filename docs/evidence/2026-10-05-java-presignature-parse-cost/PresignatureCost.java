import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.TestPki;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

/**
 * What does a cap-sized hostile receipt cost the Java implementation, which
 * has no node budget of its own before the signature? Three modes:
 *
 * <pre>
 *   make DIR             write the inputs to DIR (one TestPki for all of them)
 *   measure FILE ROOTS   verdict, retained heap, ms and bytes allocated per call
 *   once FILE ROOTS      one call; exit 0 with the verdict, 3 on OutOfMemoryError
 * </pre>
 *
 * ROOTS is {@code default} (Apple's roots, so a TestPki receipt ends at
 * UNTRUSTED_CHAIN and only the work before trust is paid) or the path of the
 * TestPki root that {@code make} wrote (the receipt verifies).
 *
 * <p>Inputs, every one signed by the same TestPki leaf and at most 3,145,728
 * base64 characters, the receipt cap:
 * <ul>
 *   <li>{@code baseline.b64}: a genuine-shaped receipt from
 *       {@code TestPki.receiptPayload}, the JVM floor for the -Xmx bisection.
 *   <li>{@code tiny-attributes.b64}: the same payload with as many tiny
 *       attributes appended inside its SET as fit, each
 *       SEQUENCE { INTEGER type (3 bytes, distinct), INTEGER 1, OCTET STRING
 *       of 0 bytes }, 12 bytes. The library decodes the whole top-level SET
 *       before any signer is matched.
 *   <li>{@code unsigned-attribute.b64}: the baseline receipt with one
 *       unsigned attribute on its SignerInfo whose value SET holds as many
 *       empty SEQUENCEs (2 bytes each) as fit. Outside the signature, so
 *       anyone can append it to a genuine receipt; BouncyCastle parses it
 *       with the rest of the envelope, before anything else runs.
 * </ul>
 */
public final class PresignatureCost {

    private static final int CAP = 3_145_728;

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "make":
                make(Paths.get(args[1]));
                break;
            case "measure":
                measure(read(args[1]), verifier(args[2]));
                break;
            case "once":
                once(read(args[1]), verifier(args[2]));
                break;
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }

    private static void make(Path dir) throws Exception {
        TestPki pki = TestPki.receipt();
        Files.write(dir.resolve("root.der"), pki.root.getEncoded());
        // The chain is valid from a day ago; the creation date must fall
        // inside it, or the trusted run ends at INVALID_CERTIFICATE.
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        byte[] payload = TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                now,
                Collections.<byte[]>singletonList(TestPki.inAppPurchase(
                        1, "com.example.product", "1000000000000001", "1000000000000001",
                        now, null)));
        byte[] baseline = pki.signReceipt(payload);
        write(dir, "baseline.b64", baseline, payload.length);

        // Room left under the cap, in DER bytes, less a margin for longer
        // length fields and a different signature length.
        int room = CAP / 4 * 3 - baseline.length - 64;

        // 1. The payload SET with tiny attributes appended. BouncyCastle
        // writes large encapsulated content as a chunked BER OCTET STRING,
        // so the count is fitted to the cap by trial.
        int n = room / 12;
        byte[] tinyPayload;
        byte[] tiny;
        while (true) {
            tinyPayload = tinyAttributes(payload, n);
            tiny = pki.signReceipt(tinyPayload);
            int over = (tiny.length + 2) / 3 * 4 - CAP;
            if (over <= 0) {
                break;
            }
            n -= over * 3 / 4 / 12 + 1;
        }
        write(dir, "tiny-attributes.b64", tiny, tinyPayload.length);
        System.out.println("  tiny attributes appended: " + n);

        // 2. One unsigned attribute of empty SEQUENCEs on the baseline's SignerInfo.
        int m = room / 2;
        ASN1EncodableVector values = new ASN1EncodableVector(m);
        DERSequence empty = new DERSequence();
        for (int i = 0; i < m; i++) {
            values.add(empty);
        }
        // DLSet: no DER sort of a million equal values while encoding.
        Attribute flood = new Attribute(new ASN1ObjectIdentifier("1.2.3.4.5"), new DLSet(values));
        CMSSignedData cms = new CMSSignedData(baseline);
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        SignerInformation flooded = SignerInformation.replaceUnsignedAttributes(
                signer, new AttributeTable(flood));
        byte[] unsigned = CMSSignedData.replaceSigners(cms, new SignerInformationStore(flooded))
                .toASN1Structure()
                .getEncoded("DL");
        write(dir, "unsigned-attribute.b64", unsigned, payload.length);
        System.out.println("  empty SEQUENCEs in the unsigned attribute: " + m);
    }

    private static void measure(String base64, Verifier verifier) {
        for (int i = 0; i < 30; i++) {
            verifier.verifyReceipt(base64);
        }
        System.gc();
        System.gc();
        long before = used();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
        System.gc();
        System.gc();
        long retained = used() - before;
        System.out.println("verdict: " + verdict(result));
        System.out.printf("retained by the result after GC: %.1f MiB%n", retained / 1048576.0);
        result = null;
        int calls = 20;
        long allocated = allocated();
        long start = System.nanoTime();
        for (int i = 0; i < calls; i++) {
            verifier.verifyReceipt(base64);
        }
        long elapsed = System.nanoTime() - start;
        System.out.printf("per call over %d warm calls: %.1f ms, %.1f MiB allocated%n",
                calls, elapsed / 1e6 / calls, (allocated() - allocated) / 1048576.0 / calls);
    }

    private static void once(String base64, Verifier verifier) {
        try {
            System.out.println("verdict: " + verdict(verifier.verifyReceipt(base64)));
        } catch (OutOfMemoryError e) {
            System.out.println("OutOfMemoryError");
            System.exit(3);
        }
    }

    private static String verdict(VerificationResult<ReceiptPayload> result) {
        return result.verified() ? "VERIFIED" : result.failure().reason().toString();
    }

    private static Verifier verifier(String roots) throws Exception {
        if (roots.equals("default")) {
            return Verifier.create(Config.defaults());
        }
        X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Paths.get(roots))));
        return Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
    }

    private static String read(String file) throws Exception {
        return new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.US_ASCII);
    }

    private static void write(Path dir, String name, byte[] der, int payloadBytes) throws Exception {
        String base64 = Base64.getEncoder().encodeToString(der);
        if (base64.length() > CAP) {
            throw new IllegalStateException(name + " is over the cap: " + base64.length());
        }
        Files.write(dir.resolve(name), base64.getBytes(StandardCharsets.US_ASCII));
        System.out.printf("%s: %d DER bytes, %d base64 chars (cap %d), payload %d bytes%n",
                name, der.length, base64.length(), CAP, payloadBytes);
    }

    private static long used() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static long allocated() {
        return ((com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean())
                .getThreadAllocatedBytes(Thread.currentThread().getId());
    }

    /** {@code payload}'s SET with {@code n} tiny attributes of distinct types appended. */
    private static byte[] tinyAttributes(byte[] payload, int n) throws Exception {
        ByteArrayOutputStream grown = new ByteArrayOutputStream();
        grown.write(contentOfSet(payload));
        for (int i = 0; i < n; i++) {
            int type = 100_000 + i;
            grown.write(new byte[] {
                0x30, 0x0A,
                0x02, 0x03, (byte) (type >> 16), (byte) (type >> 8), (byte) type,
                0x02, 0x01, 0x01,
                0x04, 0x00
            });
        }
        return set(grown.toByteArray());
    }

    /** The content octets of a DER SET. */
    private static byte[] contentOfSet(byte[] der) {
        int lengthBytes = (der[1] & 0x80) == 0 ? 0 : der[1] & 0x7F;
        int offset = 2 + lengthBytes;
        byte[] out = new byte[der.length - offset];
        System.arraycopy(der, offset, out, 0, out.length);
        return out;
    }

    /** A DER SET around {@code content}, as written, unsorted. */
    private static byte[] set(byte[] content) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x31);
        out.write(length(content.length));
        out.write(content);
        return out.toByteArray();
    }

    /** A minimal DER length. */
    private static byte[] length(int n) {
        if (n < 128) {
            return new byte[] {(byte) n};
        }
        int bytes = n < 1 << 8 ? 1 : n < 1 << 16 ? 2 : n < 1 << 24 ? 3 : 4;
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = 0; i < bytes; i++) {
            out[bytes - i] = (byte) (n >> (8 * i));
        }
        return out;
    }
}
