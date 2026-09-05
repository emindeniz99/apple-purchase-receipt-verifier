package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.AppTransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Anchors, verifiers and the invariants the five targets share.
 *
 * <p>Everything is built once in a static initializer and only read from
 * {@code fuzzerTestOneInput}: an anchor set costs a certificate parse and a
 * PKIX {@code TrustAnchor} construction, which at a few hundred thousand
 * executions would be the whole budget.
 */
final class Harness {

    private Harness() {}

    /** The bundle id every generated fixture carries (fixtures/generated/manifest.json). */
    static final String BUNDLE_ID = "com.example.app";

    /**
     * The bundle id of the base64 receipt corpus — {@code fixtures/public-receipts}
     * and {@code fixtures/generated/receipt-b64}, which are the same genuine
     * Apple-signed sandbox receipt in ten encodings.
     *
     * <p>It is not {@link #BUNDLE_ID}, and the difference matters: bound to
     * {@code com.example.app} the string verifier rejects every seed it has
     * with {@code WRONG_BUNDLE_ID}, which reads like a healthy run — the
     * fuzzer still reports coverage and finds no crash — while in fact no
     * input ever reaches acceptance, so the anchor-set invariant below never
     * fires and the code past the bundle check is never entered from this
     * entry point. Measured here: 0 of 16 receipt-b64 fixtures accepted.
     */
    static final String RECEIPT_BUNDLE_ID = "dev.bonzer.weeka.app";

    /** The app Apple id the AppTransaction fixtures carry. */
    static final Long APP_APPLE_ID = Long.valueOf(123456789L);

    static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Apple's three receipt roots plus the fixture receipt root, so that the
     * generated fixtures and both public Apple receipts get past the chain
     * check and the fuzzer can explore what lies beyond it.
     */
    static final Set<X509Certificate> RECEIPT_ANCHORS;

    /**
     * The anchor set an accepted receipt must fail against: the fixture
     * <em>JWS</em> root, which signed no receipt in this repository.
     * Deliberately a real, well-formed root rather than an empty or corrupt
     * set — "rejected because the anchor set was unusable" would prove nothing.
     */
    static final Set<X509Certificate> UNRELATED_RECEIPT_ANCHORS;

    /** The fixture JWS root: what the generated {@code .jws} fixtures chain to. */
    static final Set<X509Certificate> JWS_ANCHORS;

    /** Apple's production JWS roots: unrelated to every JWS fixture here. */
    static final Set<X509Certificate> APPLE_JWS_ANCHORS;

    static final ReceiptVerifier RECEIPT_VERIFIER;
    static final ReceiptVerifier UNRELATED_RECEIPT_VERIFIER;
    static final JwsVerifier JWS_VERIFIER;
    static final JwsVerifier APPLE_JWS_VERIFIER;
    static final VerifyReceiptEndpoint ENDPOINT;

    /**
     * The device GUID the generated receipt fixtures bind their SHA-1 hash to.
     * It does not match the public receipts the base64 corpus is made of, which
     * is the point: the device-hash check runs on every execution and answers
     * DEVICE_HASH_MISMATCH, so the SHA-1 binding path is exercised rather than
     * skipped for want of a GUID.
     */
    static final byte[] DEVICE_GUID;

    private static final Method[] RECEIPT_ACCESSORS = accessors(AppReceipt.class);
    private static final Method[] IN_APP_ACCESSORS = accessors(InAppPurchase.class);
    private static final Method[] TRANSACTION_ACCESSORS = accessors(TransactionPayload.class);
    private static final Method[] APP_TRANSACTION_ACCESSORS = accessors(AppTransactionPayload.class);

    static {
        Path fixtures = fixturesDir();
        X509Certificate receiptRoot = certificate(fixtures.resolve("generated/receipt-root.der"));
        X509Certificate jwsRoot = certificate(fixtures.resolve("generated/jws-root.der"));

        Set<X509Certificate> receiptAnchors = new LinkedHashSet<X509Certificate>(AppleRootCerts.receiptRoots());
        receiptAnchors.add(receiptRoot);
        RECEIPT_ANCHORS = Collections.unmodifiableSet(receiptAnchors);
        UNRELATED_RECEIPT_ANCHORS =
                Collections.unmodifiableSet(new LinkedHashSet<X509Certificate>(Collections.singleton(jwsRoot)));
        JWS_ANCHORS = UNRELATED_RECEIPT_ANCHORS;
        APPLE_JWS_ANCHORS = Collections.unmodifiableSet(new LinkedHashSet<X509Certificate>(AppleRootCerts.jwsRoots()));

        RECEIPT_VERIFIER = new ReceiptVerifier(RECEIPT_ANCHORS, RECEIPT_BUNDLE_ID);
        UNRELATED_RECEIPT_VERIFIER = new ReceiptVerifier(UNRELATED_RECEIPT_ANCHORS, RECEIPT_BUNDLE_ID);

        // Both environments accepted and an appAppleId supplied, so that no
        // claim check short-circuits the cryptography the target exists to
        // reach. maxSignedAge stays null for the same reason: the fixtures are
        // signed in 2024 and a staleness rule would reject them all.
        Set<Environment> environments = EnumSet.allOf(Environment.class);
        JWS_VERIFIER = new JwsVerifier(JWS_ANCHORS, BUNDLE_ID, environments, APP_APPLE_ID, null);
        APPLE_JWS_VERIFIER = new JwsVerifier(APPLE_JWS_ANCHORS, BUNDLE_ID, environments, APP_APPLE_ID, null);

        // The generated receipts carry receiptType "ProductionSandbox", so a
        // SANDBOX endpoint answers them 0 and builds the whole response body,
        // rather than routing them to 21007 before it is ever serialized.
        ENDPOINT = new VerifyReceiptEndpoint(RECEIPT_ANCHORS, Environment.SANDBOX);

        DEVICE_GUID = hex(read(fixtures.resolve("generated/device-guid.hex")));
    }

    // ----------------------------------------------------------- invariants

    /** A call the library declares may fail only with {@link VerificationException}. */
    interface Call<T> {
        T run() throws VerificationException;
    }

    /**
     * Runs one public entry point. Returns its result, or {@code null} when the
     * library rejected the input — no entry point called here returns
     * {@code null} on success, so the two stay distinguishable.
     *
     * <p>Anything else that comes out is the finding. The containment invariant
     * is asserted as "is not a {@code VerificationException}" rather than as a
     * list of forbidden types, because the leak that matters is always the type
     * nobody thought to list: a BouncyCastle {@code IllegalArgumentException},
     * a Jackson {@code JsonParseException}, a {@code StackOverflowError} out of
     * a nested ASN.1 structure and an {@code OutOfMemoryError} out of a length
     * prefix are all covered by the one phrasing. Enumerating types is exactly
     * what let eleven characters of attacker base64 escape the declared
     * contract once already.
     */
    static <T> T attempt(String where, Call<T> call) {
        try {
            return call.run();
        } catch (VerificationException rejected) {
            return null;
        } catch (Throwable t) {
            throw leaked(where, t);
        }
    }

    /**
     * Never returns; declared to return an {@link AssertionError} so a caller
     * can write {@code throw Harness.leaked(...)} and the compiler still sees
     * the method end.
     */
    static AssertionError leaked(String where, Throwable t) {
        if (t instanceof AssertionError) {
            // An invariant this harness itself asserted, on its way out.
            throw (AssertionError) t;
        }
        throw new AssertionError(where + " threw " + t.getClass().getName() + ", not VerificationException: " + t, t);
    }

    /**
     * Reads every accessor of an accepted receipt. A receipt the library says
     * is Apple-signed is one the caller immediately takes apart, so an accessor
     * that throws on an accepted-but-strange receipt leaks just as surely as a
     * verifier that throws.
     */
    static void touch(AppReceipt receipt) {
        readAll("AppReceipt", receipt, RECEIPT_ACCESSORS);
        for (InAppPurchase purchase : receipt.inAppPurchases()) {
            readAll("InAppPurchase", purchase, IN_APP_ACCESSORS);
        }
    }

    static void touch(TransactionPayload payload) {
        readAll("TransactionPayload", payload, TRANSACTION_ACCESSORS);
    }

    static void touch(AppTransactionPayload payload) {
        readAll("AppTransactionPayload", payload, APP_TRANSACTION_ACCESSORS);
    }

    /** Reads every claim of an accepted JWS payload, for the same reason. */
    static void touch(Map<String, Object> claims) {
        try {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                sink(entry.getKey());
                sink(entry.getValue());
            }
        } catch (Throwable t) {
            throw leaked("JWS claims", t);
        }
    }

    /**
     * Every no-argument accessor the class itself declares, collected once.
     * Reflective rather than a hand-written list so that an accessor added to
     * the library is covered without anyone remembering to add it here.
     */
    private static Method[] accessors(Class<?> type) {
        List<Method> found = new ArrayList<Method>();
        for (Method method : type.getMethods()) {
            if (method.getDeclaringClass() == type
                    && method.getParameterCount() == 0
                    && method.getReturnType() != void.class) {
                found.add(method);
            }
        }
        return found.toArray(new Method[0]);
    }

    private static void readAll(String where, Object value, Method[] methods) {
        for (Method method : methods) {
            try {
                sink(method.invoke(value));
            } catch (InvocationTargetException e) {
                throw leaked(where + "." + method.getName() + "()", e.getCause());
            } catch (IllegalAccessException e) {
                throw new AssertionError("cannot read " + where + "." + method.getName() + "()", e);
            }
        }
    }

    /** Keeps a JIT that can see this whole harness from deleting the reads above. */
    private static void sink(Object value) {
        if (value != null && value.hashCode() == 0xdeadbeef && System.nanoTime() == 0L) {
            throw new IllegalStateException("unreachable");
        }
    }

    // -------------------------------------------------------------- fixtures

    /**
     * {@code APRV_FIXTURES} when run.sh set it, else the repository layout, so
     * that replaying a crasher by hand from java/fuzz/ needs no environment.
     */
    private static Path fixturesDir() {
        String configured = System.getenv("APRV_FIXTURES");
        Path path =
                configured != null && !configured.isEmpty() ? Paths.get(configured) : Paths.get("..", "..", "fixtures");
        if (!Files.isDirectory(path)) {
            throw new IllegalStateException(
                    "fixtures directory not found at " + path.toAbsolutePath() + "; set APRV_FIXTURES");
        }
        return path;
    }

    private static byte[] read(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read fixture " + path, e);
        }
    }

    private static X509Certificate certificate(Path path) {
        try {
            return (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(read(path)));
        } catch (CertificateException e) {
            throw new IllegalStateException("cannot parse fixture certificate " + path, e);
        }
    }

    private static byte[] hex(byte[] text) {
        String trimmed = new String(text, StandardCharsets.US_ASCII).trim();
        byte[] out = new byte[trimmed.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
