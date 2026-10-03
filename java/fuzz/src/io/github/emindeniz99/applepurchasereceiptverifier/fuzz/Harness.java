package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Verifiers and the invariants the five targets share.
 *
 * <p>Everything is built once in a static initializer and only read from
 * {@code fuzzerTestOneInput}: an anchor set costs a certificate parse and a
 * PKIX {@code TrustAnchor} construction, which at a few hundred thousand
 * executions would be the whole budget.
 */
final class Harness {

    private Harness() {}

    /**
     * Apple's three roots plus the fixture receipt root the re-minted 0.7
     * receipts chain to, fixtures/generated-0.7/receipt-root.der, so that
     * those fixtures and both public Apple receipts get past the chain check
     * and the fuzzer can explore what lies beyond it. The receipts under
     * fixtures/generated/ chain to the 0.6 root, which is not trusted here:
     * they predate 0.7's WWDR marker check and stopped at
     * INVALID_CERTIFICATE_PURPOSE even under that root.
     */
    static final Verifier RECEIPTS;

    /**
     * The anchor set an accepted receipt must fail against: the fixture
     * <em>JWS</em> root, which signed no receipt in this repository.
     * Deliberately a real, well-formed root rather than an empty or corrupt
     * set: "rejected because the anchor set was unusable" would prove nothing.
     */
    static final Verifier UNRELATED_RECEIPTS;

    /** The fixture JWS root: what the generated {@code .jws} fixtures chain to. */
    static final Verifier JWS;

    /** Apple's production roots: unrelated to every JWS fixture here. */
    static final Verifier APPLE;

    private static final Method[] RECEIPT_ACCESSORS = accessors(ReceiptPayload.class);
    private static final Method[] IN_APP_ACCESSORS = accessors(InAppPurchase.class);

    static {
        Path fixtures = fixturesDir();
        X509Certificate receiptRoot = certificate(fixtures.resolve("generated-0.7/receipt-root.der"));
        X509Certificate jwsRoot = certificate(fixtures.resolve("generated/jws-root.der"));

        Set<X509Certificate> receiptAnchors =
                new LinkedHashSet<X509Certificate>(Config.defaults().roots());
        receiptAnchors.add(receiptRoot);
        RECEIPTS = Verifier.create(Config.builder().roots(receiptAnchors).build());
        UNRELATED_RECEIPTS = Verifier.create(
                Config.builder().roots(Collections.singleton(jwsRoot)).build());
        JWS = UNRELATED_RECEIPTS;
        APPLE = Verifier.create(Config.defaults());
    }

    // ----------------------------------------------------------- invariants

    /**
     * Runs one public method. Returns its payload, or {@code null} when the
     * library rejected the input.
     *
     * <p>Anything thrown is the finding: the verify methods never throw, so a
     * BouncyCastle {@code IllegalArgumentException}, a {@code StackOverflowError}
     * out of a nested ASN.1 structure and an {@code OutOfMemoryError} out of a
     * length prefix are all covered by one phrasing. So is a failure of
     * {@link Reason#INTERNAL_ERROR}: it is what the verifier's last-resort
     * catch answers for an exception the checks did not contain, and fuzz
     * input must never be able to raise that alert.</p>
     */
    static <T> T attempt(String where, Supplier<VerificationResult<T>> call) {
        VerificationResult<T> result;
        try {
            result = call.get();
        } catch (Throwable t) {
            throw leaked(where, t);
        }
        if (result == null || result.verified() == (result.failure() != null)) {
            throw new AssertionError(where + " broke its payload/failure invariant: " + result);
        }
        Failure failure = result.failure();
        if (failure != null && failure.reason() == Reason.INTERNAL_ERROR) {
            throw new AssertionError(where + " hit an internal error: " + failure.message(), failure.cause());
        }
        return result.payload();
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
        throw new AssertionError(where + " threw " + t.getClass().getName() + ": " + t, t);
    }

    /**
     * Reads every accessor of an accepted receipt, and its JSON. A receipt
     * the library says is Apple-signed is one the caller immediately takes
     * apart, so an accessor that throws on an accepted-but-strange receipt
     * leaks just as surely as a verifier that throws.
     */
    static void touch(ReceiptPayload receipt) {
        readAll("ReceiptPayload", receipt, RECEIPT_ACCESSORS);
        for (InAppPurchase purchase : receipt.inApp()) {
            readAll("InAppPurchase", purchase, IN_APP_ACCESSORS);
        }
    }

    static void touch(JsonPayload payload) {
        try {
            sink(payload.json());
        } catch (Throwable t) {
            throw leaked("JsonPayload", t);
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
    static void sink(Object value) {
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
}
