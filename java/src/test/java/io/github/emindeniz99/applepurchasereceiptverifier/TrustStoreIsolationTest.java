package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Trust reaches this library through exactly one door: the {@code trustedRoots}
 * argument. Not through the JDK's {@code cacerts}, not through
 * {@code -Djavax.net.ssl.trustStore}, not through {@link TrustManagerFactory}'s
 * defaults, not through any platform verifier, and not off the network.
 *
 * <p>Java is the port where that is easiest to lose, because the JDK hands out
 * an ambient trust store for free: {@code TrustManagerFactory.init((KeyStore)
 * null)} is one line, it silently reads {@code javax.net.ssl.trustStore} or
 * falls back to {@code $JAVA_HOME/lib/security/cacerts}, and
 * {@link PKIXParameters} has a {@code KeyStore} constructor that turns that
 * store into anchors. Every one of those is a single edit away from the
 * {@code PKIXParameters(Set&lt;TrustAnchor&gt;)} this library actually uses.</p>
 *
 * <p>So the rule is asserted the same three ways the python, swift and go ports
 * assert it (see {@code python/tests/test_trust_isolation.py},
 * {@code swift/Tests/.../TrustStoreIsolationTests.swift},
 * {@code go/systemtrust_test.go}):</p>
 *
 * <ul>
 *   <li><b>environmentally</b> — a certificate authority this JVM genuinely
 *       trusts buys an attacker nothing. A child JVM is started with
 *       {@code -Djavax.net.ssl.trustStore} pointing at a store holding the
 *       fixture roots, the child <em>establishes</em> (rather than assumes)
 *       that the JDK's own default trust manager now trusts exactly those two
 *       certificates, and the library still refuses the matching receipt and
 *       JWS under the bundled Apple anchors. The other direction too: this
 *       machine's real {@code cacerts}, handed to the library as its whole
 *       anchor set, refuses a genuine Apple receipt that the bundled roots
 *       accept.</li>
 *   <li><b>structurally</b> — no file under {@code src/main/java} names a
 *       trust store, a trust manager, a key store, a socket, an HTTP client or
 *       a subprocess, and both PKIX parameter objects are built from the
 *       caller's {@code Set<TrustAnchor>} and never from a {@code KeyStore}.</li>
 *   <li><b>positively</b> — the anchor set that reaches the JDK's path builder
 *       and path validator is captured, and it is exactly the caller's roots:
 *       nothing appended, dropped or substituted in transit.</li>
 * </ul>
 *
 * <p>This test class names {@code javax.net.ssl}, {@code TrustManagerFactory}
 * and {@code ProcessBuilder} on purpose — that is how it plants the trust store
 * it then proves irrelevant. The scan below covers {@code src/main/java} only.</p>
 */
class TrustStoreIsolationTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures");
    private static final Path MAIN_SOURCES = Paths.get("src", "main", "java");
    private static final String BUNDLE = "com.example.app";
    private static final String GENUINE_BUNDLE = "dev.bonzer.weeka.app";
    private static final String STORE_PASSWORD = "changeit";
    private static final String SPY_PROVIDER = "TrustStoreIsolationSpy";

    // ------------------------------------------------------------------
    // (a) behavioural — an ambient trust store, and the host's own cacerts
    // ------------------------------------------------------------------

    /**
     * The strongest offline form of the pinning claim: make the JDK genuinely
     * trust a certificate authority, prove the JDK's own default trust manager
     * accepts it, and show that the library still refuses chains under it.
     *
     * <p>It runs in a child JVM because {@code javax.net.ssl.trustStore} is a
     * startup-shaped setting — a JVM that has already built a default trust
     * manager may keep it — and because the point is a process whose ambient
     * trust store is the planted one from its very first instruction, exactly
     * as a host operator would configure it. The go port forks for the same
     * reason.</p>
     */
    @Test
    void aTrustStoreThisJvmGenuinelyTrustsMovesNoVerdict(@TempDir Path tmp) throws Exception {
        Path java = javaExecutable();
        assumeTrue(java != null, "no java executable next to java.home, so no child JVM can be started");

        Path store = tmp.resolve("planted-truststore.jks");
        KeyStore planted = KeyStore.getInstance("JKS");
        planted.load(null, null);
        planted.setCertificateEntry("receipt-root", cert("generated", "receipt-root.der"));
        planted.setCertificateEntry("jws-root", cert("generated", "jws-root.der"));
        try (OutputStream out = Files.newOutputStream(store)) {
            planted.store(out, STORE_PASSWORD.toCharArray());
        }

        ProcessBuilder child = new ProcessBuilder(
                java.toString(),
                "-Djavax.net.ssl.trustStore=" + store.toAbsolutePath(),
                "-Djavax.net.ssl.trustStorePassword=" + STORE_PASSWORD,
                "-Djavax.net.ssl.trustStoreType=JKS",
                "-cp",
                System.getProperty("java.class.path"),
                PlantedTrustStoreChild.class.getName(),
                FIXTURES.toAbsolutePath().toString(),
                store.toAbsolutePath().toString());
        // Cleared so the child's ambient trust store is the planted one and
        // nothing else: both variables can carry a -Djavax.net.ssl.trustStore
        // of their own, and a CI runner or a proxied developer machine
        // routinely sets them.
        child.environment().remove("JAVA_TOOL_OPTIONS");
        child.environment().remove("_JAVA_OPTIONS");
        child.redirectErrorStream(true);

        Process process = child.start();
        String output = drain(process.getInputStream());
        assertTrue(process.waitFor(5, TimeUnit.MINUTES), "the child JVM did not exit:\n" + output);
        assertEquals(0, process.exitValue(), "the child JVM failed:\n" + output);
        // The premise, read back out of the child rather than assumed: without
        // it every refusal the child asserts could be a refusal for any reason.
        assertTrue(
                output.contains(PlantedTrustStoreChild.PREMISE),
                "the child did not establish that the JDK trusts the planted store:\n" + output);
        assertTrue(output.contains(PlantedTrustStoreChild.DONE), "the child stopped early:\n" + output);
    }

    /** Runs inside the child JVM described above; see that test for the why. */
    public static final class PlantedTrustStoreChild {

        static final String PREMISE = "premise: the JDK's default trust manager trusts exactly the planted roots";
        static final String DONE = "all planted-trust-store assertions held";

        public static void main(String[] args) throws Exception {
            Path fixtures = Paths.get(args[0]);
            String storePath = args[1];

            require(
                    storePath.equals(System.getProperty("javax.net.ssl.trustStore")),
                    "javax.net.ssl.trustStore is " + System.getProperty("javax.net.ssl.trustStore")
                            + ", not the planted store, so nothing below would prove anything");

            X509Certificate receiptRoot = certificate(read(fixtures, "generated", "receipt-root.der"));
            X509Certificate jwsRoot = certificate(read(fixtures, "generated", "jws-root.der"));

            // The premise. TrustManagerFactory.init((KeyStore) null) is the
            // JDK's "use the default trust store" call — the one line this
            // library must never contain — and here it now answers with the
            // planted roots and with nothing from cacerts.
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            Set<X509Certificate> ambient = new HashSet<X509Certificate>();
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager) {
                    ambient.addAll(Arrays.asList(((X509TrustManager) manager).getAcceptedIssuers()));
                }
            }
            require(
                    ambient.equals(new HashSet<X509Certificate>(Arrays.asList(receiptRoot, jwsRoot))),
                    "the planted store did not become this JVM's default trust store (it trusts " + ambient.size()
                            + " certificates)");
            System.out.println(PREMISE);

            byte[] receipt = read(fixtures, "generated", "receipt.der");
            String jws = text(fixtures, "generated", "transaction.jws");
            Set<X509Certificate> plantedReceipt = Collections.singleton(receiptRoot);
            Set<X509Certificate> plantedJws = Collections.singleton(jwsRoot);

            // Positive controls first: the only thing separating these from
            // the refusals below is which anchors were passed.
            require(
                    BUNDLE.equals(new ReceiptVerifier(plantedReceipt, BUNDLE)
                            .verify(receipt)
                            .bundleId()),
                    "the receipt does not verify under the root that signed it");
            require(
                    BUNDLE.equals(new JwsVerifier(plantedJws, BUNDLE, EnumSet.of(Environment.SANDBOX))
                            .verifyTransaction(jws)
                            .bundleId()),
                    "the transaction does not verify under the root that signed it");

            // And the refusals: the same bytes, under the bundled Apple
            // anchors, while the JVM around them trusts the roots that signed
            // them.
            requireInvalidChain(
                    () -> new ReceiptVerifier(AppleRootCerts.receiptRoots(), BUNDLE).verify(receipt),
                    "a receipt whose root is in the JVM's trust store");
            requireInvalidChain(
                    () -> ReceiptVerifier.verifyReceiptCore(receipt, AppleRootCerts.receiptRoots()),
                    "the same receipt through verifyReceiptCore");
            requireInvalidChain(
                    () -> new JwsVerifier(AppleRootCerts.jwsRoots(), BUNDLE, EnumSet.of(Environment.SANDBOX))
                            .verifyTransaction(jws),
                    "a transaction whose root is in the JVM's trust store");

            // No ambient set to fall back to, even now that there is a
            // populated one to fall back to: an empty anchor set is a
            // configuration error and is refused up front.
            requireIllegalArgument(
                    () -> new ReceiptVerifier(Collections.<X509Certificate>emptySet(), BUNDLE),
                    "an empty receipt anchor set");
            requireIllegalArgument(
                    () -> ReceiptVerifier.verifyReceiptCore(receipt, Collections.<X509Certificate>emptySet()),
                    "an empty anchor set through verifyReceiptCore");
            requireIllegalArgument(
                    () -> new JwsVerifier(
                            Collections.<X509Certificate>emptySet(), BUNDLE, EnumSet.of(Environment.SANDBOX)),
                    "an empty JWS anchor set");

            // The other direction: the planted store did not take anything
            // away either. Genuine Apple material still verifies under the
            // bundled roots in this JVM whose trust store holds neither.
            String genuine = text(fixtures, "public-receipts", "receipt-sandbox-g5.b64");
            require(
                    GENUINE_BUNDLE.equals(new ReceiptVerifier(AppleRootCerts.receiptRoots(), GENUINE_BUNDLE)
                            .verify(Base64.getMimeDecoder().decode(genuine))
                            .bundleId()),
                    "a genuine Apple receipt stopped verifying under the bundled roots");

            System.out.println(DONE);
        }

        private static void require(boolean condition, String what) {
            if (!condition) {
                throw new IllegalStateException(what);
            }
        }

        private static void requireInvalidChain(Body body, String what) {
            try {
                body.run();
            } catch (VerificationException e) {
                require(e.reason() == Reason.INVALID_CHAIN, what + " was refused as " + e.reason() + ": " + e);
                return;
            } catch (Exception e) {
                throw new IllegalStateException(what + " raised " + e, e);
            }
            throw new IllegalStateException(what + " was accepted");
        }

        private static void requireIllegalArgument(Body body, String what) {
            try {
                body.run();
            } catch (IllegalArgumentException e) {
                return;
            } catch (Exception e) {
                throw new IllegalStateException(what + " raised " + e, e);
            }
            throw new IllegalStateException(what + " was accepted");
        }

        private static byte[] read(Path fixtures, String... segments) throws IOException {
            Path path = fixtures;
            for (String segment : segments) {
                path = path.resolve(segment);
            }
            return Files.readAllBytes(path);
        }

        private static String text(Path fixtures, String... segments) throws IOException {
            return new String(read(fixtures, segments), StandardCharsets.US_ASCII).trim();
        }

        private static X509Certificate certificate(byte[] der) throws Exception {
            return (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        }
    }

    /**
     * The complement, and the one that needs no child: this machine's real
     * {@code cacerts} — every certificate authority the JDK ships, the set a
     * {@code TrustManagerFactory} default would hand out — confers no standing
     * on anything here, and taking it as the anchor set refuses a genuine
     * Apple receipt that the bundled roots accept.
     */
    @Test
    void theJdksOwnCacertsConferNoStanding() throws Exception {
        Set<X509Certificate> cacerts = cacerts();
        assumeTrue(!cacerts.isEmpty(), "this JDK's cacerts could not be read, so it cannot be handed to the library");
        assertTrue(
                cacerts.size() > 1, "cacerts holds " + cacerts.size() + " certificates, so it was not read properly");

        // The bundled anchors are loaded from this library's own resources,
        // never from the JDK. If that ever changed, this is the first thing
        // that would stop being true — but Apple is not in the Mozilla root
        // programme most cacerts are built from, so a JDK that did ship its
        // roots would make the refusals below vacuous rather than wrong.
        Set<X509Certificate> bundled = new HashSet<X509Certificate>(AppleRootCerts.receiptRoots());
        bundled.retainAll(cacerts);
        assumeTrue(bundled.isEmpty(), "this JDK ships an Apple root in cacerts, so it cannot be used as a foil");

        // The premise: genuinely Apple-signed material this library does
        // accept, so the refusal below is about the anchors and not about the
        // receipt.
        byte[] genuine = Base64.getMimeDecoder().decode(fixtureText("public-receipts", "receipt-sandbox-g5.b64"));
        assertEquals(
                GENUINE_BUNDLE,
                new ReceiptVerifier(AppleRootCerts.receiptRoots(), GENUINE_BUNDLE)
                        .verify(genuine)
                        .bundleId());

        assertInvalidChain(() -> new ReceiptVerifier(cacerts, GENUINE_BUNDLE).verify(genuine));
        assertInvalidChain(() -> ReceiptVerifier.verifyReceiptCore(fixture("generated", "receipt.der"), cacerts));
        assertInvalidChain(() -> new JwsVerifier(cacerts, BUNDLE, EnumSet.of(Environment.SANDBOX))
                .verifyTransaction(fixtureText("generated", "transaction.jws")));

        // And a public root gains nothing from sitting next to Apple's in the
        // caller's list: the anchor still has to have issued the chain.
        Set<X509Certificate> mixed = new LinkedHashSet<X509Certificate>(AppleRootCerts.receiptRoots());
        mixed.add(cacerts.iterator().next());
        assertEquals(
                GENUINE_BUNDLE,
                new ReceiptVerifier(mixed, GENUINE_BUNDLE).verify(genuine).bundleId());
        assertInvalidChain(() -> ReceiptVerifier.verifyReceiptCore(fixture("generated", "receipt.der"), mixed));
    }

    /**
     * The failure mode this rules out: "no anchors given, so use the system
     * ones". There is no ambient set to fall back to, and asking for one is
     * refused at construction rather than silently widened. Asserted in the
     * child JVM too, where a populated ambient store exists to fall back to.
     */
    @Test
    void anEmptyAnchorSetIsAConfigurationErrorNotAFallback() {
        Set<X509Certificate> none = Collections.emptySet();
        assertThrows(IllegalArgumentException.class, () -> new ReceiptVerifier(none, BUNDLE));
        assertThrows(
                IllegalArgumentException.class, () -> new JwsVerifier(none, BUNDLE, EnumSet.of(Environment.SANDBOX)));
        assertThrows(
                IllegalArgumentException.class,
                () -> ReceiptVerifier.verifyReceiptCore(fixture("generated", "receipt.der"), none));
        assertThrows(IllegalArgumentException.class, () -> new ReceiptVerifier(null, BUNDLE));
        assertThrows(
                IllegalArgumentException.class, () -> new JwsVerifier(null, BUNDLE, EnumSet.of(Environment.SANDBOX)));
    }

    // ------------------------------------------------------------------
    // (b) structural — the source scan
    // ------------------------------------------------------------------

    /**
     * Every spelling by which a main source could reach a trust store this
     * library was not handed, run a subprocess, or reach the network. Matched
     * as substrings of the source with comments removed, so the javadoc that
     * legitimately explains what the code avoids — and the Apple PKI URL in
     * {@link AppleRootCerts} — is not a hit.
     *
     * <p>{@code Runtime} and {@code Process} are deliberately absent from the
     * list and their dangerous spellings named instead: {@code RuntimeException}
     * and {@code JsonProcessingException} are legitimate and frequent.</p>
     */
    private static final String[] FORBIDDEN = {
        "javax.net.ssl",
        "TrustManager",
        "SSLContext",
        "KeyStore",
        "cacerts",
        "trustStore",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "/etc/ssl",
        "/etc/pki",
        "keychain",
        "Keychain",
        "java.net.http",
        "HttpClient",
        "HttpURLConnection",
        "URLConnection",
        "openConnection",
        "java.net.URL",
        "Socket",
        "InetAddress",
        "ProcessBuilder",
        "Runtime.getRuntime",
        "Runtime.exec",
        "System.getenv",
        "System.getProperty",
        "Security.addProvider",
        "Security.insertProviderAt",
        "Security.setProperty",
        "http://",
        "https://",
    };

    @Test
    void noMainSourceCanReachATrustStoreOrTheNetwork() throws Exception {
        List<Path> sources = mainSources();
        for (Path source : sources) {
            String code = codeStrippedOfComments(new String(Files.readAllBytes(source), StandardCharsets.UTF_8));
            for (String needle : FORBIDDEN) {
                assertFalse(
                        code.contains(needle),
                        source.getFileName() + " names \"" + needle + "\" in code: anchors come from the caller's "
                                + "trustedRoots and bytes come from the caller, never from the platform");
            }
        }
    }

    /**
     * The PKIX seam itself. Both {@link PKIXParameters} and its builder
     * subclass have a {@code (KeyStore, CertSelector)} constructor that turns
     * a key store — {@code cacerts} included — into trust anchors; this asserts
     * that the only constructor either verifier reaches takes the caller's
     * {@code Set<TrustAnchor>} field, and that revocation checking (the one
     * thing PKIX validation would otherwise fetch over the network) is turned
     * off at every one of them.
     */
    @Test
    void pkixParametersAreOnlyEverBuiltFromTheCallersAnchorSet() throws Exception {
        Pattern construction =
                Pattern.compile("new\\s+(PKIXBuilderParameters|PKIXParameters)\\s*\\(\\s*([A-Za-z0-9_]+)");
        // Every place `trustAnchors` is declared — the field on each verifier
        // and the parameters that carry it down to the builder — so the
        // identifier the constructions above read is pinned to its type as
        // well as its name.
        Pattern declaration = Pattern.compile("(?<![.\\w])([A-Za-z_][\\w<>]*)\\s+trustAnchors\\s*[;,)=]");
        int constructions = 0;
        int declarations = 0;
        int revocationDisabled = 0;
        for (Path source : mainSources()) {
            String code = codeStrippedOfComments(new String(Files.readAllBytes(source), StandardCharsets.UTF_8));
            Matcher matcher = construction.matcher(code);
            while (matcher.find()) {
                constructions++;
                assertEquals(
                        "trustAnchors",
                        matcher.group(2),
                        source.getFileName() + " builds " + matcher.group(1) + " from " + matcher.group(2)
                                + " rather than from the caller's pinned anchor set");
            }
            Matcher declared = declaration.matcher(code);
            while (declared.find()) {
                declarations++;
                assertEquals(
                        "Set<TrustAnchor>",
                        declared.group(1),
                        source.getFileName() + " declares trustAnchors as " + declared.group(1)
                                + ", so the PKIX parameters are not built from an explicit anchor set");
            }
            Matcher revocation =
                    Pattern.compile("setRevocationEnabled\\(\\s*false\\s*\\)").matcher(code);
            while (revocation.find()) {
                revocationDisabled++;
            }
        }
        // One per verified path: the receipt path builder and the JWS path
        // validator. A third would be a new trust seam nobody reviewed.
        assertEquals(2, constructions, "the number of PKIX parameter objects this library builds changed");
        assertTrue(declarations >= 2, "no trustAnchors declaration was found, so the type check above scanned nothing");
        assertEquals(2, revocationDisabled, "a PKIX parameter object no longer disables revocation checking");
    }

    // ------------------------------------------------------------------
    // (c) positive — the anchors that actually reach the JDK
    // ------------------------------------------------------------------

    /**
     * A source scan proves nothing was <em>imported</em>; this proves nothing
     * was <em>added</em>. A JCE provider shadowing {@code CertPathBuilder.PKIX}
     * captures the very parameter object the library hands the JDK, and its
     * anchor set is the caller's roots, exactly — no host root folded in, none
     * of the caller's dropped.
     *
     * <p>Two anchors are passed, one of which cannot possibly issue this
     * chain, so an implementation that filtered, deduplicated or substituted
     * the set would show here rather than pass silently.</p>
     */
    @Test
    void theReceiptPathBuilderSeesExactlyTheCallersAnchors() throws Exception {
        Set<X509Certificate> passed = new LinkedHashSet<X509Certificate>(
                Arrays.asList(cert("generated", "jws-root.der"), cert("generated", "receipt-root.der")));
        List<PKIXParameters> captured = capture(() -> assertEquals(
                BUNDLE,
                new ReceiptVerifier(passed, BUNDLE)
                        .verify(fixture("generated", "receipt.der"))
                        .bundleId()));
        assertAnchorsAre(passed, captured);

        // Nothing added, either: drop the anchor that signed the chain and no
        // ambient set makes up for it.
        assertInvalidChain(() -> ReceiptVerifier.verifyReceiptCore(
                fixture("generated", "receipt.der"), Collections.singleton(cert("generated", "jws-root.der"))));
    }

    /** The same for the JWS path, which validates rather than builds. */
    @Test
    void theJwsPathValidatorSeesExactlyTheCallersAnchors() throws Exception {
        Set<X509Certificate> passed = new LinkedHashSet<X509Certificate>(
                Arrays.asList(cert("generated", "receipt-root.der"), cert("generated", "jws-root.der")));
        List<PKIXParameters> captured = capture(() -> assertEquals(
                BUNDLE,
                new JwsVerifier(passed, BUNDLE, EnumSet.of(Environment.SANDBOX))
                        .verifyTransaction(fixtureText("generated", "transaction.jws"))
                        .bundleId()));
        assertAnchorsAre(passed, captured);

        assertInvalidChain(() -> new JwsVerifier(
                        Collections.singleton(cert("generated", "receipt-root.der")),
                        BUNDLE,
                        EnumSet.of(Environment.SANDBOX))
                .verifyTransaction(fixtureText("generated", "transaction.jws")));
    }

    private static void assertAnchorsAre(Set<X509Certificate> expected, List<PKIXParameters> captured) {
        assertEquals(1, captured.size(), "the library did not run exactly one PKIX validation");
        Set<TrustAnchor> anchors = captured.get(0).getTrustAnchors();
        Set<X509Certificate> certificates = new HashSet<X509Certificate>();
        for (TrustAnchor anchor : anchors) {
            // A name-constrained or CA-name-only anchor would be a different
            // trust decision from the one the caller asked for.
            assertNull(anchor.getNameConstraints(), "an anchor grew name constraints in transit");
            assertNull(anchor.getCAName(), "an anchor is not the caller's certificate");
            certificates.add(anchor.getTrustedCert());
        }
        assertEquals(expected.size(), anchors.size(), "the anchor set changed size in transit");
        assertEquals(new HashSet<X509Certificate>(expected), certificates, "the anchor set is not the caller's");
        assertFalse(captured.get(0).isRevocationEnabled(), "revocation checking would reach the network");
    }

    /**
     * Runs {@code body} with a provider that shadows the JDK's PKIX path
     * builder and validator, and returns the parameter objects it saw. The
     * real implementations are resolved before the shadow is installed, both
     * so the delegation cannot recurse and so the verification under test
     * still genuinely runs.
     */
    private static List<PKIXParameters> capture(Body body) throws Exception {
        CAPTURED.clear();
        REAL_BUILDER = CertPathBuilder.getInstance("PKIX");
        REAL_VALIDATOR = CertPathValidator.getInstance("PKIX");
        Security.insertProviderAt(new SpyProvider(), 1);
        try {
            body.run();
        } finally {
            Security.removeProvider(SPY_PROVIDER);
        }
        return new ArrayList<PKIXParameters>(CAPTURED);
    }

    private static final List<PKIXParameters> CAPTURED = Collections.synchronizedList(new ArrayList<PKIXParameters>());
    private static CertPathBuilder REAL_BUILDER;
    private static CertPathValidator REAL_VALIDATOR;

    /** Public and instantiable by name because the JCA loads SPIs reflectively. */
    public static final class SpyProvider extends Provider {

        private static final long serialVersionUID = 1L;

        @SuppressWarnings("deprecation") // the (String, String, String) constructor is Java 9+; this is a Java 8 port.
        public SpyProvider() {
            super(SPY_PROVIDER, 1.0d, "captures the PKIX parameters this library builds");
            put("CertPathBuilder.PKIX", SpyCertPathBuilder.class.getName());
            put("CertPathValidator.PKIX", SpyCertPathValidator.class.getName());
        }
    }

    public static final class SpyCertPathBuilder extends CertPathBuilderSpi {

        public SpyCertPathBuilder() {}

        @Override
        public CertPathBuilderResult engineBuild(CertPathParameters params)
                throws CertPathBuilderException, InvalidAlgorithmParameterException {
            CAPTURED.add((PKIXParameters) params);
            return REAL_BUILDER.build(params);
        }
    }

    public static final class SpyCertPathValidator extends CertPathValidatorSpi {

        public SpyCertPathValidator() {}

        @Override
        public CertPathValidatorResult engineValidate(CertPath path, CertPathParameters params)
                throws CertPathValidatorException, InvalidAlgorithmParameterException {
            CAPTURED.add((PKIXParameters) params);
            return REAL_VALIDATOR.validate(path, params);
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private interface Body {
        void run() throws Exception;
    }

    private static void assertInvalidChain(Body body) {
        try {
            body.run();
        } catch (VerificationException e) {
            assertEquals(Reason.INVALID_CHAIN, e.reason(), e.getMessage());
            return;
        } catch (Exception e) {
            throw new AssertionError("expected INVALID_CHAIN, got " + e, e);
        }
        throw new AssertionError("expected INVALID_CHAIN but the material was accepted");
    }

    private static byte[] fixture(String... segments) throws IOException {
        Path path = FIXTURES;
        for (String segment : segments) {
            path = path.resolve(segment);
        }
        return Files.readAllBytes(path);
    }

    private static String fixtureText(String... segments) throws IOException {
        return new String(fixture(segments), StandardCharsets.US_ASCII).trim();
    }

    private static X509Certificate cert(String... segments) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(fixture(segments)));
    }

    /** Every certificate in this JDK's own {@code cacerts}, or none if it cannot be read. */
    private static Set<X509Certificate> cacerts() {
        Path path = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        if (!Files.isReadable(path)) {
            return Collections.emptySet();
        }
        // JKS on a Java 8 JDK and on Debian's ca-certificates-java; PKCS12 on
        // a modern Temurin. The compatibility mode of "JKS" reads both from
        // Java 9 on, so the fallback only matters on 8.
        for (String type : new String[] {"JKS", "PKCS12"}) {
            try (InputStream in = Files.newInputStream(path)) {
                KeyStore store = KeyStore.getInstance(type);
                store.load(in, STORE_PASSWORD.toCharArray());
                Set<X509Certificate> roots = new LinkedHashSet<X509Certificate>();
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    Certificate certificate = store.getCertificate(aliases.nextElement());
                    if (certificate instanceof X509Certificate) {
                        roots.add((X509Certificate) certificate);
                    }
                }
                if (!roots.isEmpty()) {
                    return roots;
                }
            } catch (Exception e) {
                // Try the next type; an unreadable cacerts skips the test.
            }
        }
        return Collections.emptySet();
    }

    private static Path javaExecutable() {
        Path home = Paths.get(System.getProperty("java.home"));
        for (String name : new String[] {"java", "java.exe"}) {
            Path candidate = home.resolve("bin").resolve(name);
            if (Files.isExecutable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static String drain(InputStream stream) throws IOException {
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    private static List<Path> mainSources() throws IOException {
        List<Path> sources;
        try (Stream<Path> walk = Files.walk(MAIN_SOURCES)) {
            sources = walk.filter(path -> path.getFileName().toString().endsWith(".java"))
                    .sorted()
                    .collect(Collectors.toList());
        }
        // Fails loudly if the scan is ever pointed at the wrong tree, which is
        // the way a scan like this rots into always passing.
        assertTrue(
                sources.size() >= 8, "the source scan found only " + sources.size() + " files under " + MAIN_SOURCES);
        return sources;
    }

    /**
     * A Java source with its comments removed, so the ban lands on code and not
     * on prose that legitimately names what the code avoids. String and
     * character literals are tracked, so a {@code //} inside one is not a
     * comment; text blocks are not, because these sources compile at the Java 8
     * baseline where there are none.
     */
    private static String codeStrippedOfComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        boolean inBlockComment = false;
        boolean inString = false;
        boolean inChar = false;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            if (inBlockComment) {
                if (c == '*' && next == '/') {
                    inBlockComment = false;
                    i++;
                }
                continue;
            }
            if (inString || inChar) {
                if (c == '\\') {
                    out.append(c).append(next);
                    i++;
                    continue;
                }
                if (inString && c == '"') {
                    inString = false;
                }
                if (inChar && c == '\'') {
                    inChar = false;
                }
                out.append(c);
                continue;
            }
            if (c == '/' && next == '/') {
                while (i < source.length() && source.charAt(i) != '\n') {
                    i++;
                }
                out.append('\n');
                continue;
            }
            if (c == '/' && next == '*') {
                inBlockComment = true;
                i++;
                continue;
            }
            if (c == '"') {
                inString = true;
            }
            if (c == '\'') {
                inChar = true;
            }
            out.append(c);
        }
        return out.toString();
    }
}
