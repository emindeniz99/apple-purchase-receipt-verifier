package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import io.github.emindeniz99.applepurchasereceiptverifier.SignatureAlgorithm;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.Nullable;

/**
 * The certificate signature algorithms a verifier accepts, and the check that
 * this JVM can validate a chain signed with each of them.
 *
 * <p>The chain is validated by the JDK's own PKIX implementation, which obeys
 * {@code jdk.certpath.disabledAlgorithms} in {@code java.security}. A host
 * that disables an algorithm Apple signs with would otherwise answer
 * INVALID_CHAIN for genuine receipts, one request at a time, and nothing
 * would tell the operator why. So {@link #require} builds a throwaway
 * two-certificate chain per algorithm, with the key type and size Apple uses,
 * and validates it the same way. A failure there is the host's, and the
 * verifier's constructor throws. The result is kept per algorithm for the
 * life of the process.</p>
 *
 * <p>An implementation detail, public only because the verifiers sit in
 * different packages; see {@link SafeText}.</p>
 */
public final class ChainAlgorithms {

    /** Algorithm → "" when this JVM validates it, else why not. */
    private static final Map<SignatureAlgorithm, String> CHECKED = new ConcurrentHashMap<SignatureAlgorithm, String>();

    private ChainAlgorithms() {}

    /**
     * A copy of {@code algorithms} once this JVM is shown to validate a
     * chain signed with each one.
     *
     * @throws IllegalArgumentException if {@code algorithms} is null or empty
     * @throws IllegalStateException    if this JVM cannot validate one of them
     */
    public static Set<SignatureAlgorithm> require(Set<SignatureAlgorithm> algorithms) {
        if (algorithms == null || algorithms.isEmpty()) {
            throw new IllegalArgumentException("chain algorithms must not be empty");
        }
        Set<SignatureAlgorithm> copy = EnumSet.copyOf(algorithms);
        for (SignatureAlgorithm algorithm : copy) {
            String failure = CHECKED.computeIfAbsent(algorithm, ChainAlgorithms::check);
            if (!failure.isEmpty()) {
                throw new IllegalStateException(algorithm.jcaName()
                        + " is in this verifier's chain algorithms, but this JVM cannot validate a certificate"
                        + " signed with it (" + failure + "). Apple signs " + appleUse(algorithm)
                        + " with it. Take it out of jdk.certpath.disabledAlgorithms (java.security), or pass a"
                        + " set without " + algorithm.name() + "; " + appleUse(algorithm)
                        + " then fail with INVALID_CHAIN.");
            }
        }
        return Collections.unmodifiableSet(copy);
    }

    /** The name of the first certificate signature algorithm outside {@code accepted}, or null. */
    public static @Nullable String firstRejected(
            Iterable<? extends java.security.cert.Certificate> chain, Set<SignatureAlgorithm> accepted) {
        for (java.security.cert.Certificate certificate : chain) {
            X509Certificate x509 = (X509Certificate) certificate;
            SignatureAlgorithm algorithm = SignatureAlgorithm.fromOid(x509.getSigAlgOID());
            if (algorithm == null || !accepted.contains(algorithm)) {
                return x509.getSigAlgName();
            }
        }
        return null;
    }

    private static String appleUse(SignatureAlgorithm algorithm) {
        switch (algorithm) {
            case SHA1_WITH_RSA:
                return "legacy receipts";
            case SHA256_WITH_RSA:
                return "current receipts";
            default:
                return "every StoreKit 2 JWS";
        }
    }

    /** "" if a chain signed with {@code algorithm} validates here, else the reason it does not. */
    private static String check(SignatureAlgorithm algorithm) {
        try {
            KeyPairGenerator generator;
            if (algorithm == SignatureAlgorithm.SHA1_WITH_RSA || algorithm == SignatureAlgorithm.SHA256_WITH_RSA) {
                generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
            } else {
                generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec(
                        algorithm == SignatureAlgorithm.SHA384_WITH_ECDSA ? "secp384r1" : "secp256r1"));
            }
            KeyPair issuer = generator.generateKeyPair();
            KeyPair subject = generator.generateKeyPair();
            long now = System.currentTimeMillis();
            Date notBefore = new Date(now - 86_400_000L);
            Date notAfter = new Date(now + 86_400_000L);
            X500Principal issuerName = new X500Principal("CN=chain algorithm check issuer");
            X509Certificate root = certificate(issuerName, issuerName, issuer, issuer, algorithm, notBefore, notAfter);
            X509Certificate leaf = certificate(
                    issuerName,
                    new X500Principal("CN=chain algorithm check subject"),
                    subject,
                    issuer,
                    algorithm,
                    notBefore,
                    notAfter);
            // The throwaway root just minted, never the caller's: this checks
            // the JVM's algorithm policy, and its result trusts nothing.
            Set<TrustAnchor> trustAnchors = Collections.singleton(new TrustAnchor(root, null));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX")
                    .validate(
                            CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(leaf)),
                            params);
            return "";
        } catch (Exception e) {
            String message = e.getMessage();
            return e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
        }
    }

    private static X509Certificate certificate(
            X500Principal issuer,
            X500Principal subject,
            KeyPair subjectKeys,
            KeyPair issuerKeys,
            SignatureAlgorithm algorithm,
            Date notBefore,
            Date notAfter)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.ONE, notBefore, notAfter, subject, subjectKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(issuer.equals(subject)));
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder(algorithm.jcaName())
                        .setProvider(BouncyCastle.PROVIDER)
                        .build(issuerKeys.getPrivate())));
    }
}
