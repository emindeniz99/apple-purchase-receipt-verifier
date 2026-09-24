package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * A certificate signature algorithm a verifier accepts on the chain from the
 * signing leaf up to the pinned root.
 *
 * <p>Each verifier has a default set that covers every chain Apple signs
 * with ({@code ReceiptVerifier.DEFAULT_CHAIN_ALGORITHMS},
 * {@code JwsVerifier.DEFAULT_CHAIN_ALGORITHMS}) and a constructor that takes
 * a smaller one. The constructor checks that this JVM can validate a chain
 * signed with each algorithm in the set, and throws
 * {@link IllegalStateException} if it cannot, so a host policy that disables
 * one of them is found at startup rather than one request at a time. A chain
 * signed with an algorithm outside the set is {@code INVALID_CHAIN}.</p>
 */
public enum SignatureAlgorithm {

    /**
     * sha1WithRSAEncryption, RSA-2048. Apple signs the legacy receipt chain
     * with it: the leaf and the WWDR intermediate alike. Without it every
     * legacy receipt is {@code INVALID_CHAIN}.
     */
    SHA1_WITH_RSA("1.2.840.113549.1.1.5", "SHA1withRSA"),

    /** sha256WithRSAEncryption, RSA-2048. The current receipt chain (WWDR G5). */
    SHA256_WITH_RSA("1.2.840.113549.1.1.11", "SHA256withRSA"),

    /** ecdsa-with-SHA256 over P-256. The JWS signing leaf, issued by WWDR G6. */
    SHA256_WITH_ECDSA("1.2.840.10045.4.3.2", "SHA256withECDSA"),

    /** ecdsa-with-SHA384 over P-384. The JWS WWDR intermediate, issued by Apple Root CA G3. */
    SHA384_WITH_ECDSA("1.2.840.10045.4.3.3", "SHA384withECDSA");

    private final String oid;
    private final String jcaName;

    SignatureAlgorithm(String oid, String jcaName) {
        this.oid = oid;
        this.jcaName = jcaName;
    }

    /** The algorithm's OID, as {@code X509Certificate.getSigAlgOID()} reports it. */
    public String oid() {
        return oid;
    }

    /** The JCA standard name, e.g. {@code SHA1withRSA}. */
    public String jcaName() {
        return jcaName;
    }

    /** The algorithm with this OID, or {@code null} if it is none of these. */
    public static @Nullable SignatureAlgorithm fromOid(@Nullable String oid) {
        for (SignatureAlgorithm algorithm : values()) {
            if (algorithm.oid.equals(oid)) {
                return algorithm;
            }
        }
        return null;
    }
}
