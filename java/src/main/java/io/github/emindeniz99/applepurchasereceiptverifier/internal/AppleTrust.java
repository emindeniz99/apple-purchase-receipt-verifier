package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 * Trust material both verifiers share. An implementation detail, public only
 * because the JWS and receipt verifiers sit in different packages; see
 * {@link SafeText}.
 */
public final class AppleTrust {

    /**
     * Apple marker OID stamped on the leaf that signs App Store JWS payloads
     * and legacy receipts alike. The chain check alone is not enough:
     * developer "Apple Distribution" certificates chain through the same WWDR
     * intermediate to the same pinned root, so without this purpose check any
     * developer could sign a forged payload or receipt.
     */
    public static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";

    private AppleTrust() {}

    /**
     * One {@link TrustAnchor} per root, with no name constraints.
     *
     * @throws IllegalArgumentException if {@code trustedRoots} is null or empty
     */
    public static Set<TrustAnchor> anchors(Set<X509Certificate> trustedRoots) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        return anchors;
    }
}
