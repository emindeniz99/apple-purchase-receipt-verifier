package bakeoff.jni;

import java.util.List;
import java.util.Set;

/** Verifies StoreKit 2 signed transactions (JWS). Thread-safe; close it to free the native object. */
public final class JwsVerifier extends NativeHandle {
    /**
     * @param bundleId the app's bundle identifier
     * @param environments the environments to accept
     * @param appAppleId the app's Apple id to require, or null
     * @param roots DER root certificates; null for Apple's pinned roots
     * @throws ConfigurationException if the configuration is invalid
     */
    public JwsVerifier(String bundleId, Set<Environment> environments, Long appAppleId, List<byte[]> roots) {
        super(Native.jvNew(bundleId, mask(environments), appAppleId != null,
                appAppleId == null ? 0 : appAppleId, Native.roots(roots)));
    }

    private static int mask(Set<Environment> envs) {
        int m = 0;
        for (Environment e : envs) m |= e.mask();
        return m;
    }

    @Override void free(long h) { Native.jvFree(h); }

    /**
     * Verifies a signed transaction.
     * @param jws the compact JWS
     * @return the verified payload
     * @throws VerificationException if it does not verify
     */
    public TransactionPayload verifyTransaction(String jws) throws VerificationException {
        return Native.payload(call(h -> Native.jvVerifyTransaction(h, jws)));
    }
}
