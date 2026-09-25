package bakeoff.swig;

import bakeoff.swig.raw.SWIGTYPE_p_AprvJwsVerifier;
import bakeoff.swig.raw.aprv;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifies signed StoreKit 2 transaction JWS payloads: certificate chain,
 * signature, bundle id and accepted environment. Thread-safe on the same
 * terms as {@link ReceiptVerifier}.
 */
public final class JwsVerifier implements AutoCloseable {
    private final SWIGTYPE_p_AprvJwsVerifier handle;

    /** {@code appAppleId} is required to accept a Production {@code AppTransaction};
     *  {@code null} means "not configured". {@code roots}, each DER-encoded,
     *  replace Apple's three bundled roots; {@code null} selects them. */
    public JwsVerifier(String bundleId, Set<Environment> envs, Long appAppleId, List<byte[]> roots) {
        long mask = Environment.maskOf(envs);
        BigInteger appId = (appAppleId == null) ? BigInteger.ZERO : BigInteger.valueOf(appAppleId);
        try {
            handle = aprv.jws_new(bundleId, mask, appId, Native.toArray(roots));
        } catch (RuntimeException e) {
            throw new ConfigurationException(e.getMessage(), e);
        }
    }

    /** Verifies a signed transaction, then checks bundle id and environment. */
    public TransactionPayload verifyTransaction(String jws) throws VerificationException {
        int[] status = new int[1];
        String json = aprv.jws_verify_transaction(handle, jws, status);
        Map<String, Object> m = Json.parseObject(json);
        if (status[0] == 0) return TransactionPayload.fromJson(json, m);
        Native.throwVerification(status[0], m);
        throw new AssertionError("unreachable");
    }

    @Override
    public void close() {
        aprv.aprv_verifier_free_jws(handle);
    }
}
