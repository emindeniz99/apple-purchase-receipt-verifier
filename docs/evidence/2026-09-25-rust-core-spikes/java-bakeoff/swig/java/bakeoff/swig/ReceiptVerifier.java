package bakeoff.swig;

import bakeoff.swig.raw.SWIGTYPE_p_AprvReceiptVerifier;
import bakeoff.swig.raw.aprv;

import java.util.List;
import java.util.Map;

/**
 * Verifies legacy PKCS#7 app receipts against a bundle id (and, once built,
 * a fixed set of trust anchors). Thread-safe: the underlying C handle is
 * immutable once built and any number of threads may verify through the
 * same {@code ReceiptVerifier} concurrently (see the ABI header's THREADING
 * note); only {@link #close()} must not race a verify call.
 */
public final class ReceiptVerifier implements AutoCloseable {
    private final SWIGTYPE_p_AprvReceiptVerifier handle;

    /** Pinned to Apple's three bundled roots. */
    public ReceiptVerifier(String bundleId) {
        this(bundleId, null);
    }

    /** {@code roots}, each one DER-encoded, replace Apple's bundled roots;
     *  {@code null} selects them. */
    public ReceiptVerifier(String bundleId, List<byte[]> roots) {
        try {
            handle = aprv.receipt_new(bundleId, Native.toArray(roots));
        } catch (RuntimeException e) {
            throw new ConfigurationException(e.getMessage(), e);
        }
    }

    /** Verifies a raw DER receipt. */
    public AppReceipt verify(byte[] der) throws VerificationException {
        int[] status = new int[1];
        String json = aprv.receipt_verify_der(handle, der, status);
        return decode(status[0], json);
    }

    /** Verifies a base64 receipt, as a client would send it. */
    public AppReceipt verifyBase64(String b64) throws VerificationException {
        int[] status = new int[1];
        String json = aprv.receipt_verify_base64(handle, b64, status);
        return decode(status[0], json);
    }

    private AppReceipt decode(int status, String json) throws VerificationException {
        Map<String, Object> m = Json.parseObject(json);
        if (status == 0) return AppReceipt.fromNormalizedJson(m);
        Native.throwVerification(status, m);
        throw new AssertionError("unreachable");
    }

    /** Releases the underlying C handle. Not safe to call while another
     *  thread is inside {@link #verify} or {@link #verifyBase64} on this
     *  verifier. */
    @Override
    public void close() {
        aprv.aprv_verifier_free_receipt(handle);
    }
}
