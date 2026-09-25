package bakeoff.jni;

import java.util.List;

/** Verifies legacy PKCS#7 app receipts. Thread-safe; close it to free the native object. */
public final class ReceiptVerifier extends NativeHandle {
    /**
     * A verifier trusting Apple's pinned roots.
     * @param bundleId the app's bundle identifier
     */
    public ReceiptVerifier(String bundleId) { this(bundleId, null); }

    /**
     * A verifier trusting the given roots.
     * @param bundleId the app's bundle identifier
     * @param roots DER root certificates; null for Apple's pinned roots
     * @throws ConfigurationException if a root does not parse
     */
    public ReceiptVerifier(String bundleId, List<byte[]> roots) {
        super(Native.rvNew(bundleId, Native.roots(roots)));
    }

    @Override void free(long h) { Native.rvFree(h); }

    /**
     * Verifies DER receipt bytes.
     * @param der the receipt
     * @return the verified receipt
     * @throws VerificationException if it does not verify
     */
    public AppReceipt verify(byte[] der) throws VerificationException {
        return Native.receipt(call(h -> Native.rvVerify(h, der)));
    }

    /**
     * Verifies a base64 receipt, as apps upload it.
     * @param b64 the receipt, base64
     * @return the verified receipt
     * @throws VerificationException if it does not verify
     */
    public AppReceipt verifyBase64(String b64) throws VerificationException {
        return Native.receipt(call(h -> Native.rvVerifyBase64(h, b64)));
    }
}
