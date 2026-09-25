package spike.jni;

/**
 * Verifies legacy App Store receipts against Apple's pinned root certificates.
 * Plain Java: this class and its Javadoc are hand-written; the work runs in Rust.
 */
public final class ReceiptVerifier implements AutoCloseable {
    static { System.load(System.getProperty("aprv.lib")); }

    private static native long create(String bundleId);
    private static native String verifyBase64(long handle, String base64) throws VerificationException;
    private static native void destroy(long handle);

    private long handle;

    /** @param bundleId the app's bundle identifier the receipt must carry */
    public ReceiptVerifier(String bundleId) { this.handle = create(bundleId); }

    /**
     * Verifies a base64 receipt as apps upload it.
     * @return the receipt's bundle id (spike: the real class returns an AppReceipt)
     * @throws VerificationException if the receipt is not authentic or not for this app
     */
    public String verifyBase64(String base64) throws VerificationException {
        if (handle == 0) throw new IllegalStateException("closed");
        return verifyBase64(handle, base64);
    }

    @Override public synchronized void close() { destroy(handle); handle = 0; }
}
