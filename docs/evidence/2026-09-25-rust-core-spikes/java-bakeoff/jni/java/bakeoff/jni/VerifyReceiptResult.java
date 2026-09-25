package bakeoff.jni;

/**
 * One endpoint outcome: Apple's status plus the receipt or failure reason.
 * Holds the native result, so {@link #toJsonIn} re-renders without verifying again.
 */
public final class VerifyReceiptResult extends NativeHandle {
    VerifyReceiptResult(long handle) { super(handle); }

    @Override void free(long h) { Native.resFree(h); }

    /** @return Apple's status: 0, 21002, 21003, 21007, 21008 or 21009 */
    public long status() { return call(Native::resStatus); }

    /** @return true when the receipt verified, whichever environment it belongs to */
    public boolean verified() { return call(Native::resVerified); }

    /** @return the verified receipt, or null */
    public AppReceipt receipt() {
        byte[] b = call(Native::resReceipt);
        return b == null ? null : Native.receipt(b);
    }

    /** @return why verification failed, or null on success */
    public Reason failureReason() {
        String t = call(Native::resFailureReason);
        return t == null ? null : Reason.fromToken(t);
    }

    /** @return the response body Apple would send */
    public String toJson() { return call(Native::resToJson); }

    /**
     * @param environment the endpoint environment to render for
     * @return the response body that environment's endpoint would send
     * @throws ConfigurationException if the environment is not supported
     */
    public String toJsonIn(Environment environment) { return call(h -> Native.resToJsonIn(h, environment.ordinal())); }
}
