package bakeoff.jni;

/** The input failed verification. */
public class VerificationException extends Exception {
    private static final long serialVersionUID = 1L;
    /** The reason. */
    private final Reason reason;
    /** The detail message. */
    private final String detail;

    /** Called from native code with the core's reason token. */
    VerificationException(String token, String detail) {
        super(token + ": " + detail);
        this.reason = Reason.fromToken(token);
        this.detail = detail;
    }

    /** @return the machine-readable reason */
    public Reason reason() { return reason; }

    /** @return a human-readable detail message */
    public String detail() { return detail; }
}
