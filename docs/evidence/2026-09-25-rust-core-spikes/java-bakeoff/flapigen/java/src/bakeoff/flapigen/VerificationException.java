package bakeoff.flapigen;

/** A verification verdict from the Rust core: the input was rejected. Thrown from native code. */
public class VerificationException extends Exception {
    private static final long serialVersionUID = 1L;
    private final Reason reason;
    private final String detail;

    /** Called from native code with the Rust {@code Reason} discriminant. */
    VerificationException(int reason, String detail) {
        super(Reason.fromInt(reason) + ": " + detail);
        this.reason = Reason.fromInt(reason);
        this.detail = detail;
    }

    /** @return why verification failed. */
    public Reason reason() { return reason; }

    /** @return human-readable detail; never parse it. */
    public String detail() { return detail; }
}
