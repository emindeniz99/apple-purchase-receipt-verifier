package bakeoff.swig;

/**
 * A verdict about the input: the payload was well-formed enough to reach a
 * decision, and the decision was "reject". Thrown by every verify call that
 * returns an {@code AprvReason} in the {@code 1..12} band.
 */
public final class VerificationException extends Exception {
    private static final long serialVersionUID = 1L;

    private final Reason reason;
    private final String detail;

    VerificationException(Reason reason, String detail) {
        super(reason + ": " + detail);
        this.reason = reason;
        this.detail = detail;
    }

    /** Which of the canonical cross-port reasons this rejection was. */
    public Reason reason() {
        return reason;
    }

    /** A short, non-sensitive description from the C ABI. Never contains
     *  receipt bytes, claims or key material. */
    public String detail() {
        return detail;
    }
}
