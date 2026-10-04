package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * How the implementation reports a failed check internally. Never reaches a
 * caller: {@link DefaultVerifier} turns it into a {@link Failure}, keeping the
 * cause only for {@link Reason#UNREADABLE_PAYLOAD},
 * {@link Reason#INTERNAL_ERROR} and the {@link Reason#MALFORMED} that
 * {@link #unexpected} builds.
 *
 * <p>The message never quotes the input, so it is safe to log as is.</p>
 */
final class VerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    private final boolean keepCause;

    VerificationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
        this.keepCause = false;
    }

    VerificationException(Reason reason, String message, @Nullable Throwable cause) {
        this(reason, message, cause, reason == Reason.UNREADABLE_PAYLOAD || reason == Reason.INTERNAL_ERROR);
    }

    private VerificationException(Reason reason, String message, @Nullable Throwable cause, boolean keepCause) {
        super(message, cause);
        this.reason = reason;
        this.keepCause = keepCause;
    }

    /**
     * MALFORMED for an unchecked exception Jackson or BouncyCastle threw
     * before trust. MALFORMED, not INTERNAL_ERROR: nothing is signed yet, and
     * anyone could otherwise raise the 21009 alarm. The message names only
     * the class, so it stays free of input; the exception is kept as the
     * caller's cause, the one place a developer can see what was rejected.
     */
    static VerificationException unexpected(RuntimeException e) {
        return new VerificationException(
                Reason.MALFORMED, "unexpected " + e.getClass().getName(), e, true);
    }

    Reason reason() {
        return reason;
    }

    /**
     * The public view. The cause is kept where it explains Apple-signed
     * content or a library fault, and behind {@link #unexpected}, where it is
     * the developer's only clue. Everywhere else it is a parser or provider
     * exception about unverified input whose message can quote raw
     * certificate text that a logged stack trace would print, and the
     * reason and message already say what was refused.
     */
    Failure toFailure() {
        return new Failure(reason, String.valueOf(getMessage()), keepCause ? getCause() : null);
    }
}
