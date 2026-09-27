package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * How the implementation reports a failed check internally. Never reaches a
 * caller: {@link DefaultVerifier} turns it into a {@link Failure}, keeping the
 * cause only for {@link Reason#UNREADABLE_PAYLOAD} and
 * {@link Reason#INTERNAL_ERROR}.
 *
 * <p>The message is log-safe by construction: anything quoted out of the
 * input goes through {@link SafeText} before it is put here.</p>
 */
final class VerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    VerificationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    VerificationException(Reason reason, String message, @Nullable Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    Reason reason() {
        return reason;
    }

    /**
     * The public view. The cause is kept only where it explains
     * Apple-signed content or a library fault: behind any other reason it is
     * a parser or provider exception about unverified input, whose message
     * can quote raw certificate text that a logged stack trace would print.
     */
    Failure toFailure() {
        boolean keepCause = reason == Reason.UNREADABLE_PAYLOAD || reason == Reason.INTERNAL_ERROR;
        return new Failure(reason, String.valueOf(getMessage()), keepCause ? getCause() : null);
    }
}
