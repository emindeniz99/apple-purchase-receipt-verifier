package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Why a verification failed. Immutable.
 *
 * <p>Match on {@link #reason()}. {@link #message()} is for logs and support
 * requests: it never quotes the input's bytes, so it can go into a log line
 * as is, though it may state a date or a count the input declared. Its
 * wording may change between releases.</p>
 */
public final class Failure {

    private final Reason reason;
    private final String message;
    private final @Nullable Throwable cause;

    /** Public so callers can build failures for a mocked {@link Verifier}. */
    public Failure(Reason reason, String message, @Nullable Throwable cause) {
        this.reason = Objects.requireNonNull(reason, "reason");
        this.message = Objects.requireNonNull(message, "message");
        this.cause = cause;
    }

    /** What went wrong, as the value to match on. */
    public Reason reason() {
        return reason;
    }

    /** Safe to log as is; not meant to be parsed. */
    public String message() {
        return message;
    }

    /**
     * The exception behind an {@link Reason#UNREADABLE_PAYLOAD} or
     * {@link Reason#INTERNAL_ERROR}, when there is one; normally {@code null}
     * for every other reason.
     */
    public @Nullable Throwable cause() {
        return cause;
    }

    /** Equal when reason and message are; the cause is not compared. */
    @Override
    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Failure)) {
            return false;
        }
        Failure that = (Failure) other;
        return reason == that.reason && message.equals(that.message);
    }

    @Override
    public int hashCode() {
        return 31 * reason.hashCode() + message.hashCode();
    }

    @Override
    public String toString() {
        return reason + ": " + message;
    }
}
