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
     * The exception behind the failure, when there is one, for logs. An
     * {@link Reason#INTERNAL_ERROR} this library raised itself (a runtime
     * failure, an answer it could not read, a clock that threw) carries one.
     * In the main artifact an {@link Reason#UNREADABLE_PAYLOAD} carries the
     * parser's exception, and a {@link Reason#MALFORMED} whose message is
     * {@code "unexpected <class>"} carries the unchecked exception
     * BouncyCastle or Jackson threw before the signature, for debugging.
     * That exception's message is theirs and may quote fragments of the
     * unverified input, so log it as you would the input. In the
     * {@code -wasm} artifact the core decides every reason from the input
     * and none of them carries one. Match on {@link #reason()}, not on this.
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
