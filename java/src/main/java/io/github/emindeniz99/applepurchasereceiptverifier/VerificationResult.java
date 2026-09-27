package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The outcome of one verification: either the verified payload or the
 * {@link Failure}, never both. Immutable.
 *
 * @param <T> the payload type
 */
public final class VerificationResult<T> {

    private final @Nullable T payload;
    private final @Nullable Failure failure;

    private VerificationResult(@Nullable T payload, @Nullable Failure failure) {
        this.payload = payload;
        this.failure = failure;
    }

    /** A verified result carrying {@code payload}; for callers mocking {@link Verifier}. */
    public static <T> VerificationResult<T> of(T payload) {
        return new VerificationResult<T>(Objects.requireNonNull(payload, "payload"), null);
    }

    /** A failed result; for callers mocking {@link Verifier}. */
    public static <T> VerificationResult<T> failed(Failure failure) {
        return new VerificationResult<T>(null, Objects.requireNonNull(failure, "failure"));
    }

    /** Whether the input verified; exactly when {@link #payload()} is non-null. */
    public boolean verified() {
        return payload != null;
    }

    /** The verified payload, set only when {@link #verified()}. */
    public @Nullable T payload() {
        return payload;
    }

    /** Why verification failed, set only when not {@link #verified()}. */
    public @Nullable Failure failure() {
        return failure;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof VerificationResult)) {
            return false;
        }
        VerificationResult<?> that = (VerificationResult<?>) other;
        return Objects.equals(payload, that.payload) && Objects.equals(failure, that.failure);
    }

    @Override
    public int hashCode() {
        return Objects.hash(payload, failure);
    }

    @Override
    public String toString() {
        return payload != null ? "VerificationResult[verified]" : "VerificationResult[" + failure + "]";
    }
}
