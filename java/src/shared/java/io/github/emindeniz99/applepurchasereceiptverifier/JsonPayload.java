package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A verified JWS payload: the JSON object Apple signed, unchanged, and the
 * environment it names. Parse the JSON with the library of your choice,
 * such as Apple's own app-store-server-library model classes. Immutable.
 */
public final class JsonPayload {

    private final String json;
    private final @Nullable Environment environment;

    /**
     * Public so callers can build payloads for a mocked {@link Verifier}.
     * The verifier passes the {@code environment} the JSON names
     * ({@link #environment()}); a hand-built payload states its own.
     */
    public JsonPayload(String json, @Nullable Environment environment) {
        this.json = Objects.requireNonNull(json, "json");
        this.environment = environment;
    }

    /** The verified payload as UTF-8 JSON text, exactly as it was signed. */
    public String json() {
        return json;
    }

    /**
     * The environment the payload names, as the verifier read it: from the
     * first of the three places Apple documents that is present, the
     * top-level {@code environment} (a transaction, renewal info),
     * {@code data.environment} (an App Store Server Notification V2) and
     * {@code summary.environment} (a summary notification).
     * {@code Production} is {@link Environment#PRODUCTION} and
     * {@code Sandbox} {@link Environment#SANDBOX}; anything else there
     * ({@code Xcode}, {@code LocalTesting}, a value that is not a string), or
     * none of the three, is {@code null}. It states what Apple's value means
     * and decides nothing.
     */
    public @Nullable Environment environment() {
        return environment;
    }

    /** Equal when {@link #json()} and {@link #environment()} are. */
    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof JsonPayload
                && json.equals(((JsonPayload) other).json)
                && environment == ((JsonPayload) other).environment;
    }

    @Override
    public int hashCode() {
        return 31 * json.hashCode() + Objects.hashCode(environment);
    }

    /**
     * {@link #json()}: the whole signed payload, the customer's transaction
     * ids included. Logging a payload logs all of it.
     */
    @Override
    public String toString() {
        return json;
    }
}
