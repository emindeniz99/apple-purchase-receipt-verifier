package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A verified JWS payload: the JSON object Apple signed, unchanged. Parse it
 * with the JSON library of your choice, such as Apple's own
 * app-store-server-library model classes. Immutable.
 */
public final class JsonPayload {

    private final String json;

    /** Public so callers can build payloads for a mocked {@link Verifier}. */
    public JsonPayload(String json) {
        this.json = Objects.requireNonNull(json, "json");
    }

    /** The verified payload as UTF-8 JSON text, exactly as it was signed. */
    public String json() {
        return json;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof JsonPayload && json.equals(((JsonPayload) other).json);
    }

    @Override
    public int hashCode() {
        return json.hashCode();
    }

    @Override
    public String toString() {
        return json;
    }
}
