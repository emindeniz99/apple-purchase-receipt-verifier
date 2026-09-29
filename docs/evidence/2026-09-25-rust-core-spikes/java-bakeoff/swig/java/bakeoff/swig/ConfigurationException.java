package bakeoff.swig;

/**
 * A mistake in the call itself, not a verdict about any input: a rejected
 * verifier/endpoint configuration (empty bundle id, empty or unknown
 * environment mask, unparsable root certificate bytes, ...), or an ABI-side
 * status in its {@code 100+} band (null pointer, invalid UTF-8, a caught
 * panic). Unchecked, because a caller who configured a verifier wrong has a
 * bug, not an input to react to.
 */
public final class ConfigurationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ConfigurationException(String message) {
        super(message);
    }

    public ConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
