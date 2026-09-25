package bakeoff.jni;

/** A verifier was configured with invalid arguments, such as unparsable root certificates. */
public class ConfigurationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param detail what was wrong */
    public ConfigurationException(String detail) { super(detail); }
}
