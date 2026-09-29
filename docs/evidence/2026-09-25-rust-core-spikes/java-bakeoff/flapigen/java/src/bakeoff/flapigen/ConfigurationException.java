package bakeoff.flapigen;

/** The verifier was misconfigured (e.g. unparseable root). Thrown from native code via ThrowNew. */
public class ConfigurationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param detail the core's ConfigError detail. */
    public ConfigurationException(String detail) { super(detail); }
}
