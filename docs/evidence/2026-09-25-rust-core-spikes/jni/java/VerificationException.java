package spike.jni;

/** Thrown when a receipt fails verification. The message starts with the reason token. */
public final class VerificationException extends Exception {
    public VerificationException(String message) { super(message); }
}
