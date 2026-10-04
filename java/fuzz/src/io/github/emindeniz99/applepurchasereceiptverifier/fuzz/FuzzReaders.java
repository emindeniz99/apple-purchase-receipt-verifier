package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.Reason;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * The readers this port writes by hand, driven directly rather than through
 * the verifier: no CMS parse, no chain build, no signature check in front of
 * them, so one execution costs microseconds and the mutations land on the
 * reader instead of on the certificate machinery.
 *
 * <ul>
 *   <li>{@code ReceiptDecoder.parse}: the receipt attribute walk: the ASN.1
 *       SET, the optional Xcode double wrap, the per-attribute type and value
 *       decode, the in-app sub-walk, the date and integer bounds.
 *   <li>{@code StrictBase64.decode}: the base64 dialect Apple's clients
 *       actually send.
 *   <li>{@code JwsCore.Header.read} and {@code JwsCore.readPayload}: the
 *       streaming reads of a decoded JWS header and payload.
 * </ul>
 *
 * <p>Reflection rather than an exported test hook: the implementation is
 * package-private and nothing about the shipped jar changes to make it
 * fuzzable.
 *
 * <p><strong>The containment invariant differs per reader.</strong>
 * {@code ReceiptDecoder.parse} is reached only through
 * {@code ReceiptCore.parseSignedPayload}, which catches
 * {@code RuntimeException} and reports it as UNREADABLE_PAYLOAD, so an
 * unchecked exception out of BouncyCastle here is contained by design and is
 * not a finding, while an {@code Error} (a {@code StackOverflowError} from
 * nesting, an {@code OutOfMemoryError} from a length prefix) escapes that
 * catch and is. The others contain everything themselves: only the
 * package's own {@code VerificationException} may come out.
 */
public final class FuzzReaders {

    private FuzzReaders() {}

    private static final String PACKAGE = "io.github.emindeniz99.applepurchasereceiptverifier.";

    private static final Method PARSE_PAYLOAD = method("ReceiptDecoder", "parse", byte[].class);
    private static final Method DECODE_BASE64 =
            method("StrictBase64", "decode", String.class, Reason.class, String.class);
    private static final Method READ_HEADER = method("JwsCore$Header", "read", byte[].class);
    private static final Method READ_PAYLOAD = method("JwsCore", "readPayload", byte[].class);

    public static void fuzzerTestOneInput(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);
        call("ReceiptDecoder.parse", PARSE_PAYLOAD, true, (Object) data);
        call("StrictBase64.decode", DECODE_BASE64, false, text, Reason.MALFORMED, "receipt");
        call("JwsCore.Header.read", READ_HEADER, false, (Object) data);
        call("JwsCore.readPayload", READ_PAYLOAD, false, (Object) data);
    }

    /**
     * @param runtimeContained whether a caller above this reader catches
     *                         {@code RuntimeException}; see the class javadoc
     */
    private static void call(String where, Method method, boolean runtimeContained, Object... args) {
        try {
            method.invoke(null, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause.getClass().getName().equals(PACKAGE + "VerificationException")) {
                return;
            }
            if (runtimeContained && cause instanceof RuntimeException) {
                return;
            }
            throw Harness.leaked(where, cause);
        } catch (IllegalAccessException e) {
            throw new AssertionError("cannot reach " + where, e);
        }
    }

    private static Method method(String simpleName, String name, Class<?>... parameters) {
        try {
            Method method = Class.forName(PACKAGE + simpleName).getDeclaredMethod(name, parameters);
            method.setAccessible(true);
            return method;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            throw new IllegalStateException(simpleName + "." + name + " moved or changed signature", e);
        }
    }
}
