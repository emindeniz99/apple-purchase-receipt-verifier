package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The three readers this port writes by hand, driven directly rather than
 * through a verifier — no CMS parse, no chain build, no signature check in
 * front of them, so one execution costs microseconds and the mutations land on
 * the reader instead of on the certificate machinery.
 *
 * <ul>
 *   <li>{@code ReceiptVerifier.parsePayload} — the receipt attribute walk:
 *       the ASN.1 SET, the optional Xcode double wrap, the per-attribute type
 *       and value decode, the in-app sub-walk, the date and integer bounds.
 *   <li>{@code ReceiptBase64.decode} — the base64 dialect Apple's clients
 *       actually send.
 *   <li>{@code JwsVerifier.parseJson} — the strict base64url reader and the
 *       Jackson tree parse behind it, the JWS glue.
 * </ul>
 *
 * <p>Reflection rather than an exported test hook: nothing about the shipped
 * jar changes to make it fuzzable. The reflective call costs a few hundred
 * nanoseconds against readers that take microseconds.
 *
 * <p><strong>The containment invariant differs per reader, and the difference
 * is real rather than a concession.</strong> {@code parsePayload} is reached
 * only through {@code ReceiptVerifier.verifyCore}, which catches
 * {@code RuntimeException} and rewraps it as
 * {@code INVALID_RECEIPT_FORMAT} — so an unchecked exception out of
 * BouncyCastle here is contained by design and is not a finding, while an
 * {@code Error} (a {@code StackOverflowError} from nesting, an
 * {@code OutOfMemoryError} from a length prefix) escapes that catch and is.
 * The other two have no such guard above them — {@code verify(String)} decodes
 * before it enters the guarded core, and the whole JWS path is unguarded — so
 * for them the invariant is the strict one: only {@code VerificationException}.
 */
public final class FuzzReaders {

    private FuzzReaders() {}

    private static final Method PARSE_PAYLOAD = method(ReceiptVerifier.class, "parsePayload", byte[].class);
    private static final Method DECODE_BASE64 = method(receiptBase64(), "decode", String.class);
    private static final Method PARSE_JSON = method(JwsVerifier.class, "parseJson", String.class, String.class);

    public static void fuzzerTestOneInput(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);

        // The attribute walk, on the payload bytes as they come out of the CMS
        // envelope. RuntimeException-contained: see the class javadoc.
        call("ReceiptVerifier.parsePayload", PARSE_PAYLOAD, null, true, (Object) data);

        // The base64 decoder, on the same bytes read as a string.
        call("ReceiptBase64.decode", DECODE_BASE64, null, false, text);

        // The JWS glue, twice: once on the raw text, which mostly exercises the
        // strict base64url rejection path, and once on the input re-encoded as
        // base64url, which puts the fuzzer's own bytes in front of Jackson.
        call("JwsVerifier.parseJson(raw)", PARSE_JSON, Harness.JWS_VERIFIER, false, text, "header");
        call(
                "JwsVerifier.parseJson(base64url)",
                PARSE_JSON,
                Harness.JWS_VERIFIER,
                false,
                Base64.getUrlEncoder().withoutPadding().encodeToString(data),
                "payload");
    }

    /**
     * @param runtimeContained whether a caller above this reader catches
     *                         {@code RuntimeException}; see the class javadoc
     */
    private static void call(String where, Method method, Object receiver, boolean runtimeContained, Object... args) {
        try {
            method.invoke(receiver, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof VerificationException) {
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

    private static Class<?> receiptBase64() {
        try {
            return Class.forName("io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptBase64");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("ReceiptBase64 moved or was renamed", e);
        }
    }

    private static Method method(Class<?> owner, String name, Class<?>... parameters) {
        try {
            Method method = owner.getDeclaredMethod(name, parameters);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(owner.getName() + "." + name + " moved or changed signature", e);
        }
    }
}
