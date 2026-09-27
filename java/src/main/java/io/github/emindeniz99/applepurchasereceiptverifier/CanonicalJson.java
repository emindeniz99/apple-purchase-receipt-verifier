package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Writes the canonical JSON of {@link ReceiptPayload#toJson()}, the form every
 * port must produce byte for byte: no whitespace, keys in the order the
 * caller writes them, only the escapes JSON requires ({@code "} and
 * {@code \} as {@code \"} and {@code \\}, every other character below U+0020
 * as a lowercase <code>&#92;u00xx</code>), {@code /} unescaped, and non-ASCII
 * characters written raw.
 *
 * <p>Written by hand rather than through Jackson's generator, which uses the
 * short escapes ({@code \n}, {@code \t}) that the canonical form does not.</p>
 */
final class CanonicalJson {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final StringBuilder out;
    private boolean first = true;

    private CanonicalJson(StringBuilder out) {
        this.out = out;
    }

    /** Starts an object in {@code out}; call {@link #end()} to close it. */
    static CanonicalJson object(StringBuilder out) {
        out.append('{');
        return new CanonicalJson(out);
    }

    void end() {
        out.append('}');
    }

    CanonicalJson string(String key, @Nullable String value) {
        key(key);
        if (value == null) {
            out.append("null");
        } else {
            quote(out, value);
        }
        return this;
    }

    CanonicalJson number(String key, @Nullable Long value) {
        key(key);
        out.append(value == null ? "null" : value.toString());
        return this;
    }

    /** A 64-bit id, written as a JSON string so JavaScript readers do not round it. */
    CanonicalJson id(String key, @Nullable Long value) {
        return string(key, value == null ? null : value.toString());
    }

    CanonicalJson bool(String key, @Nullable Boolean value) {
        key(key);
        out.append(value == null ? "null" : value.toString());
        return this;
    }

    CanonicalJson bytes(String key, byte @Nullable [] value) {
        return string(key, value == null ? null : Base64.getEncoder().encodeToString(value));
    }

    /** {@code {"13": ["<base64>", ...], ...}} in the map's own order. */
    CanonicalJson attributes(String key, Map<Integer, List<byte[]>> attributes) {
        key(key);
        CanonicalJson object = object(out);
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            object.key(entry.getKey().toString());
            out.append('[');
            boolean firstValue = true;
            for (byte[] value : entry.getValue()) {
                if (!firstValue) {
                    out.append(',');
                }
                firstValue = false;
                quote(out, Base64.getEncoder().encodeToString(value));
            }
            out.append(']');
        }
        object.end();
        return this;
    }

    /** Writes the key and its colon; the caller appends the value to {@link #out}. */
    StringBuilder key(String key) {
        if (!first) {
            out.append(',');
        }
        first = false;
        quote(out, key);
        out.append(':');
        return out;
    }

    static void quote(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20) {
                out.append("\\u00").append(HEX[c >> 4]).append(HEX[c & 0xF]);
            } else {
                out.append(c);
            }
        }
        out.append('"');
    }
}
