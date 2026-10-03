package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * One JSON value read into unmodifiable maps and lists, strings, numbers,
 * booleans and {@link #NULL}, for this artifact's two readers: {@link Wire}
 * reads the module's answers strictly, {@link ServerJson} reads the
 * server's own JSON leniently.
 */
final class JsonTree {

    private JsonTree() {}

    /** Stands for a JSON {@code null} inside the tree. */
    static final Object NULL = new Object();

    /**
     * The value that starts at {@code token}. An integer that fits 64 bits
     * is a {@link Long}. With {@code strict}, a larger integer, a fraction or
     * an exponent is refused, since the wire writes none of them; without
     * it, such a number arrives as Jackson reads it. A document that ends
     * early, or a number {@code strict} refuses, is {@code refuse} applied to
     * a message that names no value.
     *
     * @throws IOException when Jackson cannot read the text as JSON
     */
    static Object read(
            JsonParser parser,
            @Nullable JsonToken token,
            boolean strict,
            Function<String, ? extends RuntimeException> refuse)
            throws IOException {
        if (token == null) {
            throw refuse.apply("the document ends early");
        }
        switch (token) {
            case START_OBJECT: {
                Map<String, Object> object = new LinkedHashMap<>();
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String name = parser.currentName();
                    object.put(name, read(parser, parser.nextToken(), strict, refuse));
                }
                return Collections.unmodifiableMap(object);
            }
            case START_ARRAY: {
                List<Object> array = new ArrayList<>();
                JsonToken next;
                while ((next = parser.nextToken()) != JsonToken.END_ARRAY) {
                    array.add(read(parser, next, strict, refuse));
                }
                return Collections.unmodifiableList(array);
            }
            case VALUE_STRING:
                return parser.getText();
            case VALUE_NUMBER_INT: {
                Number number = parser.getNumberValue();
                if (!(number instanceof BigInteger)) {
                    return number.longValue();
                }
                if (strict) {
                    throw refuse.apply("a number beyond 64 bits");
                }
                return number;
            }
            case VALUE_NUMBER_FLOAT:
                if (strict) {
                    throw refuse.apply("a " + token + " token");
                }
                return parser.getNumberValue();
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return NULL;
            default:
                throw refuse.apply("a " + token + " token");
        }
    }
}
