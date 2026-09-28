package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import org.jspecify.annotations.Nullable;

/**
 * The one streaming read of a JSON object's top-level members, shared by the
 * JWS header and payload and the verifyReceipt request body, so a repeated
 * name resolves the same way (the last one wins) in all three. What follows
 * the object is each caller's own decision.
 */
final class JsonFields {

    private JsonFields() {}

    /** Called with each member's name and first value token; may consume the value. */
    interface Visitor {
        void field(String name, JsonToken value, JsonParser parser) throws IOException;
    }

    /**
     * Hands each top-level member of the object {@code parser} starts at to
     * {@code visitor}, in order, and leaves the parser on its closing brace.
     * False, with nothing visited, when the first token is not an object.
     */
    static boolean read(JsonParser parser, Visitor visitor) throws IOException {
        if (parser.nextToken() != JsonToken.START_OBJECT) {
            return false;
        }
        while (parser.nextToken() == JsonToken.FIELD_NAME) {
            String name = parser.currentName();
            visitor.field(name, parser.nextToken(), parser);
            parser.skipChildren();
        }
        return true;
    }

    /**
     * A number as epoch milliseconds, the way Jackson's tree model converts
     * it: an integer must fit a long, and a fraction or exponent is read as
     * a double and truncated when it lies within the long range (2^63
     * saturates). Null for anything else, 1e300 included.
     */
    static @Nullable Long instant(JsonParser parser, JsonToken value) {
        try {
            if (value == JsonToken.VALUE_NUMBER_INT) {
                return parser.getLongValue();
            }
            if (value == JsonToken.VALUE_NUMBER_FLOAT) {
                double number = parser.getDoubleValue();
                return number >= Long.MIN_VALUE && number <= Long.MAX_VALUE ? (long) number : null;
            }
        } catch (IOException e) {
            // An integer no long holds.
        }
        return null;
    }

    /** Strict UTF-8 with no byte order mark (RFC 8259 8.1), or null; Jackson would guess UTF-16 or UTF-32. */
    static @Nullable String text(byte[] bytes) {
        try {
            String text = StandardCharsets.UTF_8
                    .newDecoder()
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
            return text.startsWith("\uFEFF") ? null : text;
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
