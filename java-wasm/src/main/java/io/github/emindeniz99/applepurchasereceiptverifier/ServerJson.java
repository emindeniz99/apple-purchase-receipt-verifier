package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * The server's own JSON, as opposed to the module's answers ({@link Wire}):
 * {@code GET /v1/info} and RFC 9457 problems. Read leniently, as maps,
 * lists, strings, numbers and booleans, since only a few members matter.
 */
final class ServerJson {

    private ServerJson() {}

    private static final JsonFactory JSON = new JsonFactory();

    /** The parsed value, or {@code null} when {@code text} is not one JSON value. */
    static @Nullable Object parse(String text) {
        try (JsonParser parser = JSON.createParser(text)) {
            JsonToken first = parser.nextToken();
            if (first == null) {
                return null;
            }
            Object value = value(parser, first);
            return parser.nextToken() == null ? value : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static @Nullable Object value(JsonParser parser, @Nullable JsonToken token) throws IOException {
        if (token == null) {
            throw new IOException("the document ends early");
        }
        switch (token) {
            case START_OBJECT: {
                Map<String, Object> object = new LinkedHashMap<>();
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String name = parser.currentName();
                    object.put(name, value(parser, parser.nextToken()));
                }
                return object;
            }
            case START_ARRAY: {
                List<Object> array = new ArrayList<>();
                JsonToken next;
                while ((next = parser.nextToken()) != JsonToken.END_ARRAY) {
                    array.add(value(parser, next));
                }
                return array;
            }
            case VALUE_STRING:
                return parser.getText();
            case VALUE_NUMBER_INT:
            case VALUE_NUMBER_FLOAT:
                return parser.getNumberValue();
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return null;
            default:
                throw new IOException("an unexpected token " + token);
        }
    }

    /** A member of an object, or {@code null}. */
    static @Nullable Object member(@Nullable Object object, String name) {
        return object instanceof Map ? ((Map<?, ?>) object).get(name) : null;
    }

    /** A problem's {@code code}, or {@code HTTP_<status>} when the body is not a problem with one. */
    static ServerProblem problem(HttpConn.Response response) {
        Object body = parse(response.text());
        Object code = member(body, "code");
        Object detail = member(body, "detail");
        return new ServerProblem(
                response.status,
                code instanceof String ? (String) code : "HTTP_" + response.status,
                detail instanceof String ? (String) detail : "(no detail)");
    }
}
