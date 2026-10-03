package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * The server's own JSON, as opposed to the module's answers ({@link Wire}):
 * {@code GET /v1/info} and RFC 9457 problems. Read leniently into a
 * {@link JsonTree}, since only a few members matter.
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
            Object value = JsonTree.read(parser, first, false, IllegalStateException::new);
            return parser.nextToken() == null ? value : null;
        } catch (IOException | RuntimeException e) {
            return null;
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
