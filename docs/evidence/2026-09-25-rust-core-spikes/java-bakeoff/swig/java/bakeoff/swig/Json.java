package bakeoff.swig;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, dependency-free JSON reader for the shapes the C ABI returns.
 *
 * <p>This is a real recursive-descent parser (objects, arrays, strings with
 * escapes, numbers, booleans, null), not a shape-specific scraper — but it
 * is intentionally small and unvalidated against adversarial input, because
 * every document it reads here is produced by this library's own C ABI, not
 * by an untrusted third party. See the SWIG entry's report for why a hand
 * -written parser was chosen over a Maven dependency.
 */
final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    /** Parses {@code text} into a {@code Map}/{@code List}/{@code String}/
     *  {@code Long}/{@code Double}/{@code Boolean}/{@code null} tree. */
    static Object parse(String text) {
        Json p = new Json(text);
        p.skipWs();
        Object v = p.value();
        p.skipWs();
        if (p.i != p.s.length()) {
            throw new IllegalArgumentException("trailing data after JSON value at " + p.i);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        return (Map<String, Object>) parse(text);
    }

    // ---- typed accessors, all tolerant of a missing or JSON-null key ----

    static String getString(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : (String) v;
    }

    static Long getLong(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) return null;
        if (v instanceof Long) return (Long) v;
        if (v instanceof Double) return ((Double) v).longValue();
        throw new IllegalArgumentException(key + " is not a number: " + v);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> getObject(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    static List<Object> getArray(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : (List<Object>) v;
    }

    // ---- recursive descent ----

    private Object value() {
        char c = peek();
        switch (c) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default: return number();
        }
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        expect('{');
        skipWs();
        if (peek() == '}') { i++; return m; }
        while (true) {
            skipWs();
            String key = string();
            skipWs();
            expect(':');
            skipWs();
            m.put(key, value());
            skipWs();
            char c = next();
            if (c == '}') break;
            if (c != ',') throw err("expected ',' or '}'");
        }
        return m;
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<Object>();
        expect('[');
        skipWs();
        if (peek() == ']') { i++; return l; }
        while (true) {
            skipWs();
            l.add(value());
            skipWs();
            char c = next();
            if (c == ']') break;
            if (c != ',') throw err("expected ',' or ']'");
        }
        return l;
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') break;
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        int cp = Integer.parseInt(s.substring(i, i + 4), 16);
                        i += 4;
                        b.append((char) cp);
                        break;
                    default: throw err("bad escape \\" + e);
                }
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    private Object number() {
        int start = i;
        boolean isDouble = false;
        if (peek() == '-') i++;
        while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        if (i < s.length() && s.charAt(i) == '.') {
            isDouble = true;
            i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        }
        if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            isDouble = true;
            i++;
            if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        }
        String tok = s.substring(start, i);
        if (tok.isEmpty() || tok.equals("-")) throw err("bad number");
        return isDouble ? (Object) Double.parseDouble(tok) : (Object) Long.parseLong(tok);
    }

    private char peek() {
        if (i >= s.length()) throw err("unexpected end of JSON");
        return s.charAt(i);
    }

    private char next() {
        char c = peek();
        i++;
        return c;
    }

    private void expect(char c) {
        if (next() != c) throw err("expected '" + c + "'");
    }

    private void expect(String tok) {
        if (!s.regionMatches(i, tok, 0, tok.length())) throw err("expected " + tok);
        i += tok.length();
    }

    private void skipWs() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private IllegalArgumentException err(String msg) {
        return new IllegalArgumentException("JSON parse error at " + i + ": " + msg);
    }
}
