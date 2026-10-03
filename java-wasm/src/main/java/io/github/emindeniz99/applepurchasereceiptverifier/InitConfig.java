package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * A config's roots as both engines hand them on: {@code init}'s
 * configuration (rust/bindings/wire/schema/init-config.schema.json), which
 * the Endive engine passes to the module and the server engine sends as its
 * managed handshake's second line, and the SHA-256 of each root, which
 * {@code GET /v1/info} lists. A root travels as its DER and nothing else:
 * nothing here parses or checks a certificate.
 */
final class InitConfig {

    private InitConfig() {}

    private static final JsonFactory JSON = new JsonFactory();

    /**
     * {@code {}}, the module's built-in Apple roots, when {@code roots} are
     * exactly the bundled three ({@link Config#defaults()}); otherwise
     * {@code {"roots":[...]}} with each root's DER as padded standard base64,
     * in the config's order. The module also reads {@code {"roots":[]}} as
     * the built-in roots, but {@code aprv-server} refuses it, so {@code {}}
     * is the one form both engines send.
     */
    static String json(Set<X509Certificate> roots) {
        if (roots.equals(AppleRootCerts.roots())) {
            return "{}";
        }
        StringWriter text = new StringWriter();
        try (JsonGenerator json = JSON.createGenerator(text)) {
            json.writeStartObject();
            json.writeFieldName("roots");
            json.writeStartArray();
            for (X509Certificate root : roots) {
                json.writeString(Base64.getEncoder().encodeToString(der(root)));
            }
            json.writeEndArray();
            json.writeEndObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e); // a StringWriter never fails
        }
        return text.toString();
    }

    /** The SHA-256 of each root's DER, as {@code /v1/info} lists them. */
    static Set<String> fingerprints(Set<X509Certificate> roots) {
        Set<String> fingerprints = new HashSet<>();
        for (X509Certificate root : roots) {
            fingerprints.add(ServerBinary.sha256(der(root)));
        }
        return fingerprints;
    }

    private static byte[] der(X509Certificate root) {
        try {
            return root.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("a root in the config cannot be encoded: " + e.getMessage(), e);
        }
    }
}
