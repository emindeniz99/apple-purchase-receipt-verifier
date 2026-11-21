package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A config as both engines hand it on: {@code init}'s configuration
 * (rust/bindings/wire/schema/init-config.schema.json), which the Endive
 * engine passes to the module and the server engine sends as its managed
 * handshake's second line, and what {@code GET /v1/info} reports of it: the
 * SHA-256 of each root, of each revocation list and of each added issuer,
 * and the distrust entries. A root or an issuer travels as its DER, a list
 * as its bytes, a distrust entry as its two strings, as given: nothing here
 * parses or checks a certificate or a list.
 */
final class InitConfig {

    private InitConfig() {}

    private static final JsonFactory JSON = new JsonFactory();

    /**
     * {@code {}}, the module's built-in Apple roots and no revocation
     * setting, when the config's roots are exactly the bundled three
     * ({@link Config#defaults()}) and it sets no revocation setting;
     * otherwise an object with {@code "roots"} (each root's DER as padded
     * standard base64, in the config's order) unless the roots are the
     * bundled three, and each revocation setting the config sets:
     * {@code "revocation_lists"}, {@code "revocation_issuers"} and
     * {@code "distrust"}. {@code {}} is the one form of the built-in roots:
     * the module and {@code aprv-server} both refuse {@code {"roots":[]}}.
     */
    static String json(Config config) {
        StringWriter text = new StringWriter();
        try (JsonGenerator json = JSON.createGenerator(text)) {
            json.writeStartObject();
            if (!config.roots().equals(AppleRootCerts.roots())) {
                json.writeFieldName("roots");
                json.writeStartArray();
                for (X509Certificate root : config.roots()) {
                    json.writeString(Base64.getEncoder().encodeToString(der(root, "a root")));
                }
                json.writeEndArray();
            }
            if (!config.revocationLists().isEmpty()) {
                json.writeFieldName("revocation_lists");
                json.writeStartArray();
                for (byte[] list : config.revocationLists()) {
                    json.writeString(Base64.getEncoder().encodeToString(list));
                }
                json.writeEndArray();
            }
            if (!config.revocationIssuers().isEmpty()) {
                json.writeFieldName("revocation_issuers");
                json.writeStartArray();
                for (X509Certificate issuer : config.revocationIssuers()) {
                    json.writeString(Base64.getEncoder().encodeToString(der(issuer, "a revocation issuer")));
                }
                json.writeEndArray();
            }
            if (!config.distrust().isEmpty()) {
                json.writeFieldName("distrust");
                json.writeStartArray();
                for (RevokedCertificate entry : config.distrust()) {
                    json.writeStartObject();
                    json.writeStringField("issuer", entry.issuer());
                    json.writeStringField("serial", entry.serial());
                    json.writeEndObject();
                }
                json.writeEndArray();
            }
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
            fingerprints.add(ServerBinary.sha256(der(root, "a root")));
        }
        return fingerprints;
    }

    /**
     * The SHA-256 of each revocation list, sorted, as {@code /v1/info}
     * lists them: their order does not matter to the module.
     */
    static List<String> listSha256s(Config config) {
        List<String> out = new ArrayList<>();
        for (byte[] list : config.revocationLists()) {
            out.add(ServerBinary.sha256(list));
        }
        Collections.sort(out);
        return out;
    }

    /**
     * The SHA-256 of each added issuer's DER, in the config's order, as
     * {@code /v1/info} lists them: the first issuer whose key verifies a
     * list owns it, so the order matters.
     */
    static List<String> issuerSha256s(Config config) {
        List<String> out = new ArrayList<>();
        for (X509Certificate issuer : config.revocationIssuers()) {
            out.add(ServerBinary.sha256(der(issuer, "a revocation issuer")));
        }
        return out;
    }

    /** The distrust entries as {@code /v1/info} lists them: two strings each, as given, in order. */
    static List<Map<String, String>> distrust(Config config) {
        List<Map<String, String>> out = new ArrayList<>();
        for (RevokedCertificate entry : config.distrust()) {
            Map<String, String> one = new LinkedHashMap<>();
            one.put("issuer", entry.issuer());
            one.put("serial", entry.serial());
            out.add(one);
        }
        return out;
    }

    private static byte[] der(X509Certificate certificate, String what) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(what + " in the config cannot be encoded: " + e.getMessage(), e);
        }
    }
}
