package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * The built-in revocation list, read from the JSON of
 * {@code certs/revocations.json} (docs/design/revocation.md §5): the
 * issuers whose lists exist, with the newest list each has been seen to
 * sign, and the revocation keys that are always refused. {@link #apple()} is
 * the compiled-in copy; tests build others with {@link #parse}. Immutable.
 */
final class BuiltInRevocations {

    private static final Pattern ISSUER_ID = Pattern.compile("[0-9a-f]{64}");

    /** One entry of {@code issuers}. */
    static final class Issuer {
        /** Its issuer id (§2). */
        final String id;

        /** The certificate, or null for a root, which is found among the configured roots by {@link #id}. */
        final @Nullable X509Certificate certificate;

        /** The URL of the list it signs. */
        final String list;

        /** The CRL Number of the newest list seen, or null when that list had none. */
        final @Nullable BigInteger newestNumber;

        /** The {@code thisUpdate} of the newest list seen, in epoch milliseconds. */
        final long newestThisUpdate;

        Issuer(
                String id,
                @Nullable X509Certificate certificate,
                String list,
                @Nullable BigInteger newestNumber,
                long newestThisUpdate) {
            this.id = id;
            this.certificate = certificate;
            this.list = list;
            this.newestNumber = newestNumber;
            this.newestThisUpdate = newestThisUpdate;
        }
    }

    /** The issuers, in the file's order. */
    final List<Issuer> issuers;

    /** Each revocation key, as {@code "<issuer id>:<serial>"} (§2). */
    final Set<String> revoked;

    private BuiltInRevocations(List<Issuer> issuers, Set<String> revoked) {
        this.issuers = Collections.unmodifiableList(issuers);
        this.revoked = Collections.unmodifiableSet(revoked);
    }

    /** The compiled-in list, read once. */
    static BuiltInRevocations apple() {
        return Apple.LIST;
    }

    private static final class Apple {
        static final BuiltInRevocations LIST = parse(AppleRevocations.json(), AppleRevocations::certificate);
    }

    /** The revocation key of a serial under an issuer, as {@link #revoked} holds it. */
    static String key(String issuerId, String serialHex) {
        return issuerId + ":" + serialHex;
    }

    /** The issuer whose id is {@code id}, or null. */
    @Nullable
    Issuer issuer(String id) {
        for (Issuer issuer : issuers) {
            if (issuer.id.equals(id)) {
                return issuer;
            }
        }
        return null;
    }

    /**
     * Reads the file's JSON. {@code certificates} turns an issuer's
     * {@code certificate} path into its DER. Members this reader does not
     * use ({@code name}, {@code reason}, {@code delisted}, ...) are skipped:
     * an entry revokes whatever they say.
     *
     * @throws IllegalStateException if the JSON is not of the documented
     *     shape, which for the compiled-in copy is this library's defect
     */
    static BuiltInRevocations parse(byte[] json, Function<String, byte @Nullable []> certificates) {
        Object document;
        try (JsonParser parser = JsonFields.JSON.createParser(json)) {
            parser.nextToken();
            document = value(parser);
            if (parser.nextToken() != null) {
                throw new IllegalStateException("content after the object");
            }
        } catch (IOException e) {
            throw new IllegalStateException("the built-in revocation list is not JSON", e);
        }
        try {
            Map<?, ?> root = (Map<?, ?>) document;
            List<Issuer> issuers = new ArrayList<>();
            for (Object entry : (List<?>) root.get("issuers")) {
                Map<?, ?> issuer = (Map<?, ?>) entry;
                String id = issuerId(issuer.get("id"));
                Object path = issuer.get("certificate");
                X509Certificate certificate = null;
                if (path != null) {
                    byte[] der = certificates.apply((String) path);
                    if (der == null) {
                        throw new IllegalStateException("no certificate " + path);
                    }
                    certificate = certificate(der);
                    if (!Der.names(certificate).issuerId().equals(id)) {
                        throw new IllegalStateException(path + " is not issuer " + id);
                    }
                }
                Map<?, ?> newest = (Map<?, ?>) issuer.get("newest");
                Object number = newest.get("crlNumber");
                issuers.add(new Issuer(
                        id,
                        certificate,
                        (String) issuer.get("list"),
                        number == null ? null : new BigInteger(hex((String) number), 16),
                        Instant.parse((String) newest.get("thisUpdate")).toEpochMilli()));
            }
            Set<String> revoked = new HashSet<>();
            for (Object entry : (List<?>) root.get("revoked")) {
                Map<?, ?> revocation = (Map<?, ?>) entry;
                String serial = Der.normaliseHex((String) revocation.get("serial"));
                if (serial == null) {
                    throw new IllegalStateException("a serial is not hex");
                }
                revoked.add(key(issuerId(revocation.get("issuer")), serial));
            }
            return new BuiltInRevocations(issuers, revoked);
        } catch (ClassCastException | NullPointerException | DateTimeParseException | IllegalArgumentException e) {
            throw new IllegalStateException("the built-in revocation list is not of the documented shape", e);
        }
    }

    private static String issuerId(@Nullable Object value) {
        if (!(value instanceof String) || !ISSUER_ID.matcher((String) value).matches()) {
            throw new IllegalStateException("an issuer id is not 64 lowercase hex digits");
        }
        return (String) value;
    }

    private static String hex(String value) {
        if (value.isEmpty() || !Der.isHex(value)) {
            throw new IllegalStateException("a CRL Number is not hex");
        }
        return value;
    }

    private static X509Certificate certificate(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER)
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new IllegalStateException("a built-in issuer certificate does not parse", e);
        }
    }

    /** The JSON value the parser stands on: a Map, a List, a String, a Boolean, a Number or null. */
    private static @Nullable Object value(JsonParser parser) throws IOException {
        JsonToken token = parser.currentToken();
        if (token == JsonToken.START_OBJECT) {
            Map<String, @Nullable Object> object = new LinkedHashMap<>();
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                parser.nextToken();
                object.put(name, value(parser));
            }
            return object;
        }
        if (token == JsonToken.START_ARRAY) {
            List<@Nullable Object> array = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                array.add(value(parser));
            }
            return array;
        }
        if (token == JsonToken.VALUE_STRING) {
            return parser.getText();
        }
        if (token == JsonToken.VALUE_NULL) {
            return null;
        }
        if (token == JsonToken.VALUE_TRUE || token == JsonToken.VALUE_FALSE) {
            return token == JsonToken.VALUE_TRUE;
        }
        if (token == JsonToken.VALUE_NUMBER_INT || token == JsonToken.VALUE_NUMBER_FLOAT) {
            return parser.getNumberValue();
        }
        throw new IllegalStateException("unexpected " + token);
    }
}
