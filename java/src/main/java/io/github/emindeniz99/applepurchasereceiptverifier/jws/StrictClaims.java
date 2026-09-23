package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.io.IOException;
import java.math.BigDecimal;

/**
 * The typed read of a verified payload into {@link TransactionPayload} or
 * {@link AppTransactionPayload}.
 *
 * <p>A modelled claim that is absent or JSON null reads as null. Otherwise a
 * string field takes only a JSON string, and an integer field only a JSON
 * number whose value is a whole number that fits the field, so {@code 1.0}
 * reads as 1 and {@code 1.5} is refused. Jackson's defaults would instead
 * turn {@code 42} into {@code "42"}, {@code "1"} into 1 and truncate
 * {@code 1.5} to 1. Claims the model does not have are ignored.</p>
 *
 * <p>This runs only after the chain and the signature passed, so a claim it
 * refuses was written by a trusted signer: the failure is INTERNAL_ERROR,
 * never a reason a caller reads as "deny".</p>
 */
final class StrictClaims {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new SimpleModule()
                    .addDeserializer(String.class, new StrictString())
                    .addDeserializer(Long.class, new WholeNumber<Long>(Long.class) {
                        @Override
                        Long exact(BigDecimal value) {
                            return Long.valueOf(value.longValueExact());
                        }
                    })
                    .addDeserializer(Integer.class, new WholeNumber<Integer>(Integer.class) {
                        @Override
                        Integer exact(BigDecimal value) {
                            return Integer.valueOf(value.intValueExact());
                        }
                    }));

    private StrictClaims() {}

    static <T> T read(JsonNode payload, Class<T> type) throws VerificationException {
        try {
            return MAPPER.treeToValue(payload, type);
        } catch (JsonMappingException e) {
            String claim = e.getPath().isEmpty()
                    ? "?"
                    : e.getPath().get(e.getPath().size() - 1).getFieldName();
            throw new VerificationException(
                    Reason.INTERNAL_ERROR, "signed payload claim " + claim + " does not have its model's type", e);
        } catch (IOException | RuntimeException e) {
            throw new VerificationException(Reason.INTERNAL_ERROR, "signed payload could not be read", e);
        }
    }

    private static final class StrictString extends StdScalarDeserializer<String> {
        StrictString() {
            super(String.class);
        }

        @Override
        public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            if (p.currentToken() != JsonToken.VALUE_STRING) {
                return (String) ctxt.handleUnexpectedToken(String.class, p);
            }
            return p.getText();
        }
    }

    private abstract static class WholeNumber<T extends Number> extends StdScalarDeserializer<T> {
        private final Class<T> type;

        WholeNumber(Class<T> type) {
            super(type);
            this.type = type;
        }

        /** The value as {@code T}; throws ArithmeticException if it has a fraction or does not fit. */
        abstract T exact(BigDecimal value);

        @Override
        public T deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            if (!p.currentToken().isNumeric()) {
                return type.cast(ctxt.handleUnexpectedToken(type, p));
            }
            BigDecimal value = p.getDecimalValue();
            try {
                return exact(value);
            } catch (ArithmeticException e) {
                throw InvalidFormatException.from(
                        p, "not a whole number that fits " + type.getSimpleName(), value, type);
            }
        }
    }
}
