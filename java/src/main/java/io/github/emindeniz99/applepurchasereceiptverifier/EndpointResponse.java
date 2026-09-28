package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import java.io.IOException;
import java.io.StringWriter;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.jspecify.annotations.Nullable;

/**
 * Renders the verifyReceipt response body Apple would return, for the fields
 * a receipt can carry. Keys and value types follow Apple's endpoint; key
 * order is deterministic but not part of the contract, and differs from
 * Apple's in places ({@code original_application_version}, for one).
 * {@code in_app_ownership_type} and everything that lives only in Apple's
 * server-side database are never present.
 */
final class EndpointResponse {

    // Locale.ROOT, so the JVM's default locale never reaches the rendering.
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withLocale(Locale.ROOT);
    private static final ZoneId PACIFIC = ZoneId.of("America/Los_Angeles");

    // Jackson's own generator defaults: short escapes for \n and the like,
    // "/" and non-ASCII unescaped, as Apple's endpoint writes them.
    static final JsonFactory JSON = new JsonFactory();

    private EndpointResponse() {}

    /** A response carrying only {@code status}. */
    static String status(int status) {
        return "{\"status\":" + status + "}";
    }

    /**
     * The response for {@code status}; {@code environment} and
     * {@code receipt} are written only for status 0.
     */
    static String render(
            int status, Environment environment, @Nullable ReceiptPayload receipt, long requestDateMillis) {
        if (status != AppleStatus.OK || receipt == null) {
            return status(status);
        }
        // A size hint only; clamped, so a cap-sized receipt does not reserve
        // tens of megabytes up front or overflow the multiplication.
        StringWriter out =
                new StringWriter((int) Math.min(1024 + 1024L * receipt.inApp().size(), 1 << 20));
        try (JsonGenerator json = JSON.createGenerator(out)) {
            json.writeStartObject();
            json.writeNumberField("status", status);
            json.writeStringField("environment", environment.value());
            json.writeFieldName("receipt");
            writeReceipt(json, receipt, requestDateMillis);
            json.writeEndObject();
        } catch (IOException | RuntimeException e) {
            return status(AppleStatus.INTERNAL_DATA_ACCESS_ERROR);
        }
        return out.toString();
    }

    private static void writeReceipt(JsonGenerator json, ReceiptPayload receipt, long requestDateMillis)
            throws IOException {
        json.writeStartObject();
        string(json, "receipt_type", receipt.receiptType());
        // Apple echoes attribute 1 under both names (its response reference
        // defines adam_id as "See app_item_id") and as JSON numbers, not as
        // the strings the in-app integers are rendered with.
        number(json, "adam_id", receipt.appItemId());
        number(json, "app_item_id", receipt.appItemId());
        string(json, "bundle_id", receipt.bundleId());
        string(json, "application_version", receipt.applicationVersion());
        number(json, "download_id", receipt.downloadId());
        number(json, "version_external_identifier", receipt.versionExternalIdentifier());
        string(json, "original_application_version", receipt.originalApplicationVersion());
        appleDates(json, "receipt_creation_date", receipt.receiptCreationDateMs());
        appleDates(json, "request_date", requestDateMillis);
        appleDates(json, "original_purchase_date", receipt.originalPurchaseDateMs());
        appleDates(json, "expiration_date", receipt.expirationDateMs());
        json.writeArrayFieldStart("in_app");
        for (InAppPurchase purchase : receipt.inApp()) {
            writePurchase(json, purchase);
        }
        json.writeEndArray();
        json.writeEndObject();
    }

    private static void writePurchase(JsonGenerator json, InAppPurchase purchase) throws IOException {
        json.writeStartObject();
        Long quantity = purchase.quantity();
        if (quantity != null) {
            json.writeStringField("quantity", quantity.toString());
        }
        string(json, "product_id", purchase.productId());
        string(json, "transaction_id", purchase.transactionId());
        string(json, "original_transaction_id", purchase.originalTransactionId());
        appleDates(json, "purchase_date", purchase.purchaseDateMs());
        appleDates(json, "original_purchase_date", purchase.originalPurchaseDateMs());
        appleDates(json, "expires_date", purchase.expiresDateMs());
        appleDates(json, "cancellation_date", purchase.cancellationDateMs());
        // Apple omits the key when attribute 1711 is 0, as it is for
        // consumables.
        Long webOrderLineItemId = purchase.webOrderLineItemId();
        if (webOrderLineItemId != null && webOrderLineItemId != 0) {
            json.writeStringField("web_order_line_item_id", webOrderLineItemId.toString());
        }
        if (purchase.isTrialPeriod() != null) {
            json.writeStringField("is_trial_period", purchase.isTrialPeriod().toString());
        }
        if (purchase.isInIntroOfferPeriod() != null) {
            json.writeStringField(
                    "is_in_intro_offer_period", purchase.isInIntroOfferPeriod().toString());
        }
        json.writeEndObject();
    }

    private static void string(JsonGenerator json, String key, @Nullable String value) throws IOException {
        if (value != null) {
            json.writeStringField(key, value);
        }
    }

    private static void number(JsonGenerator json, String key, @Nullable Long value) throws IOException {
        if (value != null) {
            json.writeNumberField(key, value);
        }
    }

    /** Apple's three date renderings: {@code x} (GMT), {@code x_ms}, {@code x_pst}. */
    private static void appleDates(JsonGenerator json, String prefix, @Nullable Long epochMillis) throws IOException {
        if (epochMillis == null) {
            return;
        }
        Instant instant = Instant.ofEpochMilli(epochMillis);
        json.writeStringField(prefix, FORMAT.format(instant.atZone(ZoneOffset.UTC)) + " Etc/GMT");
        json.writeStringField(prefix + "_ms", epochMillis.toString());
        json.writeStringField(prefix + "_pst", FORMAT.format(instant.atZone(PACIFIC)) + " America/Los_Angeles");
    }
}
