package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * The outcome of one {@link VerifyReceiptEndpoint} call: the Apple status, the
 * verified receipt or the reason there is none, and the Apple-shaped response,
 * rendered only when asked for.
 *
 * <p>Exactly one of {@link #receipt()} and {@link #failureReason()} is
 * non-null. The receipt is present whenever its bytes verified, including when
 * the endpoint's own environment answers 21007 or 21008, so a caller can
 * {@linkplain #toJson(Environment) re-render} for the other environment without
 * verifying twice. The status is always recomputed from the receipt's own
 * {@code receipt_type}, so no render can answer 0 for a receipt from the wrong
 * environment.</p>
 *
 * <p>Immutable and thread-safe. Only the endpoint creates one: a caller cannot
 * construct a result carrying status 0.</p>
 */
public final class VerifyReceiptResult {

    // Locale.ROOT pinned so a JVM default locale can never reach the
    // rendering.
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withLocale(Locale.ROOT);
    private static final ZoneId PACIFIC = ZoneId.of("America/Los_Angeles");

    private final Environment environment;
    private final @Nullable AppReceipt receipt;
    private final @Nullable Reason failureReason;
    private final @Nullable Throwable failureCause;
    private final Instant requestDate;

    private VerifyReceiptResult(
            Environment environment,
            @Nullable AppReceipt receipt,
            @Nullable Reason failureReason,
            @Nullable Throwable failureCause,
            Instant requestDate) {
        this.environment = environment;
        this.receipt = receipt;
        this.failureReason = failureReason;
        this.failureCause = failureCause;
        this.requestDate = requestDate;
    }

    static VerifyReceiptResult verified(Environment environment, AppReceipt receipt, Instant requestDate) {
        return new VerifyReceiptResult(environment, receipt, null, null, requestDate);
    }

    static VerifyReceiptResult failed(Environment environment, Reason reason, Instant requestDate) {
        return new VerifyReceiptResult(environment, null, reason, null, requestDate);
    }

    static VerifyReceiptResult internalError(Environment environment, Throwable cause, Instant requestDate) {
        return new VerifyReceiptResult(environment, null, Reason.INTERNAL_ERROR, cause, requestDate);
    }

    /** The Apple status for the endpoint's own environment. */
    public int status() {
        return status(environment);
    }

    /**
     * The verified receipt, or {@code null} when verification failed. Present
     * for 21007 and 21008 too: those say the receipt belongs to the other
     * environment, not that it failed to verify.
     */
    public @Nullable AppReceipt receipt() {
        return receipt;
    }

    /**
     * Whether the receipt bytes verified, {@code true} exactly when
     * {@link #receipt()} is non-null. This includes 21007 and 21008 results:
     * the receipt verified, only its environment differs from this endpoint's
     * own, so this is <strong>not</strong> the same check as {@code status()
     * == 0}. {@code status() == 0} answers "does this endpoint's own
     * environment accept the receipt"; {@code isVerified()} answers "did the
     * receipt verify at all", which is what a caller should check before
     * trusting {@link #receipt()}'s fields or retrying with
     * {@link #toResponse(Environment)}.
     */
    public boolean isVerified() {
        return receipt != null;
    }

    /** Why there is no receipt; non-null exactly when {@link #receipt()} is null. */
    public @Nullable Reason failureReason() {
        return failureReason;
    }

    /**
     * What is behind {@link Reason#INTERNAL_ERROR}: the unexpected exception
     * the endpoint caught, or the parser's exception for signed receipt
     * content that could not be read. Null for every other outcome.
     */
    public @Nullable Throwable failureCause() {
        return failureCause;
    }

    /** The instant rendered as {@code request_date}, fixed when the call was made. */
    public Instant requestDate() {
        return requestDate;
    }

    /**
     * The response the endpoint's own environment answers, as a new map on
     * each call. Same keys, order and types as Apple's endpoint.
     */
    public Map<String, Object> toResponse() {
        return toResponse(environment);
    }

    /** {@link #toResponse()} serialized as the JSON response body. */
    public String toJson() {
        return toJson(environment);
    }

    /**
     * The response an endpoint of {@code environment} would answer for the same
     * receipt, at the same {@link #requestDate()}. A production receipt answers
     * 0 on {@code PRODUCTION} and 21008 on {@code SANDBOX}; any other receipt
     * answers 21007 on {@code PRODUCTION} and 0 on {@code SANDBOX}; a failed
     * result answers its own status on both.
     *
     * @throws IllegalArgumentException if {@code environment} is neither
     *                                  {@code PRODUCTION} nor {@code SANDBOX}
     */
    public Map<String, Object> toResponse(Environment environment) {
        int status = status(environment);
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put("status", status);
        if (status == VerifyReceiptEndpoint.STATUS_OK && receipt != null) {
            response.put("environment", environment.value());
            response.put("receipt", receiptJson(receipt, requestDate));
        }
        return response;
    }

    /** {@link #toResponse(Environment)} serialized as the JSON response body. */
    public String toJson(Environment environment) {
        Map<String, Object> response = toResponse(environment);
        try {
            return VerifyReceiptEndpoint.MAPPER.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            return "{\"status\":" + VerifyReceiptEndpoint.STATUS_INTERNAL + "}";
        }
    }

    private int status(Environment environment) {
        if (environment != Environment.PRODUCTION && environment != Environment.SANDBOX) {
            throw new IllegalArgumentException("environment must be PRODUCTION or SANDBOX, got " + environment);
        }
        if (receipt == null) {
            if (failureReason == Reason.MALFORMED_REQUEST
                    || failureReason == Reason.REQUEST_TOO_LARGE
                    || failureReason == Reason.INVALID_RECEIPT_FORMAT) {
                return VerifyReceiptEndpoint.STATUS_MALFORMED;
            }
            if (failureReason == Reason.INTERNAL_ERROR) {
                return VerifyReceiptEndpoint.STATUS_INTERNAL;
            }
            return VerifyReceiptEndpoint.STATUS_NOT_AUTHENTICATED;
        }
        // 21007/21008 environment routing from the receipt_type attribute.
        // Production types are exactly "Production" and "ProductionVPP";
        // everything else ("ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute) fails closed as non-production.
        // "Xcode" is listed for completeness only: an Xcode-generated
        // receipt is not Apple-signed, so it fails chain verification with
        // 21003 and never gets here.
        boolean productionReceipt =
                "Production".equals(receipt.receiptType()) || "ProductionVPP".equals(receipt.receiptType());
        if (environment == Environment.PRODUCTION && !productionReceipt) {
            return VerifyReceiptEndpoint.STATUS_SANDBOX_RECEIPT_ON_PRODUCTION;
        }
        if (environment == Environment.SANDBOX && productionReceipt) {
            return VerifyReceiptEndpoint.STATUS_PRODUCTION_RECEIPT_ON_SANDBOX;
        }
        return VerifyReceiptEndpoint.STATUS_OK;
    }

    private static Map<String, Object> receiptJson(AppReceipt receipt, Instant requestDate) {
        Map<String, Object> json = new LinkedHashMap<String, Object>();
        put(json, "receipt_type", receipt.receiptType());
        // Apple echoes attribute 1 under both names — its response reference
        // defines adam_id as "See app_item_id" — and as JSON numbers, not as
        // the strings the in-app integers are rendered with.
        put(json, "adam_id", receipt.appItemId());
        put(json, "app_item_id", receipt.appItemId());
        put(json, "bundle_id", receipt.bundleId());
        put(json, "application_version", receipt.appVersion());
        put(json, "download_id", receipt.downloadId());
        put(json, "version_external_identifier", receipt.versionExternalIdentifier());
        put(json, "original_application_version", receipt.originalAppVersion());
        appleDates(json, "receipt_creation_date", receipt.creationDate());
        appleDates(json, "request_date", requestDate);
        appleDates(json, "original_purchase_date", receipt.originalPurchaseDate());
        appleDates(json, "expiration_date", receipt.expirationDate());
        List<Map<String, Object>> inApp = new ArrayList<Map<String, Object>>();
        for (InAppPurchase purchase : receipt.inAppPurchases()) {
            inApp.add(inAppJson(purchase));
        }
        json.put("in_app", inApp);
        return json;
    }

    private static Map<String, Object> inAppJson(InAppPurchase purchase) {
        Map<String, Object> json = new LinkedHashMap<String, Object>();
        put(json, "quantity", stringOrNull(purchase.quantity()));
        put(json, "product_id", purchase.productId());
        put(json, "transaction_id", purchase.transactionId());
        put(json, "original_transaction_id", purchase.originalTransactionId());
        appleDates(json, "purchase_date", purchase.purchaseDate());
        appleDates(json, "original_purchase_date", purchase.originalPurchaseDate());
        appleDates(json, "expires_date", purchase.expiresDate());
        appleDates(json, "cancellation_date", purchase.cancellationDate());
        put(json, "web_order_line_item_id", stringOrNull(purchase.webOrderLineItemId()));
        if (purchase.isTrialPeriod() != null) {
            json.put("is_trial_period", String.valueOf(purchase.isTrialPeriod() == 1L));
        }
        if (purchase.isInIntroOfferPeriod() != null) {
            json.put("is_in_intro_offer_period", String.valueOf(purchase.isInIntroOfferPeriod() == 1L));
        }
        return json;
    }

    private static @Nullable String stringOrNull(@Nullable Long value) {
        return value == null ? null : String.valueOf(value);
    }

    private static void put(Map<String, Object> json, String key, @Nullable Object value) {
        if (value != null) {
            json.put(key, value);
        }
    }

    /** Apple's three date renderings: {@code x} (GMT), {@code x_ms}, {@code x_pst}. */
    private static void appleDates(Map<String, Object> json, String prefix, @Nullable Instant instant) {
        if (instant == null) {
            return;
        }
        json.put(prefix, FORMAT.format(instant.atZone(ZoneOffset.UTC)) + " Etc/GMT");
        json.put(prefix + "_ms", String.valueOf(instant.toEpochMilli()));
        json.put(prefix + "_pst", FORMAT.format(instant.atZone(PACIFIC)) + " America/Los_Angeles");
    }
}
