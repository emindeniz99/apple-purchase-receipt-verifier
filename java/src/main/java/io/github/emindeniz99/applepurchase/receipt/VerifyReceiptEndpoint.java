package io.github.emindeniz99.applepurchase.receipt;

import io.github.emindeniz99.applepurchase.VerificationException;
import io.github.emindeniz99.applepurchase.VerificationException.Reason;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Drop-in local replacement for Apple's deprecated {@code verifyReceipt}
 * endpoint: same request body, same response body shape, same status codes —
 * but verified offline against the pinned Apple root instead of by calling
 * Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
 * exist in Apple's server-side subscription database, like
 * {@code latest_receipt_info} / {@code pending_renewal_info}) are documented
 * in COMPARISON.md.
 *
 * <p>Like Apple's endpoint, this does NOT check the bundle id — the caller
 * compares {@code receipt.bundle_id}, exactly as with the real endpoint.</p>
 */
public final class VerifyReceiptEndpoint {

    public static final int STATUS_OK = 0;
    /** Malformed request or receipt-data property. */
    public static final int STATUS_MALFORMED = 21002;
    /** Receipt could not be authenticated. */
    public static final int STATUS_NOT_AUTHENTICATED = 21003;
    /** Sandbox receipt sent to the production environment. */
    public static final int STATUS_SANDBOX_RECEIPT_ON_PRODUCTION = 21007;
    /** Production receipt sent to the sandbox environment. */
    public static final int STATUS_PRODUCTION_RECEIPT_ON_SANDBOX = 21008;
    /** Internal error. */
    public static final int STATUS_INTERNAL = 21009;

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ZoneId GMT = ZoneId.of("UTC");
    private static final ZoneId PACIFIC = ZoneId.of("America/Los_Angeles");

    private final ReceiptVerifier verifier;
    private final boolean production;

    /**
     * @param trustedRoots pinned roots (production:
     *                     {@code AppleRootCerts.receiptRoots()})
     * @param production   which environment this instance emulates
     *                     (drives 21007/21008 routing)
     */
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, boolean production) {
        // The bundle id is never consulted: verifyCore skips the claim check,
        // matching Apple's endpoint (callers compare receipt.bundle_id).
        this.verifier = new ReceiptVerifier(trustedRoots, "*");
        this.production = production;
    }

    /**
     * Handles one verifyReceipt request body. Never throws — like the real
     * endpoint, failures are reported through {@code status}.
     */
    public Map<String, Object> verifyReceipt(Map<String, ?> requestBody) {
        Object receiptData = requestBody == null ? null : requestBody.get("receipt-data");
        if (!(receiptData instanceof String) || ((String) receiptData).isEmpty()) {
            return status(STATUS_MALFORMED);
        }
        byte[] der;
        try {
            der = Base64.getMimeDecoder().decode((String) receiptData);
        } catch (IllegalArgumentException e) {
            return status(STATUS_MALFORMED);
        }
        AppReceipt receipt;
        try {
            receipt = verifier.verifyCore(der);
        } catch (VerificationException e) {
            return status(e.reason() == Reason.INVALID_RECEIPT_FORMAT
                    ? STATUS_MALFORMED : STATUS_NOT_AUTHENTICATED);
        } catch (RuntimeException e) {
            return status(STATUS_INTERNAL);
        }

        // 21007/21008 environment routing from the receipt_type attribute.
        // Production types are exactly "Production" and "ProductionVPP";
        // everything else ("ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute) fails closed as non-production.
        boolean productionReceipt = "Production".equals(receipt.receiptType())
                || "ProductionVPP".equals(receipt.receiptType());
        if (production && !productionReceipt) {
            return status(STATUS_SANDBOX_RECEIPT_ON_PRODUCTION);
        }
        if (!production && productionReceipt) {
            return status(STATUS_PRODUCTION_RECEIPT_ON_SANDBOX);
        }

        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put("status", STATUS_OK);
        response.put("environment", production ? "Production" : "Sandbox");
        response.put("receipt", receiptJson(receipt, Instant.now()));
        return response;
    }

    private static Map<String, Object> status(int code) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put("status", code);
        return response;
    }

    private static Map<String, Object> receiptJson(AppReceipt receipt, Instant requestDate) {
        Map<String, Object> json = new LinkedHashMap<String, Object>();
        put(json, "receipt_type", receipt.receiptType());
        put(json, "bundle_id", receipt.bundleId());
        put(json, "application_version", receipt.appVersion());
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
        if (purchase.isInIntroOfferPeriod() != null) {
            json.put("is_in_intro_offer_period",
                    String.valueOf(purchase.isInIntroOfferPeriod() == 1L));
        }
        return json;
    }

    private static String stringOrNull(Long value) {
        return value == null ? null : String.valueOf(value);
    }

    private static void put(Map<String, Object> json, String key, Object value) {
        if (value != null) {
            json.put(key, value);
        }
    }

    /** Apple's three date renderings: {@code x} (GMT), {@code x_ms}, {@code x_pst}. */
    private static void appleDates(Map<String, Object> json, String prefix, Instant instant) {
        if (instant == null) {
            return;
        }
        json.put(prefix, FORMAT.format(instant.atZone(GMT)) + " Etc/GMT");
        json.put(prefix + "_ms", String.valueOf(instant.toEpochMilli()));
        json.put(prefix + "_pst", FORMAT.format(instant.atZone(PACIFIC)) + " America/Los_Angeles");
    }
}
