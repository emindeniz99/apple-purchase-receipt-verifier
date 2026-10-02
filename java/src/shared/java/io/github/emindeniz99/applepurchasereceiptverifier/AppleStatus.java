package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * The {@code status} codes Apple documents for its verifyReceipt endpoint, so
 * callers do not write {@code 21007} by hand.
 *
 * <p>{@link Verifier#verifyReceiptEndpoint} returns only {@link #OK},
 * {@link #MALFORMED_RECEIPT_DATA}, {@link #RECEIPT_NOT_AUTHENTICATED},
 * {@link #SANDBOX_RECEIPT_ON_PRODUCTION},
 * {@link #PRODUCTION_RECEIPT_ON_SANDBOX} and
 * {@link #INTERNAL_DATA_ACCESS_ERROR}. Its 21009 is deterministic for the
 * same input, so alert on it rather than retry. It never returns
 * {@link #SERVER_UNAVAILABLE} or the 21100 to 21199 range, which mean Apple's
 * own servers failed and invite a retry.</p>
 */
public final class AppleStatus {

    /** The receipt is valid. */
    public static final int OK = 0;

    /** The request was not an HTTP POST. */
    public static final int REQUEST_NOT_POST = 21000;

    /** No longer sent by the App Store. */
    public static final int NO_LONGER_SENT = 21001;

    /** The {@code receipt-data} property was malformed or missing. */
    public static final int MALFORMED_RECEIPT_DATA = 21002;

    /** The receipt could not be authenticated. */
    public static final int RECEIPT_NOT_AUTHENTICATED = 21003;

    /** The shared secret does not match the one on file for the account. */
    public static final int SHARED_SECRET_MISMATCH = 21004;

    /** The receipt server was temporarily unable to provide the receipt. */
    public static final int SERVER_UNAVAILABLE = 21005;

    /** The receipt is valid but the subscription has expired (iOS 6-style receipts only). */
    public static final int SUBSCRIPTION_EXPIRED = 21006;

    /** A sandbox receipt was sent to the production environment. */
    public static final int SANDBOX_RECEIPT_ON_PRODUCTION = 21007;

    /** A production receipt was sent to the sandbox environment. */
    public static final int PRODUCTION_RECEIPT_ON_SANDBOX = 21008;

    /** Internal data access error. */
    public static final int INTERNAL_DATA_ACCESS_ERROR = 21009;

    /** The user account cannot be found or has been deleted. */
    public static final int ACCOUNT_NOT_FOUND = 21010;

    /** First code of the 21100 to 21199 range of Apple's internal data access errors. */
    public static final int INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST = 21100;

    /** Last code of the 21100 to 21199 range of Apple's internal data access errors. */
    public static final int INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST = 21199;

    private AppleStatus() {}
}
