<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * Named constants for every status code Apple documents for `verifyReceipt`
 * (21000 to 21010, and the 21100-21199 range), so a caller does not write
 * `21007` by hand. {@see Verifier::verifyReceiptEndpoint()} can only ever
 * return {@see Ok}, {@see MalformedReceiptData}, {@see NotAuthenticated},
 * {@see SandboxReceiptOnProduction}, {@see ProductionReceiptOnSandbox} and
 * {@see InternalDataAccessError} — the six status codes docs/design/0.7-api.md's
 * table maps from a {@see Reason}. Its 21009 is deterministic for the same
 * input, so alert on it rather than retry; it never returns
 * {@see ServerUnavailable} or a code in the 21100-21199 range, which mean
 * Apple's own servers failed and invite a retry.
 */
final class AppleStatus
{
    /** The receipt is valid. Returned by the endpoint. */
    public const Ok = 0;

    /** The request was not an HTTP POST. Never returned by the endpoint. */
    public const RequestNotPost = 21000;

    /** No longer sent by the App Store. Never returned by the endpoint. */
    public const NoLongerSent = 21001;

    /** The `receipt-data` property was malformed or missing. Returned by the endpoint. */
    public const MalformedReceiptData = 21002;

    /** The receipt could not be authenticated. Returned by the endpoint. */
    public const NotAuthenticated = 21003;

    /** The shared secret does not match the one on file for the account. Never returned by the endpoint. */
    public const SharedSecretMismatch = 21004;

    /** The receipt server was temporarily unable to provide the receipt. Never returned by the endpoint. */
    public const ServerUnavailable = 21005;

    /** The receipt is valid but the subscription has expired (iOS 6-style receipts only). Never returned by the endpoint. */
    public const SubscriptionExpired = 21006;

    /** A sandbox receipt was sent to the production environment. Returned by the endpoint. */
    public const SandboxReceiptOnProduction = 21007;

    /** A production receipt was sent to the sandbox environment. Returned by the endpoint. */
    public const ProductionReceiptOnSandbox = 21008;

    /** Internal data access error. Returned by the endpoint. */
    public const InternalDataAccessError = 21009;

    /** The user account cannot be found or has been deleted. Never returned by the endpoint. */
    public const AccountNotFound = 21010;

    /** First code of the 21100-21199 range of Apple's internal data access errors. Never returned by the endpoint. */
    public const InternalDataAccessErrorRangeFirst = 21100;

    /** Last code of the 21100-21199 range of Apple's internal data access errors. Never returned by the endpoint. */
    public const InternalDataAccessErrorRangeLast = 21199;

    private function __construct()
    {
    }
}
