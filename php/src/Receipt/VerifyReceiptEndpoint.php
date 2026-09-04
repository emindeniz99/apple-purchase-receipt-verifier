<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ChainValidator;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Drop-in local replacement for Apple's deprecated `verifyReceipt` endpoint:
 * same request body, same response body shape, same status codes — but
 * verified offline against pinned Apple roots instead of by calling Apple
 * (PLAN.md D9). Field-by-field fidelity and the unavoidable gaps (fields that
 * only exist in Apple's server-side subscription database, such as
 * `latest_receipt_info` and `pending_renewal_info`) are documented in
 * COMPARISON.md.
 *
 * Like Apple's endpoint, this does **not** check the bundle id — the caller
 * compares `receipt.bundle_id`, exactly as with the real endpoint.
 *
 * Neither method ever throws: a failure is a `status` in the returned body.
 *
 * ```php
 * $endpoint = new VerifyReceiptEndpoint(AppleRootCerts::receiptRoots(), Environment::Production);
 * $response->getBody()->write($endpoint->verifyReceiptJson((string) $request->getBody()));
 * ```
 */
final class VerifyReceiptEndpoint
{
    public const STATUS_OK = 0;

    /** Malformed request, or a malformed `receipt-data` property. */
    public const STATUS_MALFORMED = 21002;

    /** The receipt could not be authenticated. */
    public const STATUS_NOT_AUTHENTICATED = 21003;

    /** A sandbox receipt was sent to the production environment. */
    public const STATUS_SANDBOX_RECEIPT_ON_PRODUCTION = 21007;

    /** A production receipt was sent to the sandbox environment. */
    public const STATUS_PRODUCTION_RECEIPT_ON_SANDBOX = 21008;

    /** Internal error. */
    public const STATUS_INTERNAL = 21009;

    /**
     * Ceiling on the raw request body {@see verifyReceiptJson()} will parse.
     *
     * "Neither method ever throws" is a promise about `Throwable`s, and a
     * `memory_limit` exhaustion is not one: it is a fatal error, so the worker
     * dies with no body at all and the promise silently stops holding on
     * exactly the hostile input it exists for. `json_decode` expands a breadth
     * bomb — a flat array of millions of tiny nodes — by about 48×, and
     * `JSON_MAX_DEPTH` bounds nesting, not breadth, so a 3.3 MB body was
     * enough at the `php.ini-production` default of 128M.
     *
     * The largest genuine receipt in the corpus is 106 KB of base64, so 1 MiB
     * carries any real request with room to spare while bounding the parse to
     * tens of MB. It is deliberately below {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES}:
     * the JSON entry point has an amplification the pre-decoded
     * {@see verifyReceipt()} entry point does not.
     */
    public const MAX_REQUEST_BYTES = 1048576;

    private const MALFORMED_JSON = '{"status":21002}';

    /** @var list<string> */
    private readonly array $trustedRoots;

    private readonly ClockInterface $clock;

    /**
     * @param list<string> $trustedRoots DER bytes or PEM text of the pinned
     *        anchors. In production: {@see \EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts::receiptRoots()}.
     * @param Environment $environment which environment this endpoint
     *        instance emulates; it drives the 21007/21008 routing. Only
     *        {@see Environment::Production} and {@see Environment::Sandbox}
     *        are meaningful — Apple's endpoint has no third mode.
     * @param ClockInterface|null $clock source of "now" for the
     *        `request_date` triple, the only wall-clock-dependent output
     *        here; null installs {@see SystemClock}. It cannot move a
     *        certificate-validity verdict.
     *
     * @throws InvalidArgumentException on misconfiguration
     */
    public function __construct(
        array $trustedRoots,
        private readonly Environment $environment,
        ?ClockInterface $clock = null,
    ) {
        ReceiptVerifier::requireSixtyFourBit();
        ChainValidator::normalizeRoots($trustedRoots); // validate eagerly
        if ($environment !== Environment::Production && $environment !== Environment::Sandbox) {
            throw new InvalidArgumentException(
                'environment must be Environment::Production or Environment::Sandbox',
            );
        }
        $this->trustedRoots = array_values($trustedRoots);
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * Handles one verifyReceipt request body.
     *
     * `password` and `exclude-old-transactions` are accepted for wire
     * compatibility and never read: the first cannot be validated offline,
     * and the second only affects `latest_receipt_info`, which this endpoint
     * never produces (COMPARISON.md).
     *
     * @param mixed $requestBody the decoded JSON body; anything that is not
     *        an array with a usable `receipt-data` answers 21002
     *
     * @return array<string, mixed> the response body
     */
    public function verifyReceipt(mixed $requestBody): array
    {
        try {
            if (!is_array($requestBody)) {
                return ['status' => self::STATUS_MALFORMED];
            }
            $receiptData = $requestBody['receipt-data'] ?? null;
            if (!is_string($receiptData) || $receiptData === '') {
                return ['status' => self::STATUS_MALFORMED];
            }
            // This entry point base64-decodes before `verifyReceiptCore` gets
            // to apply its own cap, so the cap is applied to the transport
            // string here — the same string, and the same limit, that
            // `ReceiptVerifier::toDer()` would have measured. It answers 21002
            // either way; the difference is that nothing is allocated first.
            if (strlen($receiptData) > ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES) {
                return ['status' => self::STATUS_MALFORMED];
            }

            $fields = ReceiptVerifier::verifyReceiptCore(Base64::decode($receiptData), $this->trustedRoots);

            // 21007/21008 routing from the receipt_type attribute, failing
            // closed: production is exactly "Production" and "ProductionVPP".
            // Everything else — "ProductionSandbox", "ProductionVPPSandbox",
            // "Xcode", or a missing attribute — routes as non-production
            // (PLAN.md D10; a VPP-sandbox misroute found by adversarial
            // review drove this tightening).
            $productionReceipt = $fields->receiptType === 'Production'
                || $fields->receiptType === 'ProductionVPP';
            if ($this->environment === Environment::Production && !$productionReceipt) {
                return ['status' => self::STATUS_SANDBOX_RECEIPT_ON_PRODUCTION];
            }
            if ($this->environment === Environment::Sandbox && $productionReceipt) {
                return ['status' => self::STATUS_PRODUCTION_RECEIPT_ON_SANDBOX];
            }

            return [
                'status' => self::STATUS_OK,
                'environment' => $this->environment->value,
                'receipt' => self::receiptJson($fields, $this->clock->now()),
            ];
        } catch (VerificationException $e) {
            return [
                'status' => $e->reason === Reason::InvalidReceiptFormat
                    ? self::STATUS_MALFORMED
                    : self::STATUS_NOT_AUTHENTICATED,
            ];
        } catch (Throwable) {
            // "Never throws" is the contract, so it holds for a timezone
            // database without America/Los_Angeles just as it does for a
            // hostile receipt.
            return ['status' => self::STATUS_INTERNAL];
        }
    }

    /**
     * Handles one verifyReceipt request in its raw wire form: the JSON
     * request body in, the JSON response body out, so a PSR-7 handler can
     * pipe a body straight through without a DTO in between.
     *
     * A body that is not a JSON object (unparseable, `null`, an array, a
     * scalar) answers `{"status":21002}`. Apple has no status code for "that
     * wasn't JSON"; 21002 is the closest, and it is what a JSON object
     * without usable `receipt-data` gets anyway — and what a body over
     * {@see MAX_REQUEST_BYTES} gets, before it is parsed.
     */
    public function verifyReceiptJson(string $requestJson): string
    {
        if (strlen($requestJson) > self::MAX_REQUEST_BYTES) {
            return self::MALFORMED_JSON;
        }
        try {
            $parsed = json_decode($requestJson, true, 64, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return self::MALFORMED_JSON;
        }
        if (!is_array($parsed) || ($parsed !== [] && array_is_list($parsed))) {
            return self::MALFORMED_JSON;
        }
        $encoded = json_encode($this->verifyReceipt($parsed));

        return $encoded === false ? '{"status":21009}' : $encoded;
    }

    /** @return array<string, mixed> */
    private static function receiptJson(AppReceipt $fields, DateTimeInterface $requestDate): array
    {
        $receipt = [];
        self::put($receipt, 'receipt_type', $fields->receiptType);
        self::put($receipt, 'bundle_id', $fields->bundleId);
        self::put($receipt, 'application_version', $fields->appVersion);
        self::put($receipt, 'original_application_version', $fields->originalAppVersion);
        self::appleDates($receipt, 'receipt_creation_date', $fields->creationDate);
        self::appleDates($receipt, 'request_date', $requestDate);
        self::appleDates($receipt, 'original_purchase_date', $fields->originalPurchaseDate);
        self::appleDates($receipt, 'expiration_date', $fields->expirationDate);
        $receipt['in_app'] = array_map(self::inAppJson(...), $fields->inAppPurchases);

        return $receipt;
    }

    /** @return array<string, mixed> */
    private static function inAppJson(InAppPurchase $purchase): array
    {
        $entry = [];
        self::put($entry, 'quantity', $purchase->quantity === null ? null : (string) $purchase->quantity);
        self::put($entry, 'product_id', $purchase->productId);
        self::put($entry, 'transaction_id', $purchase->transactionId);
        self::put($entry, 'original_transaction_id', $purchase->originalTransactionId);
        self::appleDates($entry, 'purchase_date', $purchase->purchaseDate);
        self::appleDates($entry, 'original_purchase_date', $purchase->originalPurchaseDate);
        self::appleDates($entry, 'expires_date', $purchase->expiresDate);
        self::appleDates($entry, 'cancellation_date', $purchase->cancellationDate);
        self::put(
            $entry,
            'web_order_line_item_id',
            $purchase->webOrderLineItemId === null ? null : (string) $purchase->webOrderLineItemId,
        );
        self::put(
            $entry,
            'is_in_intro_offer_period',
            $purchase->isInIntroOfferPeriod === null
                ? null
                : ($purchase->isInIntroOfferPeriod === 1 ? 'true' : 'false'),
        );

        return $entry;
    }

    /** @param array<string, mixed> $target */
    private static function put(array &$target, string $key, mixed $value): void
    {
        if ($value !== null) {
            $target[$key] = $value;
        }
    }

    /**
     * Apple's three date renderings: `x` (GMT), `x_ms` (epoch millis as a
     * string), `x_pst` (US Pacific, which is what Apple's endpoint emits).
     *
     * @param array<string, mixed> $target
     */
    private static function appleDates(array &$target, string $prefix, ?DateTimeInterface $date): void
    {
        if ($date === null) {
            return;
        }
        $target[$prefix] = self::formatInZone($date, 'UTC', 'Etc/GMT');
        $target[$prefix . '_ms'] = (string) (int) $date->format('Uv');
        $target[$prefix . '_pst'] = self::formatInZone($date, 'America/Los_Angeles', 'America/Los_Angeles');
    }

    private static function formatInZone(DateTimeInterface $date, string $timeZone, string $label): string
    {
        $utc = DateTimeImmutable::createFromInterface($date)->setTimezone(new DateTimeZone($timeZone));

        return $utc->format('Y-m-d H:i:s') . ' ' . $label;
    }
}
