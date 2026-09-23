<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use InvalidArgumentException;
use Throwable;

/**
 * The outcome of one {@see VerifyReceiptEndpoint} call: the Apple status, the
 * verified receipt or the reason there is none, and the Apple-shaped response,
 * rendered only when asked for.
 *
 * Exactly one of {@see receipt()} and {@see failureReason()} is non-null. The
 * receipt is kept whenever its bytes verified, including when the endpoint's
 * own environment answers 21007 or 21008, so a caller can re-render for the
 * other environment with {@see toJson()} without verifying twice. The status
 * is always recomputed from the receipt's own `receipt_type`, so no render
 * answers 0 for a receipt from the wrong environment.
 *
 * Immutable. Only the endpoint creates one: the constructor is private, so a
 * caller cannot build a result carrying status 0.
 */
final class VerifyReceiptResult
{
    private function __construct(
        private readonly Environment $environment,
        private readonly ?AppReceipt $receipt,
        private readonly ?Reason $failureReason,
        private readonly ?Throwable $failureCause,
        private readonly DateTimeImmutable $requestDate,
    ) {
    }

    /** The Apple status for the endpoint's own environment. */
    public function status(): int
    {
        return $this->statusFor($this->environment);
    }

    /**
     * Whether the receipt bytes verified: true exactly when {@see receipt()}
     * is non-null. That includes 21007 and 21008, where the receipt verified
     * and only its environment differs from the endpoint's, so this is NOT
     * the same check as `status() === 0`. `status() === 0` asks whether this
     * endpoint's environment accepts the receipt; `isVerified()` asks whether
     * it verified at all, which is what to check before reading
     * {@see receipt()} or re-rendering for the other environment.
     */
    public function isVerified(): bool
    {
        return $this->receipt !== null;
    }

    /**
     * The verified receipt, or null when verification failed. Present for
     * 21007 and 21008 too: those say the receipt belongs to the other
     * environment, not that it failed to verify.
     */
    public function receipt(): ?AppReceipt
    {
        return $this->receipt;
    }

    /** Why there is no receipt; non-null exactly when {@see receipt()} is null. */
    public function failureReason(): ?Reason
    {
        return $this->failureReason;
    }

    /**
     * The unexpected `Throwable` behind {@see Reason::InternalError}, for
     * logging; null for every other outcome.
     */
    public function failureCause(): ?Throwable
    {
        return $this->failureCause;
    }

    /** The instant rendered as `request_date`, fixed when the call was made. */
    public function requestDate(): DateTimeImmutable
    {
        return $this->requestDate;
    }

    /**
     * The response body, built on each call. With no argument, the
     * endpoint's own environment. With {@see Environment::Production} or
     * {@see Environment::Sandbox}, what an endpoint of that environment would
     * answer for the same receipt at the same {@see requestDate()}: a
     * production receipt answers 0 on Production and 21008 on Sandbox, any
     * other receipt answers 21007 on Production and 0 on Sandbox, and a
     * failed result answers its own status on both.
     *
     * @throws InvalidArgumentException for any other environment, as the
     *         endpoint's constructor does
     *
     * @return array<string, mixed>
     */
    public function toResponse(?Environment $environment = null): array
    {
        $environment ??= $this->environment;
        $status = $this->statusFor($environment);
        if ($status !== VerifyReceiptEndpoint::STATUS_OK || $this->receipt === null) {
            return ['status' => $status];
        }
        try {
            $receipt = self::receiptJson($this->receipt, $this->requestDate);
        } catch (Throwable) {
            // What the endpoint has always answered when the rendering itself
            // fails, for example a timezone database without
            // America/Los_Angeles.
            return ['status' => VerifyReceiptEndpoint::STATUS_INTERNAL];
        }

        return [
            'status' => VerifyReceiptEndpoint::STATUS_OK,
            'environment' => $environment->value,
            'receipt' => $receipt,
        ];
    }

    /**
     * {@see toResponse()} serialized as the JSON response body, byte for byte
     * what {@see VerifyReceiptEndpoint::verifyReceiptJson()} answers.
     *
     * @throws InvalidArgumentException for an environment other than
     *         Production or Sandbox
     */
    public function toJson(?Environment $environment = null): string
    {
        $encoded = json_encode($this->toResponse($environment));

        return $encoded === false ? '{"status":21009}' : $encoded;
    }

    private function statusFor(Environment $environment): int
    {
        if ($environment !== Environment::Production && $environment !== Environment::Sandbox) {
            throw new InvalidArgumentException(
                'environment must be Environment::Production or Environment::Sandbox',
            );
        }
        if ($this->receipt === null) {
            return match ($this->failureReason) {
                Reason::MalformedRequest,
                Reason::RequestTooLarge,
                Reason::InvalidReceiptFormat => VerifyReceiptEndpoint::STATUS_MALFORMED,
                Reason::InternalError => VerifyReceiptEndpoint::STATUS_INTERNAL,
                default => VerifyReceiptEndpoint::STATUS_NOT_AUTHENTICATED,
            };
        }
        // 21007/21008 routing from the receipt_type attribute, failing
        // closed: production is exactly "Production" and "ProductionVPP".
        // Everything else ("ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute) routes as non-production
        // (PLAN.md D10; a VPP-sandbox misroute found by adversarial review
        // drove this tightening).
        $productionReceipt = $this->receipt->receiptType === 'Production'
            || $this->receipt->receiptType === 'ProductionVPP';
        if ($environment === Environment::Production && !$productionReceipt) {
            return VerifyReceiptEndpoint::STATUS_SANDBOX_RECEIPT_ON_PRODUCTION;
        }
        if ($environment === Environment::Sandbox && $productionReceipt) {
            return VerifyReceiptEndpoint::STATUS_PRODUCTION_RECEIPT_ON_SANDBOX;
        }

        return VerifyReceiptEndpoint::STATUS_OK;
    }

    /** @return array<string, mixed> */
    private static function receiptJson(AppReceipt $fields, DateTimeInterface $requestDate): array
    {
        $receipt = [];
        self::put($receipt, 'receipt_type', $fields->receiptType);
        // Apple echoes attribute 1 under both names — its response reference
        // defines adam_id as "See app_item_id" — and as JSON numbers, not as
        // the strings the in-app integers are rendered with.
        self::put($receipt, 'adam_id', $fields->appItemId);
        self::put($receipt, 'app_item_id', $fields->appItemId);
        self::put($receipt, 'bundle_id', $fields->bundleId);
        self::put($receipt, 'application_version', $fields->appVersion);
        self::put($receipt, 'download_id', $fields->downloadId);
        self::put($receipt, 'version_external_identifier', $fields->versionExternalIdentifier);
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
            'is_trial_period',
            $purchase->isTrialPeriod === null
                ? null
                : ($purchase->isTrialPeriod === 1 ? 'true' : 'false'),
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
