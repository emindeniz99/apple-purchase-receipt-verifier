<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\PayloadJson;

/**
 * A verified legacy app receipt (docs/design/0.7-api.md §1). Only receipts
 * returned by {@see Verifier::verifyReceipt()} should be trusted: on any
 * failure nothing is returned at all, so there is no such thing as a
 * partially-verified instance of this class.
 *
 * Field names are Apple's own words from the verifyReceipt response, so this
 * class, {@see toJson()} and Apple's documentation share one vocabulary.
 * `null` means the attribute was absent (or, for a date, did not parse); the
 * library invents no values. Byte-valued properties (`$bundleIdBytes`,
 * `$opaqueValue`, `$sha1Hash`, and the values inside `$unknownAttributes`)
 * are PHP binary strings.
 *
 * Nothing here has been checked against anything: the bundle id,
 * environment and purchases are whatever Apple signed, and deciding whether
 * to accept them is the caller's job (docs/design/0.7-api.md, "Principles").
 * {@see Environment::fromReceiptType()} reads {@see $receiptType}; the
 * device-hash check is `SHA-1($deviceId . $opaqueValue . $bundleIdBytes)`
 * compared with {@see $sha1Hash}.
 */
final readonly class ReceiptPayload
{
    /**
     * @param string|null $receiptType attribute 0, such as `Production` or `ProductionSandbox`
     * @param int|null $appItemId attribute 1, the app's App Store item id; zero in sandbox receipts
     * @param string|null $bundleId attribute 2, decoded
     * @param string|null $bundleIdBytes attribute 2, the value octets exactly as they sit in the receipt: input to the device hash
     * @param string|null $applicationVersion attribute 3
     * @param string|null $opaqueValue attribute 4, the value octets: input to the device hash
     * @param string|null $sha1Hash attribute 5, the value octets: the device hash itself
     * @param int|null $receiptCreationDateMs attribute 12, when Apple created the receipt
     * @param int|null $downloadId attribute 15
     * @param int|null $versionExternalIdentifier attribute 16
     * @param list<InAppPurchase> $inApp attribute 17, one entry per purchase, in receipt order
     * @param int|null $originalPurchaseDateMs attribute 18
     * @param string|null $originalApplicationVersion attribute 19, the version the user originally purchased
     * @param int|null $expirationDateMs attribute 21, set only on receipts that expire (volume purchase)
     * @param array<int, list<string>> $unknownAttributes raw value octets of
     *        the attribute types not modelled above, by type, in receipt
     *        order — forward compatibility for fields Apple may add. The
     *        attribute's `version` integer is not kept. Verified, but undecoded.
     */
    public function __construct(
        public ?string $receiptType = null,
        public ?int $appItemId = null,
        public ?string $bundleId = null,
        public ?string $bundleIdBytes = null,
        public ?string $applicationVersion = null,
        public ?string $opaqueValue = null,
        public ?string $sha1Hash = null,
        public ?int $receiptCreationDateMs = null,
        public ?int $downloadId = null,
        public ?int $versionExternalIdentifier = null,
        public array $inApp = [],
        public ?int $originalPurchaseDateMs = null,
        public ?string $originalApplicationVersion = null,
        public ?int $expirationDateMs = null,
        public array $unknownAttributes = [],
    ) {
    }

    /**
     * This payload as JSON, for logging and storage
     * (docs/design/0.7-api.md, "Our JSON"). Every port writes the same
     * value; the bytes may differ. snake_case names, dates as numbers with
     * a `_ms` suffix, 64-bit ids (`app_item_id`, `download_id`,
     * `version_external_identifier`, `web_order_line_item_id`) as strings,
     * bytes as padded standard base64 and `null` for a missing value.
     *
     * @throws \JsonException when a string field is not valid UTF-8, which a
     *         payload decoded from a receipt never is
     */
    public function toJson(): string
    {
        return json_encode([
            'receipt_type' => $this->receiptType,
            'app_item_id' => PayloadJson::id($this->appItemId),
            'bundle_id' => $this->bundleId,
            'bundle_id_bytes' => PayloadJson::bytes($this->bundleIdBytes),
            'application_version' => $this->applicationVersion,
            'opaque_value' => PayloadJson::bytes($this->opaqueValue),
            'sha1_hash' => PayloadJson::bytes($this->sha1Hash),
            'receipt_creation_date_ms' => $this->receiptCreationDateMs,
            'download_id' => PayloadJson::id($this->downloadId),
            'version_external_identifier' => PayloadJson::id($this->versionExternalIdentifier),
            'in_app' => array_map(PayloadJson::inApp(...), $this->inApp),
            'original_purchase_date_ms' => $this->originalPurchaseDateMs,
            'original_application_version' => $this->originalApplicationVersion,
            'expiration_date_ms' => $this->expirationDateMs,
            'unknown_attributes' => PayloadJson::attributes($this->unknownAttributes),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
