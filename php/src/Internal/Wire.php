<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Failure;
use EminDeniz99\ApplePurchaseReceiptVerifier\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\JsonPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationResult;

/**
 * Reads the JSON `aprv` answers with (docs/rust-core/ARCHITECTURE.md §4,
 * docs/design/0.7-api.md "Our JSON"). Mapping only: the module has already
 * decided every verdict, and a value that does not have the shape the
 * contract gives is a fault of the module, never a verdict.
 *
 * @internal
 */
final class Wire
{
    private function __construct()
    {
    }

    /**
     * @return VerificationResult<ReceiptPayload>
     *
     * @throws ModuleFaultException
     */
    public static function receiptResult(string $json): VerificationResult
    {
        $value = self::object($json);
        if (($value['verified'] ?? null) === true) {
            return new VerificationResult(payload: self::receiptPayload($value['payload'] ?? null));
        }

        return self::failure($value);
    }

    /**
     * @return VerificationResult<JsonPayload>
     *
     * @throws ModuleFaultException
     */
    public static function signedDataResult(string $json): VerificationResult
    {
        $value = self::object($json);
        if (($value['verified'] ?? null) === true) {
            $payload = $value['payload'] ?? null;
            if (!is_string($payload)) {
                throw self::bad('the signed payload is not a JSON string');
            }

            return new VerificationResult(payload: new JsonPayload($payload));
        }

        return self::failure($value);
    }

    /**
     * Apple's response JSON goes back to the caller byte for byte; it is
     * only checked to be a JSON object with an integer `status`.
     *
     * @throws ModuleFaultException
     */
    public static function endpointAnswer(string $json): string
    {
        if (!is_int(self::object($json)['status'] ?? null)) {
            throw self::bad('the endpoint answer has no integer status');
        }

        return $json;
    }

    /**
     * @param array<array-key, mixed> $value
     *
     * @return VerificationResult<never>
     *
     * @throws ModuleFaultException
     */
    private static function failure(array $value): VerificationResult
    {
        if (($value['verified'] ?? null) !== false) {
            throw self::bad('the answer is neither a payload nor a failure');
        }
        $token = $value['reason'] ?? null;
        $message = $value['message'] ?? null;
        if (!is_string($token) || !is_string($message)) {
            throw self::bad('a failure without a reason and a message');
        }
        $reason = Reason::tryFrom($token);
        if ($reason === null) {
            throw self::bad('a reason outside the eight of 0.7');
        }

        // The module's own verdicts carry no cause: it is a Rust-only chain.
        /** @var VerificationResult<never> $result */
        $result = new VerificationResult(failure: new Failure($reason, $message));

        return $result;
    }

    /** @throws ModuleFaultException */
    private static function receiptPayload(mixed $value): ReceiptPayload
    {
        $v = self::asObject($value, 'a receipt payload');
        $inApp = $v['in_app'] ?? null;
        if ($inApp !== null && !is_array($inApp)) {
            throw self::bad('expected a list of in-app purchases');
        }

        return new ReceiptPayload(
            receiptType: self::string($v['receipt_type'] ?? null),
            appItemId: self::id($v['app_item_id'] ?? null),
            bundleId: self::string($v['bundle_id'] ?? null),
            bundleIdBytes: self::octets($v['bundle_id_bytes'] ?? null),
            applicationVersion: self::string($v['application_version'] ?? null),
            opaqueValue: self::octets($v['opaque_value'] ?? null),
            sha1Hash: self::octets($v['sha1_hash'] ?? null),
            receiptCreationDateMs: self::int($v['receipt_creation_date_ms'] ?? null),
            downloadId: self::id($v['download_id'] ?? null),
            versionExternalIdentifier: self::id($v['version_external_identifier'] ?? null),
            inApp: array_map(self::inApp(...), array_values($inApp ?? [])),
            originalPurchaseDateMs: self::int($v['original_purchase_date_ms'] ?? null),
            originalApplicationVersion: self::string($v['original_application_version'] ?? null),
            expirationDateMs: self::int($v['expiration_date_ms'] ?? null),
            unknownAttributes: self::unknown($v['unknown_attributes'] ?? null),
        );
    }

    /** @throws ModuleFaultException */
    private static function inApp(mixed $value): InAppPurchase
    {
        $v = self::asObject($value, 'an in-app purchase');

        return new InAppPurchase(
            quantity: self::int($v['quantity'] ?? null),
            productId: self::string($v['product_id'] ?? null),
            transactionId: self::string($v['transaction_id'] ?? null),
            purchaseDateMs: self::int($v['purchase_date_ms'] ?? null),
            originalTransactionId: self::string($v['original_transaction_id'] ?? null),
            originalPurchaseDateMs: self::int($v['original_purchase_date_ms'] ?? null),
            expiresDateMs: self::int($v['expires_date_ms'] ?? null),
            webOrderLineItemId: self::id($v['web_order_line_item_id'] ?? null),
            cancellationDateMs: self::int($v['cancellation_date_ms'] ?? null),
            isTrialPeriod: self::flag($v['is_trial_period'] ?? null),
            isInIntroOfferPeriod: self::flag($v['is_in_intro_offer_period'] ?? null),
            unknownAttributes: self::unknown($v['unknown_attributes'] ?? null),
        );
    }

    /**
     * `{"<decimal type>": ["<base64>", ...]}`, the values in receipt order.
     *
     * @return array<int, list<string>>
     *
     * @throws ModuleFaultException
     */
    private static function unknown(mixed $value): array
    {
        if ($value === null) {
            return [];
        }
        $out = [];
        foreach (self::asObject($value, 'the unknown attributes') as $type => $values) {
            if (!is_int($type) || !is_array($values)) {
                throw self::bad('expected a decimal attribute type and a list of values');
            }
            $out[$type] = array_map(
                static fn (mixed $one): string => self::octets($one) ?? throw self::bad('expected base64, not null'),
                array_values($values),
            );
        }

        return $out;
    }

    /** @throws ModuleFaultException */
    private static function string(mixed $value): ?string
    {
        if ($value === null || is_string($value)) {
            return $value;
        }
        throw self::bad('expected a string or null');
    }

    /** @throws ModuleFaultException */
    private static function int(mixed $value): ?int
    {
        if ($value === null || is_int($value)) {
            return $value;
        }
        throw self::bad('expected an integer or null');
    }

    /** @throws ModuleFaultException */
    private static function flag(mixed $value): ?bool
    {
        if ($value === null || is_bool($value)) {
            return $value;
        }
        throw self::bad('expected a boolean or null');
    }

    /**
     * A 64-bit id, sent as a decimal string so no reader rounds it.
     *
     * @throws ModuleFaultException
     */
    private static function id(mixed $value): ?int
    {
        $text = self::string($value);
        if ($text === null) {
            return null;
        }
        $id = (int) $text;
        if ((string) $id !== $text) {
            throw self::bad('expected a decimal id');
        }

        return $id;
    }

    /** @throws ModuleFaultException */
    private static function octets(mixed $value): ?string
    {
        $text = self::string($value);
        if ($text === null) {
            return null;
        }
        $bytes = base64_decode($text, true);
        if ($bytes === false) {
            throw self::bad('expected padded base64');
        }

        return $bytes;
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ModuleFaultException
     */
    private static function object(string $json): array
    {
        try {
            $value = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw self::bad('the answer is not JSON');
        }

        return self::asObject($value, 'the answer');
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ModuleFaultException
     */
    private static function asObject(mixed $value, string $what): array
    {
        if (!is_array($value)) {
            throw self::bad("{$what} is not a JSON object");
        }

        return $value;
    }

    private static function bad(string $why): ModuleFaultException
    {
        return new ModuleFaultException('BAD_ANSWER', 'the verification module answered unreadably: ' . $why);
    }
}
