<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use DateTimeImmutable;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\AppReceipt;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * The receipt payload attribute grammar (Apple, "Validating receipts on the
 * device"):
 *
 *     ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
 *
 * Ported from `node/src/receipt-payload.ts`. The payload is decoded *before*
 * the signature is checked, because the creation date is the instant the
 * chain's validity is judged at — nothing decoded here may be returned or
 * acted on until the chain and signature checks have passed.
 *
 * @internal
 */
final class ReceiptPayload
{
    private const ATTR_RECEIPT_TYPE = 0;
    private const ATTR_BUNDLE_ID = 2;
    private const ATTR_APP_VERSION = 3;
    private const ATTR_OPAQUE_VALUE = 4;
    private const ATTR_SHA1_HASH = 5;
    private const ATTR_CREATION_DATE = 12;
    private const ATTR_IN_APP = 17;
    private const ATTR_ORIGINAL_PURCHASE_DATE = 18;
    private const ATTR_ORIGINAL_APP_VERSION = 19;
    private const ATTR_EXPIRATION_DATE = 21;

    private const IAP_QUANTITY = 1701;
    private const IAP_PRODUCT_ID = 1702;
    private const IAP_TRANSACTION_ID = 1703;
    private const IAP_PURCHASE_DATE = 1704;
    private const IAP_ORIGINAL_TRANSACTION_ID = 1705;
    private const IAP_ORIGINAL_PURCHASE_DATE = 1706;
    private const IAP_EXPIRES_DATE = 1708;
    private const IAP_WEB_ORDER_LINE_ITEM_ID = 1711;
    private const IAP_CANCELLATION_DATE = 1712;
    private const IAP_IS_IN_INTRO_OFFER_PERIOD = 1719;

    /**
     * Attribute *types* live in a 32-bit signed space: every type Apple has
     * ever issued is a small number, and a value above 2^31-1 cannot be one.
     *
     * Mapping such a type onto a sentinel (Java shipped -1) and filing it
     * under `unknownAttributes` collides every out-of-range attribute into one
     * bucket keyed by a value that is not a type, and lets two ports disagree
     * about what the same receipt says. It is a malformed receipt in every
     * port. `fixtures/cases.json` pins this as
     * `receipt/reject-attribute-type-above-int32-max`.
     */
    private const MAX_ATTRIBUTE_TYPE = 2147483647;

    /**
     * The timezone designator is mandatory. A naive date would be read as the
     * server's LOCAL time, and this date is the instant the chain's validity
     * is judged at — so the same receipt would verify on one host and fail on
     * another. Java (`Instant.parse`) and Swift (`ISO8601DateFormatter`)
     * reject a naive date too.
     */
    private const RFC_3339 =
        '/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/';

    /** @throws VerificationException */
    public static function parse(string $content, int $nodeBudget): AppReceipt
    {
        $attributes = self::parseAttributeSet($content, 'receipt payload', $nodeBudget);

        $unknown = [];
        $receiptType = null;
        $bundleId = null;
        $bundleIdBytes = null;
        $appVersion = null;
        $opaqueValue = null;
        $sha1Hash = null;
        $creationDate = null;
        $originalPurchaseDate = null;
        $originalAppVersion = null;
        $expirationDate = null;
        $inAppPurchases = [];

        foreach ($attributes as [$type, $value]) {
            switch ($type) {
                case self::ATTR_RECEIPT_TYPE:
                    $receiptType = self::decodeString($value, $nodeBudget);
                    break;
                case self::ATTR_BUNDLE_ID:
                    $bundleId = self::decodeString($value, $nodeBudget);
                    $bundleIdBytes = $value;
                    break;
                case self::ATTR_APP_VERSION:
                    $appVersion = self::decodeString($value, $nodeBudget);
                    break;
                case self::ATTR_OPAQUE_VALUE:
                    $opaqueValue = $value;
                    break;
                case self::ATTR_SHA1_HASH:
                    $sha1Hash = $value;
                    break;
                case self::ATTR_CREATION_DATE:
                    $creationDate = self::decodeDate($value, $nodeBudget);
                    break;
                case self::ATTR_IN_APP:
                    $inAppPurchases[] = self::parseInApp($value, $nodeBudget);
                    break;
                case self::ATTR_ORIGINAL_PURCHASE_DATE:
                    $originalPurchaseDate = self::decodeDate($value, $nodeBudget);
                    break;
                case self::ATTR_ORIGINAL_APP_VERSION:
                    $originalAppVersion = self::decodeString($value, $nodeBudget);
                    break;
                case self::ATTR_EXPIRATION_DATE:
                    $expirationDate = self::decodeDate($value, $nodeBudget);
                    break;
                default:
                    $unknown[$type][] = $value;
                    break;
            }
        }

        return new AppReceipt(
            receiptType: $receiptType,
            bundleId: $bundleId,
            bundleIdBytes: $bundleIdBytes,
            appVersion: $appVersion,
            opaqueValue: $opaqueValue,
            sha1Hash: $sha1Hash,
            creationDate: $creationDate,
            originalPurchaseDate: $originalPurchaseDate,
            originalAppVersion: $originalAppVersion,
            expirationDate: $expirationDate,
            inAppPurchases: $inAppPurchases,
            unknownAttributes: $unknown,
        );
    }

    /** @throws VerificationException */
    private static function parseInApp(string $value, int $nodeBudget): InAppPurchase
    {
        $attributes = self::parseAttributeSet($value, 'in-app purchase attribute', $nodeBudget);

        $unknown = [];
        $quantity = null;
        $productId = null;
        $transactionId = null;
        $originalTransactionId = null;
        $purchaseDate = null;
        $originalPurchaseDate = null;
        $expiresDate = null;
        $cancellationDate = null;
        $webOrderLineItemId = null;
        $isInIntroOfferPeriod = null;

        foreach ($attributes as [$type, $v]) {
            switch ($type) {
                case self::IAP_QUANTITY:
                    $quantity = self::decodeInteger($v, $nodeBudget);
                    break;
                case self::IAP_PRODUCT_ID:
                    $productId = self::decodeString($v, $nodeBudget);
                    break;
                case self::IAP_TRANSACTION_ID:
                    $transactionId = self::decodeString($v, $nodeBudget);
                    break;
                case self::IAP_PURCHASE_DATE:
                    $purchaseDate = self::decodeDate($v, $nodeBudget);
                    break;
                case self::IAP_ORIGINAL_TRANSACTION_ID:
                    $originalTransactionId = self::decodeString($v, $nodeBudget);
                    break;
                case self::IAP_ORIGINAL_PURCHASE_DATE:
                    $originalPurchaseDate = self::decodeDate($v, $nodeBudget);
                    break;
                case self::IAP_EXPIRES_DATE:
                    $expiresDate = self::decodeDate($v, $nodeBudget);
                    break;
                case self::IAP_WEB_ORDER_LINE_ITEM_ID:
                    $webOrderLineItemId = self::decodeInteger($v, $nodeBudget);
                    break;
                case self::IAP_CANCELLATION_DATE:
                    $cancellationDate = self::decodeDate($v, $nodeBudget);
                    break;
                case self::IAP_IS_IN_INTRO_OFFER_PERIOD:
                    $isInIntroOfferPeriod = self::decodeInteger($v, $nodeBudget);
                    break;
                default:
                    $unknown[$type][] = $v;
                    break;
            }
        }

        return new InAppPurchase(
            quantity: $quantity,
            productId: $productId,
            transactionId: $transactionId,
            originalTransactionId: $originalTransactionId,
            purchaseDate: $purchaseDate,
            originalPurchaseDate: $originalPurchaseDate,
            expiresDate: $expiresDate,
            cancellationDate: $cancellationDate,
            webOrderLineItemId: $webOrderLineItemId,
            isInIntroOfferPeriod: $isInIntroOfferPeriod,
            unknownAttributes: $unknown,
        );
    }

    /**
     * @return list<array{int, string}> type => raw value bytes
     *
     * @throws VerificationException
     */
    private static function parseAttributeSet(string $der, string $what, int $nodeBudget): array
    {
        try {
            $node = Der::parse($der, $nodeBudget);
        } catch (ParseException $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, "{$what} is not valid ASN.1", $e);
        }
        if (Der::isOctetString($node)) {
            // Xcode receipts double-wrap the payload in an extra OCTET STRING.
            try {
                $node = Der::parse(Der::octets($node), $nodeBudget);
            } catch (ParseException $e) {
                throw new VerificationException(
                    Reason::InvalidReceiptFormat,
                    "{$what} double-wrap is not valid ASN.1",
                    $e,
                );
            }
        }
        if ($node->tag !== Der::TAG_SET) {
            throw new VerificationException(Reason::InvalidReceiptFormat, "{$what} is not an ASN.1 SET");
        }

        $attributes = [];
        foreach ($node->children() as $child) {
            $fields = $child->children();
            if ($child->tag !== Der::TAG_SEQUENCE || count($fields) < 3
                || $fields[0]->tag !== Der::TAG_INTEGER || !Der::isOctetString($fields[2])) {
                throw new VerificationException(Reason::InvalidReceiptFormat, 'malformed receipt attribute');
            }
            $attributes[] = [self::attributeType($fields[0]), Der::octets($fields[2])];
        }

        return $attributes;
    }

    /** @throws VerificationException */
    private static function attributeType(Asn1Node $node): int
    {
        $type = self::integerValue($node);
        if ($type > self::MAX_ATTRIBUTE_TYPE) {
            throw new VerificationException(
                Reason::InvalidReceiptFormat,
                'receipt attribute type exceeds the 32-bit signed range',
            );
        }

        return $type;
    }

    /** @throws VerificationException */
    private static function integerValue(Asn1Node $node): int
    {
        // 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id).
        // Combined with the negative check below, this keeps every value inside
        // PHP's signed 64-bit int without a bignum extension.
        if (strlen($node->contents) > 8) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'attribute integer out of range');
        }
        if ($node->contents !== '' && ord($node->contents[0]) >= 0x80) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'negative receipt integer');
        }
        $value = 0;
        for ($i = 0, $n = strlen($node->contents); $i < $n; ++$i) {
            $value = $value * 256 + ord($node->contents[$i]);
        }

        return $value;
    }

    /** @throws VerificationException */
    private static function decodeNested(string $der, int $nodeBudget): Asn1Node
    {
        try {
            return Der::parse($der, $nodeBudget);
        } catch (ParseException $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'attribute value is not valid ASN.1', $e);
        }
    }

    /** @throws VerificationException */
    private static function decodeString(string $der, int $nodeBudget): string
    {
        $node = self::decodeNested($der, $nodeBudget);
        if ($node->tag !== Der::TAG_UTF8_STRING && $node->tag !== Der::TAG_IA5_STRING) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'attribute value is not an ASN.1 string');
        }

        return $node->contents;
    }

    /** @throws VerificationException */
    private static function decodeInteger(string $der, int $nodeBudget): int
    {
        $node = self::decodeNested($der, $nodeBudget);
        if ($node->tag !== Der::TAG_INTEGER) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'attribute value is not an ASN.1 integer');
        }

        return self::integerValue($node);
    }

    /**
     * RFC 3339 date in an IA5String; an empty string means absent, which real
     * receipts genuinely do.
     *
     * `DateTimeImmutable::createFromFormat()` and `new DateTimeImmutable()`
     * both ROLL OVER nonsense rather than failing — `2020-13-45T99:99:99Z`
     * parses to 2021-02-18 — so the components are range-checked explicitly
     * before a date object is built. That check is the whole reason this is
     * not two lines.
     *
     * @throws VerificationException
     */
    private static function decodeDate(string $der, int $nodeBudget): ?DateTimeImmutable
    {
        $text = self::decodeString($der, $nodeBudget);
        if ($text === '') {
            return null;
        }
        if (preg_match(self::RFC_3339, $text, $m) !== 1) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'unparseable receipt date');
        }
        $year = (int) $m[1];
        $month = (int) $m[2];
        $day = (int) $m[3];
        $hour = (int) $m[4];
        $minute = (int) $m[5];
        $second = (int) $m[6];
        if ($month < 1 || $month > 12 || $hour > 23 || $minute > 59 || $second > 59
            || !checkdate($month, $day, $year)) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'out-of-range receipt date');
        }
        if ($m[8] !== 'Z') {
            $offsetHour = (int) substr($m[8], 1, 2);
            $offsetMinute = (int) substr($m[8], 4, 2);
            if ($offsetHour > 23 || $offsetMinute > 59) {
                throw new VerificationException(Reason::InvalidReceiptFormat, 'out-of-range receipt date offset');
            }
        }
        try {
            $date = new DateTimeImmutable($text);
        } catch (\Throwable $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'unparseable receipt date', $e);
        }

        return $date->setTimezone(new DateTimeZone('UTC'));
    }
}
