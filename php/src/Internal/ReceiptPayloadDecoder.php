<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;

/**
 * Decodes the receipt payload attribute grammar (Apple, "Validating
 * receipts on the device"):
 *
 *     ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
 *
 * Only {@see readCreationDate()} runs before the signer is trusted, because
 * it is the instant the chain's validity is judged at; the full
 * {@see parse()} runs only after the chain and signature checks have
 * passed, so any failure in it is {@see Reason::UnreadablePayload}, never a
 * format verdict about the caller's input.
 *
 * Decode rules (docs/design/0.7-api.md, "Reading certificates and signed
 * attributes" / "Decode rules", owner 2026-09-27):
 *
 * - A missing attribute decodes to `null`; the library invents no values.
 * - A known attribute that appears more than once: the FIRST occurrence in
 *   receipt order wins for the typed field (and for the chain date); every
 *   later copy is kept raw in `unknownAttributes`, never lost.
 * - A known attribute whose value does not parse: its typed field stays
 *   `null` and the raw value is kept in `unknownAttributes` — except the
 *   bundle id, whose octets already live in `bundleIdBytes`.
 * - An IA5String holding a byte at or above 0x80 does not parse (7-bit
 *   only); a UTF8String that is not valid UTF-8 does not parse either.
 * - An INTEGER must be DER: empty, or a redundant leading octet, does not
 *   parse. Reported signed, as the receipt carries it: negative values are
 *   not rejected.
 * - A date parses only in the exact form `YYYY-MM-DDTHH:MM:SSZ`; an empty
 *   string means "not set" (typed field `null`, nothing kept raw); any
 *   other non-empty string that does not parse is kept raw.
 *
 * @internal
 */
final class ReceiptPayloadDecoder
{
    private const ATTR_RECEIPT_TYPE = 0;
    private const ATTR_APP_ITEM_ID = 1;
    private const ATTR_BUNDLE_ID = 2;
    private const ATTR_APP_VERSION = 3;
    private const ATTR_OPAQUE_VALUE = 4;
    private const ATTR_SHA1_HASH = 5;
    private const ATTR_CREATION_DATE = 12;
    private const ATTR_DOWNLOAD_ID = 15;
    private const ATTR_VERSION_EXTERNAL_IDENTIFIER = 16;
    private const ATTR_IN_APP = 17;
    private const ATTR_ORIGINAL_PURCHASE_DATE = 18;
    private const ATTR_ORIGINAL_APP_VERSION = 19;
    private const ATTR_EXPIRATION_DATE = 21;

    /** Single-value top-level attribute types: a second occurrence is kept raw, never overwrites the first. */
    private const TOP_LEVEL_TYPES = [
        self::ATTR_RECEIPT_TYPE => true,
        self::ATTR_APP_ITEM_ID => true,
        self::ATTR_BUNDLE_ID => true,
        self::ATTR_APP_VERSION => true,
        self::ATTR_OPAQUE_VALUE => true,
        self::ATTR_SHA1_HASH => true,
        self::ATTR_CREATION_DATE => true,
        self::ATTR_DOWNLOAD_ID => true,
        self::ATTR_VERSION_EXTERNAL_IDENTIFIER => true,
        self::ATTR_ORIGINAL_PURCHASE_DATE => true,
        self::ATTR_ORIGINAL_APP_VERSION => true,
        self::ATTR_EXPIRATION_DATE => true,
    ];

    private const IAP_QUANTITY = 1701;
    private const IAP_PRODUCT_ID = 1702;
    private const IAP_TRANSACTION_ID = 1703;
    private const IAP_PURCHASE_DATE = 1704;
    private const IAP_ORIGINAL_TRANSACTION_ID = 1705;
    private const IAP_ORIGINAL_PURCHASE_DATE = 1706;
    private const IAP_EXPIRES_DATE = 1708;
    private const IAP_WEB_ORDER_LINE_ITEM_ID = 1711;
    private const IAP_CANCELLATION_DATE = 1712;
    private const IAP_IS_TRIAL_PERIOD = 1713;
    private const IAP_IS_IN_INTRO_OFFER_PERIOD = 1719;

    private const IN_APP_TYPES = [
        self::IAP_QUANTITY => true, self::IAP_PRODUCT_ID => true, self::IAP_TRANSACTION_ID => true,
        self::IAP_PURCHASE_DATE => true, self::IAP_ORIGINAL_TRANSACTION_ID => true,
        self::IAP_ORIGINAL_PURCHASE_DATE => true, self::IAP_EXPIRES_DATE => true,
        self::IAP_WEB_ORDER_LINE_ITEM_ID => true, self::IAP_CANCELLATION_DATE => true,
        self::IAP_IS_TRIAL_PERIOD => true, self::IAP_IS_IN_INTRO_OFFER_PERIOD => true,
    ];

    /**
     * Attribute *types* live in a 32-bit signed space: every type Apple has
     * ever issued is a small number, and a value above 2^31-1 cannot be
     * one. A wider type refuses the whole payload (owner, 2026-09-27).
     */
    private const MAX_ATTRIBUTE_TYPE = 2147483647;

    private const RFC_3339 = '/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/';

    /**
     * The receipt creation date (attribute 12), read the only way anything
     * in a payload is read before its signer is trusted: the top-level
     * attribute SET is walked shallowly, and only the FIRST occurrence of
     * type 12 is decoded. `null` means "judge the chain at the clock": no
     * attribute 12, or a first one that is empty or does not decode. Never
     * throws: nothing is trusted yet, so nothing here can blame anyone.
     */
    public static function readCreationDateMs(string $content, int $nodeBudget): ?int
    {
        try {
            foreach (self::parseAttributeSet($content, 'receipt payload', $nodeBudget) as [$type, $value]) {
                if ($type === self::ATTR_CREATION_DATE) {
                    return self::dateOrNull($value, $nodeBudget);
                }
            }

            return null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** @throws PayloadFormatError when the top-level attribute set itself is malformed */
    public static function parse(string $content, int $nodeBudget): ReceiptPayload
    {
        $attributes = self::parseAttributeSet($content, 'receipt payload', $nodeBudget);

        $unknown = [];
        $seen = [];
        $receiptType = null;
        $bundleId = null;
        $bundleIdBytes = null;
        $appVersion = null;
        $opaqueValue = null;
        $sha1Hash = null;
        $creationDateMs = null;
        $originalPurchaseDateMs = null;
        $originalAppVersion = null;
        $expirationDateMs = null;
        $appItemId = null;
        $downloadId = null;
        $versionExternalIdentifier = null;
        $inApp = [];

        foreach ($attributes as [$type, $value]) {
            if (isset(self::TOP_LEVEL_TYPES[$type])) {
                if (isset($seen[$type])) {
                    $unknown[$type][] = $value;
                    continue;
                }
                $seen[$type] = true;
            }
            try {
                switch ($type) {
                    case self::ATTR_RECEIPT_TYPE:
                        $receiptType = self::decodeString($value, $nodeBudget);
                        break;
                    case self::ATTR_APP_ITEM_ID:
                        $appItemId = self::decodeInteger($value, $nodeBudget);
                        break;
                    case self::ATTR_BUNDLE_ID:
                        $bundleIdBytes = $value;
                        $bundleId = self::decodeString($value, $nodeBudget);
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
                        $creationDateMs = self::dateOrThrow($value, $nodeBudget);
                        break;
                    case self::ATTR_DOWNLOAD_ID:
                        $downloadId = self::decodeInteger($value, $nodeBudget);
                        break;
                    case self::ATTR_VERSION_EXTERNAL_IDENTIFIER:
                        $versionExternalIdentifier = self::decodeInteger($value, $nodeBudget);
                        break;
                    case self::ATTR_IN_APP:
                        $inApp[] = self::parseInApp($value, $nodeBudget);
                        break;
                    case self::ATTR_ORIGINAL_PURCHASE_DATE:
                        $originalPurchaseDateMs = self::dateOrThrow($value, $nodeBudget);
                        break;
                    case self::ATTR_ORIGINAL_APP_VERSION:
                        $originalAppVersion = self::decodeString($value, $nodeBudget);
                        break;
                    case self::ATTR_EXPIRATION_DATE:
                        $expirationDateMs = self::dateOrThrow($value, $nodeBudget);
                        break;
                    default:
                        $unknown[$type][] = $value;
                        break;
                }
            } catch (PayloadFormatError) {
                // A known attribute whose value does not decode: the typed
                // field stays null and the value is kept raw — except the
                // bundle id, whose octets already live in bundleIdBytes.
                if ($type !== self::ATTR_BUNDLE_ID) {
                    $unknown[$type][] = $value;
                } else {
                    $bundleId = null;
                }
            }
        }

        return new ReceiptPayload(
            receiptType: $receiptType,
            appItemId: $appItemId,
            bundleId: $bundleId,
            bundleIdBytes: $bundleIdBytes,
            applicationVersion: $appVersion,
            opaqueValue: $opaqueValue,
            sha1Hash: $sha1Hash,
            receiptCreationDateMs: $creationDateMs,
            downloadId: $downloadId,
            versionExternalIdentifier: $versionExternalIdentifier,
            inApp: $inApp,
            originalPurchaseDateMs: $originalPurchaseDateMs,
            originalApplicationVersion: $originalAppVersion,
            expirationDateMs: $expirationDateMs,
            unknownAttributes: $unknown,
        );
    }

    /** @throws PayloadFormatError when the in-app attribute set itself is malformed */
    private static function parseInApp(string $value, int $nodeBudget): InAppPurchase
    {
        $attributes = self::parseAttributeSet($value, 'in-app purchase attribute', $nodeBudget);

        $unknown = [];
        $seen = [];
        $quantity = null;
        $productId = null;
        $transactionId = null;
        $originalTransactionId = null;
        $purchaseDateMs = null;
        $originalPurchaseDateMs = null;
        $expiresDateMs = null;
        $cancellationDateMs = null;
        $webOrderLineItemId = null;
        $isTrialPeriod = null;
        $isInIntroOfferPeriod = null;

        foreach ($attributes as [$type, $v]) {
            if (isset(self::IN_APP_TYPES[$type])) {
                if (isset($seen[$type])) {
                    $unknown[$type][] = $v;
                    continue;
                }
                $seen[$type] = true;
            }
            try {
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
                        $purchaseDateMs = self::dateOrThrow($v, $nodeBudget);
                        break;
                    case self::IAP_ORIGINAL_TRANSACTION_ID:
                        $originalTransactionId = self::decodeString($v, $nodeBudget);
                        break;
                    case self::IAP_ORIGINAL_PURCHASE_DATE:
                        $originalPurchaseDateMs = self::dateOrThrow($v, $nodeBudget);
                        break;
                    case self::IAP_EXPIRES_DATE:
                        $expiresDateMs = self::dateOrThrow($v, $nodeBudget);
                        break;
                    case self::IAP_WEB_ORDER_LINE_ITEM_ID:
                        $webOrderLineItemId = self::decodeInteger($v, $nodeBudget);
                        break;
                    case self::IAP_CANCELLATION_DATE:
                        $cancellationDateMs = self::dateOrThrow($v, $nodeBudget);
                        break;
                    case self::IAP_IS_TRIAL_PERIOD:
                        $isTrialPeriod = self::decodeInteger($v, $nodeBudget) !== 0;
                        break;
                    case self::IAP_IS_IN_INTRO_OFFER_PERIOD:
                        $isInIntroOfferPeriod = self::decodeInteger($v, $nodeBudget) !== 0;
                        break;
                    default:
                        $unknown[$type][] = $v;
                        break;
                }
            } catch (PayloadFormatError) {
                $unknown[$type][] = $v;
            }
        }

        return new InAppPurchase(
            quantity: $quantity,
            productId: $productId,
            transactionId: $transactionId,
            purchaseDateMs: $purchaseDateMs,
            originalTransactionId: $originalTransactionId,
            originalPurchaseDateMs: $originalPurchaseDateMs,
            expiresDateMs: $expiresDateMs,
            webOrderLineItemId: $webOrderLineItemId,
            cancellationDateMs: $cancellationDateMs,
            isTrialPeriod: $isTrialPeriod,
            isInIntroOfferPeriod: $isInIntroOfferPeriod,
            unknownAttributes: $unknown,
        );
    }

    /**
     * @return list<array{int, string}> type => raw value bytes, in receipt order
     *
     * @throws PayloadFormatError
     *
     * A structural failure here is always reported as a value that does not
     * parse, never as {@see VerificationException} directly: called on the
     * top-level payload, that failure propagates uncaught out of
     * {@see parse()} and becomes {@see Reason::UnreadablePayload} at the
     * caller (the signature has already verified by then); called on one
     * in-app purchase's own attribute set (attribute 17's value), the SAME
     * exception type is what lets {@see parse()}'s per-attribute `catch`
     * keep it raw in `unknownAttributes` instead — that attribute is a
     * known attribute whose value does not parse, like any other (owner,
     * 2026-09-27).
     */
    private static function parseAttributeSet(string $der, string $what, int $nodeBudget): array
    {
        try {
            $node = Der::parse($der, $nodeBudget);
            if (Der::isOctetString($node)) {
                // Xcode receipts double-wrap the payload in an extra OCTET STRING.
                $node = Der::parse(Der::octets($node), $nodeBudget);
            }
        } catch (ParseException $e) {
            throw new PayloadFormatError("{$what} is not valid ASN.1", $e);
        }
        if ($node->tag !== Der::TAG_SET) {
            throw new PayloadFormatError("{$what} is not an ASN.1 SET");
        }
        $attributes = [];
        foreach ($node->children() as $child) {
            $fields = $child->children();
            if ($child->tag !== Der::TAG_SEQUENCE || count($fields) < 3
                || $fields[0]->tag !== Der::TAG_INTEGER || !Der::isOctetString($fields[2])) {
                throw new PayloadFormatError('malformed receipt attribute');
            }
            $attributes[] = [self::attributeType($fields[0]), Der::octets($fields[2])];
        }

        return $attributes;
    }

    /** @throws PayloadFormatError */
    private static function attributeType(Asn1Node $node): int
    {
        $type = self::derSignedInt($node->contents);
        if ($type < 0 || $type > self::MAX_ATTRIBUTE_TYPE) {
            throw new PayloadFormatError('receipt attribute type exceeds the 32-bit signed range');
        }

        return $type;
    }

    /**
     * The content octets of a DER INTEGER, as the SIGNED two's-complement
     * value they encode: negative values are reported, not refused. DER
     * forbids padding: no redundant leading `0x00` (next octet's high bit
     * already clear) and no redundant leading `0xFF` (next octet's high bit
     * already set). At most 8 bytes: PHP's own `int` is signed 64-bit, so
     * nothing narrower than that range is ever refused here.
     *
     * @throws PayloadFormatError
     */
    private static function derSignedInt(string $contents): int
    {
        $n = strlen($contents);
        if ($n === 0) {
            throw new PayloadFormatError('attribute integer is empty');
        }
        if ($n > 8) {
            throw new PayloadFormatError('attribute integer out of range');
        }
        if ($n >= 2 && (
            (ord($contents[0]) === 0x00 && ord($contents[1]) < 0x80)
            || (ord($contents[0]) === 0xFF && ord($contents[1]) >= 0x80)
        )) {
            throw new PayloadFormatError('attribute integer is not minimally encoded');
        }
        $value = ord($contents[0]) >= 0x80 ? -1 : 0;
        for ($i = 0; $i < $n; ++$i) {
            $value = ($value << 8) | ord($contents[$i]);
        }

        return $value;
    }

    /** @throws PayloadFormatError */
    private static function decodeNested(string $der, int $nodeBudget): Asn1Node
    {
        try {
            return Der::parse($der, $nodeBudget);
        } catch (ParseException $e) {
            throw new PayloadFormatError('attribute value is not valid ASN.1', previous: $e);
        }
    }

    /** @throws PayloadFormatError */
    private static function decodeString(string $der, int $nodeBudget): string
    {
        $node = self::decodeNested($der, $nodeBudget);
        if ($node->tag !== Der::TAG_UTF8_STRING && $node->tag !== Der::TAG_IA5_STRING) {
            throw new PayloadFormatError('attribute value is not an ASN.1 string');
        }
        if ($node->tag === Der::TAG_IA5_STRING) {
            // IA5 is seven-bit: a byte at or above 0x80 is not an IA5
            // character, and is not read as Latin-1 either (owner, 2026-09-27).
            $length = strlen($node->contents);
            for ($i = 0; $i < $length; ++$i) {
                if (ord($node->contents[$i]) >= 0x80) {
                    throw new PayloadFormatError('IA5String attribute value is not seven-bit');
                }
            }

            return $node->contents;
        }
        if (preg_match('//u', $node->contents) !== 1) {
            throw new PayloadFormatError('attribute string is not valid UTF-8');
        }

        return $node->contents;
    }

    /** @throws PayloadFormatError */
    private static function decodeInteger(string $der, int $nodeBudget): int
    {
        $node = self::decodeNested($der, $nodeBudget);
        if ($node->tag !== Der::TAG_INTEGER) {
            throw new PayloadFormatError('attribute value is not an ASN.1 integer');
        }

        return self::derSignedInt($node->contents);
    }

    /**
     * A date in an IA5String or UTF8String, as epoch milliseconds, `null`
     * when empty (Apple writes an unset date that way), or throws when the
     * string is non-empty and does not match the exact grammar.
     *
     * @throws PayloadFormatError
     */
    private static function dateOrThrow(string $der, int $nodeBudget): ?int
    {
        $text = self::decodeString($der, $nodeBudget);
        if ($text === '') {
            return null;
        }
        $millis = self::parseReceiptDate($text);
        if ($millis === null) {
            throw new PayloadFormatError('attribute value is not a YYYY-MM-DDTHH:MM:SSZ date');
        }

        return $millis;
    }

    private static function dateOrNull(string $der, int $nodeBudget): ?int
    {
        try {
            return self::dateOrThrow($der, $nodeBudget);
        } catch (PayloadFormatError) {
            return null;
        }
    }

    /**
     * Exactly `YYYY-MM-DDTHH:MM:SSZ`: a four-digit year 0000-9999, uppercase
     * `T` and `Z`, a real calendar date (leap years included), hours 00-23,
     * minutes and seconds 00-59, no fraction and no offset (owner,
     * 2026-09-27). `null` when `$text` is not in that exact form.
     */
    private static function parseReceiptDate(string $text): ?int
    {
        if (preg_match(self::RFC_3339, $text, $m) !== 1) {
            return null;
        }
        $year = (int) $m[1];
        $month = (int) $m[2];
        $day = (int) $m[3];
        $hour = (int) $m[4];
        $minute = (int) $m[5];
        $second = (int) $m[6];
        if ($month < 1 || $month > 12 || $hour > 23 || $minute > 59 || $second > 59) {
            return null;
        }
        // Not checkdate(): it refuses year 0, which the grammar allows
        // (a four-digit year 0000 to 9999, owner 2026-09-27).
        $daysInMonth = self::DAYS_IN_MONTH[$month - 1] + ($month === 2 && self::isLeap($year) ? 1 : 0);
        if ($day < 1 || $day > $daysInMonth) {
            return null;
        }
        $days = self::epochDay($year, $month, $day);

        return ((($days * 24) + $hour) * 60 + $minute) * 60000 + $second * 1000;
    }

    private const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    private static function isLeap(int $year): bool
    {
        return $year % 4 === 0 && ($year % 100 !== 0 || $year % 400 === 0);
    }

    /** Days since 1970-01-01, proleptic Gregorian. */
    private static function epochDay(int $year, int $month, int $day): int
    {
        $days = 0;
        if ($year >= 1970) {
            for ($y = 1970; $y < $year; ++$y) {
                $days += self::isLeap($y) ? 366 : 365;
            }
        } else {
            for ($y = $year; $y < 1970; ++$y) {
                $days -= self::isLeap($y) ? 366 : 365;
            }
        }
        for ($m = 1; $m < $month; ++$m) {
            $days += self::DAYS_IN_MONTH[$m - 1];
            if ($m === 2 && self::isLeap($year)) {
                ++$days;
            }
        }

        return $days + ($day - 1);
    }
}
