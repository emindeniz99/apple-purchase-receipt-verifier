<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use DateTimeImmutable;

/**
 * A verified legacy app receipt.
 *
 * Only receipts returned by {@see ReceiptVerifier::verify()} or
 * {@see ReceiptVerifier::verifyReceiptCore()} should be trusted: on any
 * failure nothing is returned at all, so there is no such thing as a
 * partially-verified instance of this class.
 *
 * Byte-valued properties (`bundleIdBytes`, `opaqueValue`, `sha1Hash`, and the
 * values inside `unknownAttributes`) are PHP binary strings, which are
 * immutable values — a caller cannot mutate an already-verified receipt, and
 * cannot reach the buffer it was parsed from.
 */
final class AppReceipt
{
    /**
     * Properties whose value is raw bytes rather than text. PHP spells both
     * `string`, so this is how a generic consumer (a serializer, a debug
     * dumper, the conformance adapter) knows to hex-encode rather than print.
     */
    public const BINARY_PROPERTIES = ['bundleIdBytes', 'opaqueValue', 'sha1Hash', 'unknownAttributes'];

    /**
     * @param string|null $receiptType attribute 0, e.g. "Production" /
     *        "ProductionSandbox" (undocumented but stable; drives the
     *        endpoint's 21007/21008 routing)
     * @param string|null $bundleIdBytes raw DER bytes of attribute 2 — the
     *        input to the device-hash check, which needs the encoded form and
     *        not the decoded string
     * @param DateTimeImmutable|null $originalPurchaseDate attribute 18
     *        (undocumented; community-established)
     * @param list<InAppPurchase> $inAppPurchases
     * @param array<int, list<string>> $unknownAttributes raw values of
     *        attribute types this library does not model, keyed by type —
     *        forward compatibility for fields Apple may add (PLAN.md D10).
     *        Verified, but undecoded.
     */
    public function __construct(
        public readonly ?string $receiptType,
        public readonly ?string $bundleId,
        public readonly ?string $bundleIdBytes,
        public readonly ?string $appVersion,
        public readonly ?string $opaqueValue,
        public readonly ?string $sha1Hash,
        public readonly ?DateTimeImmutable $creationDate,
        public readonly ?DateTimeImmutable $originalPurchaseDate,
        public readonly ?string $originalAppVersion,
        public readonly ?DateTimeImmutable $expirationDate,
        public readonly array $inAppPurchases,
        public readonly array $unknownAttributes,
    ) {
    }
}
