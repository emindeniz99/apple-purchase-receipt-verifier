<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * One decoded ASN.1 node.
 *
 * `raw` is the complete TLV, `contents` the value octets. `children` is a list
 * of nodes for a constructed value and null for a primitive one. Byte fields
 * are PHP binary strings, which are immutable values — a caller can never
 * reach back into the buffer the node was decoded from.
 *
 * @internal
 */
final class Asn1Node
{
    /**
     * @param int              $tag         full identifier octet (0x30 SEQUENCE, 0xa0 [0] constructed, …)
     * @param list<Asn1Node>|null $children null when the value is primitive
     */
    public function __construct(
        public readonly int $tag,
        public readonly bool $constructed,
        public readonly string $raw,
        public readonly string $contents,
        public readonly ?array $children,
    ) {
    }

    /** @return list<Asn1Node> */
    public function children(): array
    {
        return $this->children ?? [];
    }

    public function child(int $index): ?Asn1Node
    {
        return ($this->children ?? [])[$index] ?? null;
    }

    public function childCount(): int
    {
        return $this->children === null ? 0 : count($this->children);
    }
}
