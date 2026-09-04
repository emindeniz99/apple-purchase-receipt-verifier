<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * Minimal DER/BER reader — just enough ASN.1 to walk X.509 certificates,
 * CMS/PKCS#7 SignedData and Apple receipt payloads. Hand-rolled on purpose
 * (PLAN.md §1 + D8): dependency-light and auditable, and a port of the same
 * reader the Node implementation uses, so the two cannot disagree about what
 * a receipt says.
 *
 * Definite and indefinite (BER 0x80) lengths are both supported because
 * genuine Apple and Xcode receipts use both.
 *
 * Everything this class reads is attacker-supplied, so it is bounded in four
 * independent ways: nesting depth, node count, retained bytes, and the length
 * encodings it will honour. Those budgets are PHP-specific requirements rather
 * than ports of Node constants: PHP has no zero-copy slice, so every value is
 * a fresh string and every node a real object. Measured on PHP 8.4, a 1 MB
 * input of minimal two-byte nodes costs about 72 MB of parser state — a 76×
 * amplification, against a `php.ini-production` default `memory_limit` of
 * 128M. The Node port has no such failure mode because its subarrays are
 * views over one buffer.
 *
 * ## Why depth and node count together are still not enough
 *
 * Those two bound different axes, and the cost is their PRODUCT: a value
 * nested N levels deep is copied N times on the way down, so retained state is
 * roughly `2 × depth × input`. Deep-but-large nesting is cheap on every axis
 * they bound — 600 sibling chains of 31 SEQUENCEs around 3 KB each is 19,201
 * nodes at depth 31 in 1.9 MB of input, inside the node budget, the depth
 * ceiling and the receipt byte cap alike — and cost 92 MB of parser state,
 * which is a `memory_limit` exhaustion on a default deployment. That is a
 * fatal error and NOT a `Throwable`, so no `catch` in this library can turn it
 * into a verdict: the worker dies with no answer at all.
 * {@see DEFAULT_BYTE_BUDGET} is the bound on the product, and it is the one
 * that has to hold.
 *
 * @internal
 */
final class Der
{
    /** Nesting depth ceiling. Also what keeps recursion off PHP 8.1's unguarded stack. */
    public const MAX_DEPTH = 32;

    /**
     * Default ceiling on the number of nodes one parse may produce.
     *
     * The largest genuine fixture — the 79 KB legacy receipt with 187 in-app
     * purchases — decodes to well under 3,000 nodes in total, so this leaves
     * an order of magnitude of headroom over any real receipt.
     */
    public const DEFAULT_NODE_BUDGET = 20000;

    /**
     * Default ceiling on the bytes one parse may RETAIN — the sum, over every
     * node, of its `raw` plus its `contents`, which is what the tree actually
     * holds once `substr()` has copied both.
     *
     * The largest genuine fixture — the 79 KB legacy receipt with 187 in-app
     * purchases — retains 967 KB, a ratio of 12× that comes from real receipts
     * being shallow. The attack ratio is `2 × MAX_DEPTH`, i.e. 64×. So 32 MiB
     * is ~34× the largest real receipt while still covering a legitimate
     * receipt at the full {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES}
     * at realistic ASN.1 shapes, and it caps hostile input at roughly a third
     * of a default 128M `memory_limit` instead of blowing straight through it.
     */
    public const DEFAULT_BYTE_BUDGET = 33554432;

    public const TAG_BOOLEAN = 0x01;
    public const TAG_INTEGER = 0x02;
    public const TAG_BIT_STRING = 0x03;
    public const TAG_OCTET_STRING = 0x04;
    public const TAG_OID = 0x06;
    public const TAG_UTF8_STRING = 0x0c;
    public const TAG_IA5_STRING = 0x16;
    public const TAG_UTC_TIME = 0x17;
    public const TAG_GENERALIZED_TIME = 0x18;
    public const TAG_OCTET_STRING_CONSTRUCTED = 0x24;
    public const TAG_SEQUENCE = 0x30;
    public const TAG_SET = 0x31;
    public const TAG_CONTEXT_0 = 0xa0;
    public const TAG_CONTEXT_1 = 0xa1;
    public const TAG_CONTEXT_2 = 0xa2;
    public const TAG_CONTEXT_3 = 0xa3;

    /**
     * Parses exactly one top-level value. Trailing bytes after it are an
     * error, not something to ignore: a CMS blob with garbage appended is a
     * different blob, and accepting it would let two ports disagree.
     *
     * @throws ParseException
     */
    public static function parse(
        string $buf,
        int $nodeBudget = self::DEFAULT_NODE_BUDGET,
        int $byteBudget = self::DEFAULT_BYTE_BUDGET,
    ): Asn1Node {
        $remaining = $nodeBudget;
        $bytes = $byteBudget;
        [$node, $end] = self::readNode($buf, 0, 0, $remaining, $bytes);
        if ($end !== strlen($buf)) {
            throw new ParseException('trailing bytes after ASN.1 value (' . (strlen($buf) - $end) . ')');
        }

        return $node;
    }

    /**
     * @param int $budget     node budget, consumed by reference across the whole tree
     * @param int $byteBudget retained-byte budget, likewise
     *
     * @return array{Asn1Node, int}
     *
     * @throws ParseException
     */
    private static function readNode(string $buf, int $off, int $depth, int &$budget, int &$byteBudget): array
    {
        if ($depth > self::MAX_DEPTH) {
            throw new ParseException('maximum ASN.1 nesting depth exceeded');
        }
        if ($budget <= 0) {
            throw new ParseException('ASN.1 node budget exceeded');
        }
        --$budget;

        $len = strlen($buf);
        if ($off + 2 > $len) {
            throw new ParseException('truncated ASN.1 value');
        }
        $tag = ord($buf[$off]);
        if (($tag & 0x1f) === 0x1f) {
            throw new ParseException('multi-byte ASN.1 tags are not supported');
        }
        $constructed = ($tag & 0x20) !== 0;
        $pos = $off + 1;
        $lenByte = ord($buf[$pos]);
        ++$pos;

        $length = null;
        if ($lenByte < 0x80) {
            $length = $lenByte;
        } elseif ($lenByte === 0x80) {
            if (!$constructed) {
                throw new ParseException('indefinite length on a primitive value');
            }
        } else {
            $numBytes = $lenByte & 0x7f;
            if ($numBytes > 4 || $pos + $numBytes > $len) {
                throw new ParseException('unsupported ASN.1 length');
            }
            $length = 0;
            for ($i = 0; $i < $numBytes; ++$i) {
                $length = $length * 256 + ord($buf[$pos + $i]);
            }
            $pos += $numBytes;
        }

        if ($length !== null) {
            $end = $pos + $length;
            if ($end > $len) {
                throw new ParseException('ASN.1 length exceeds input');
            }
            $contents = substr($buf, $pos, $length);
            $raw = substr($buf, $off, $end - $off);
            // Charged BEFORE descending, so a chain of nested wrappers around a
            // large value stops on the way down rather than after every level
            // has already copied it.
            self::charge($byteBudget, strlen($contents) + strlen($raw));
            $children = $constructed
                ? self::readChildren($contents, $depth + 1, $budget, $byteBudget)
                : null;

            return [new Asn1Node($tag, $constructed, $raw, $contents, $children), $end];
        }

        // Indefinite length: children until an end-of-contents (00 00) marker.
        $children = [];
        for (;;) {
            if ($pos + 2 > $len) {
                throw new ParseException('unterminated indefinite-length value');
            }
            if ($buf[$pos] === "\x00" && $buf[$pos + 1] === "\x00") {
                $pos += 2;
                break;
            }
            [$child, $next] = self::readNode($buf, $pos, $depth + 1, $budget, $byteBudget);
            $children[] = $child;
            $pos = $next;
        }
        $joined = '';
        foreach ($children as $child) {
            $joined .= $child->raw;
        }
        $raw = substr($buf, $off, $pos - $off);
        self::charge($byteBudget, strlen($joined) + strlen($raw));

        return [new Asn1Node($tag, true, $raw, $joined, $children), $pos];
    }

    /**
     * @param int $byteBudget consumed by reference
     *
     * @throws ParseException
     */
    private static function charge(int &$byteBudget, int $bytes): void
    {
        $byteBudget -= $bytes;
        if ($byteBudget < 0) {
            throw new ParseException('ASN.1 retained-byte budget exceeded');
        }
    }

    /**
     * @return list<Asn1Node>
     *
     * @throws ParseException
     */
    private static function readChildren(string $contents, int $depth, int &$budget, int &$byteBudget): array
    {
        $children = [];
        $pos = 0;
        $len = strlen($contents);
        while ($pos < $len) {
            [$child, $next] = self::readNode($contents, $pos, $depth, $budget, $byteBudget);
            $children[] = $child;
            $pos = $next;
        }

        return $children;
    }

    public static function isOctetString(Asn1Node $node): bool
    {
        return $node->tag === self::TAG_OCTET_STRING
            || $node->tag === self::TAG_OCTET_STRING_CONSTRUCTED;
    }

    /** Value bytes of an OCTET STRING, joining BER constructed chunks. */
    public static function octets(Asn1Node $node): string
    {
        if (!$node->constructed) {
            return $node->contents;
        }
        $out = '';
        foreach ($node->children() as $child) {
            $out .= self::octets($child);
        }

        return $out;
    }

    /**
     * DER-encodes an OBJECT IDENTIFIER dotted string to its contents bytes.
     * Marker-OID checks compare these bytes, never a name a crypto library
     * decided to give the OID.
     */
    public static function encodeOidContents(string $oid): string
    {
        $parts = array_map(intval(...), explode('.', $oid));
        if (count($parts) < 2) {
            throw new ParseException('not an OID: ' . $oid);
        }
        $out = chr(40 * $parts[0] + $parts[1]);
        for ($i = 2, $n = count($parts); $i < $n; ++$i) {
            $value = $parts[$i];
            $chunk = chr($value & 0x7f);
            $value = intdiv($value, 128);
            while ($value > 0) {
                $chunk = chr(($value & 0x7f) | 0x80) . $chunk;
                $value = intdiv($value, 128);
            }
            $out .= $chunk;
        }

        return $out;
    }

    /** Decodes OBJECT IDENTIFIER contents bytes back to a dotted string. */
    public static function decodeOid(string $contents): string
    {
        if ($contents === '') {
            throw new ParseException('empty OBJECT IDENTIFIER');
        }
        $first = ord($contents[0]);
        $parts = [min(intdiv($first, 40), 2)];
        $parts[] = $first - $parts[0] * 40;
        $value = 0;
        $started = false;
        for ($i = 1, $n = strlen($contents); $i < $n; ++$i) {
            $byte = ord($contents[$i]);
            $value = $value * 128 + ($byte & 0x7f);
            $started = true;
            if (($byte & 0x80) === 0) {
                $parts[] = $value;
                $value = 0;
                $started = false;
            }
        }
        if ($started) {
            throw new ParseException('truncated OBJECT IDENTIFIER');
        }

        return implode('.', $parts);
    }
}
