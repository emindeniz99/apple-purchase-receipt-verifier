<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use RuntimeException;

/**
 * What `aprv info` and `GET /v1/info` say about the binary, as far as
 * `Verifier::create()` reads it.
 *
 * @internal
 */
final class Info
{
    /** The ABI of the WIT this package's wire contract is written against. */
    public const ABI = 'aprv:verifier@0.1.0';

    private function __construct()
    {
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws RuntimeException when the text is not a JSON object naming the expected ABI
     */
    public static function decode(string $json, string $where): array
    {
        $info = json_decode($json, true);
        if (!is_array($info)) {
            throw new RuntimeException("{$where} did not answer a JSON object");
        }
        $abi = $info['abi'] ?? null;
        if ($abi !== self::ABI) {
            $found = is_string($abi) ? Text::printable($abi, 60) : 'none';
            throw new RuntimeException(
                "{$where} speaks ABI {$found}, this package expects " . self::ABI
                . ': install the aprv binary that belongs to this package version',
            );
        }

        return $info;
    }

    /**
     * The `limits.max_input_bytes` an info document states: the most bytes
     * of one input the module needs, which its `init` answer states (one
     * over its largest cap). A transport sends no more of an input than
     * this, so an input over the cap still reaches the module over it and
     * the module answers its own size refusal (TOO_LARGE, 21002 from the
     * endpoint); the package keeps no copy of the number.
     *
     * @param array<array-key, mixed> $info
     *
     * @throws RuntimeException when the binary states none: it is not the one this package belongs to
     */
    public static function maxInputBytes(array $info, string $where): int
    {
        $limits = $info['limits'] ?? null;
        $max = is_array($limits) ? ($limits['max_input_bytes'] ?? null) : null;
        if (!is_int($max) || $max < 1) {
            throw new RuntimeException(
                "{$where} states no limits.max_input_bytes"
                . ': install the aprv binary that belongs to this package version',
            );
        }

        return $max;
    }
}
