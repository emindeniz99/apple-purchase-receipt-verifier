<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\RevocationState;
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
    public const ABI = 'aprv:verifier@0.2.0';

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

    /**
     * The `revocation_urls` and `revocation_valid_until_ms` an info
     * document states: what the module's `init` answered for the
     * configuration (docs/design/revocation.md §7), passed on as they are.
     *
     * @param array<array-key, mixed> $info
     *
     * @throws RuntimeException when the binary states neither: it is not the one this package belongs to
     */
    public static function revocationState(array $info, string $where): RevocationState
    {
        $urls = $info['revocation_urls'] ?? null;
        $until = $info['revocation_valid_until_ms'] ?? null;
        if (
            !is_array($urls) || !array_is_list($urls) || array_filter($urls, 'is_string') !== $urls
            || !array_key_exists('revocation_valid_until_ms', $info) || !($until === null || is_int($until))
        ) {
            throw new RuntimeException(
                "{$where} states no revocation_urls and revocation_valid_until_ms"
                . ': install the aprv binary that belongs to this package version',
            );
        }

        /** @var list<string> $urls */
        return new RevocationState($urls, $until);
    }
}
