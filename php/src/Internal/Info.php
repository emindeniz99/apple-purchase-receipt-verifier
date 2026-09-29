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
    public const ABI = 'aprv:verifier@1.0.0';

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
}
