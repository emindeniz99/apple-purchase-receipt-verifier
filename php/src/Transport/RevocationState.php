<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

/**
 * What the module's `init` answered about revocation for a `Config`
 * (docs/design/revocation.md §7), as {@see Transport::open()} read it from
 * `aprv info` or `GET /v1/info`. The package computes neither value.
 */
final readonly class RevocationState
{
    /**
     * @param list<string> $revocationUrls the lists the configuration expects, in the module's order
     * @param int|null $revocationValidUntilMs the earliest `nextUpdate` among the lists held,
     *        epoch milliseconds; null when an expected issuer has none
     */
    public function __construct(
        public array $revocationUrls,
        public ?int $revocationValidUntilMs,
    ) {
    }
}
