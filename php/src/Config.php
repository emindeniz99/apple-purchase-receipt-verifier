<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Psr\Clock\ClockInterface;
use RuntimeException;

/**
 * What a {@see Verifier} trusts and what time it thinks it is
 * (docs/design/0.7-api.md, "Setup"). Immutable.
 *
 * **Roots** default to the three bundled, pinned Apple roots; tests
 * substitute their own via {@see builder()}. An empty list is accepted
 * here and refused by {@see Verifier::create()} — a verifier with no roots
 * would answer `UNTRUSTED_CHAIN` to everything and nobody would notice
 * until production.
 *
 * **The clock** answers "what time is it now?" and nothing else. The
 * library reads it in two places: the chain check when the receipt or JWS
 * carries no signing date, and `request_date` in the endpoint response. A
 * caller-supplied clock must be safe to call from several threads/requests.
 */
final readonly class Config
{
    /** @param list<string> $roots DER bytes or PEM text of the pinned anchors */
    public function __construct(
        public array $roots,
        public ClockInterface $clock,
    ) {
    }

    /**
     * Apple's pinned roots and the system clock.
     *
     * @throws RuntimeException if the bundled roots are missing or fail
     *         their pinned fingerprints — see {@see AppleRootCerts::pinnedRoots()}
     */
    public static function defaults(): self
    {
        return new self(AppleRootCerts::pinnedRoots(), new SystemClock());
    }

    public static function builder(): ConfigBuilder
    {
        return new ConfigBuilder();
    }
}
