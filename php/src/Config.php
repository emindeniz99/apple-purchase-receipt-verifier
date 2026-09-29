<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Psr\Clock\ClockInterface;

/**
 * What a {@see Verifier} trusts and what time it thinks it is
 * (docs/design/0.7-api.md, "Setup"). Immutable.
 *
 * **Roots** are the caller's trust anchors as DER strings, or `null` for the
 * module's built-in ones: no roots given means the three pinned Apple roots
 * that `aprv` carries. This package holds no copy of them, so
 * {@see defaults()} names none. An empty list is not "no roots": it is a
 * mistake, and {@see Verifier::create()} refuses it. "Apple's roots plus
 * mine" is written by passing all four DER strings, Apple's three read from
 * its PKI page or the repository's `certs/`. A value that is not a
 * certificate is refused by {@see Verifier::create()}, which is where `aprv`
 * first reads the roots.
 *
 * **The clock** answers "what time is it now?" and nothing else. The
 * library reads it once per call and sends the value to `aprv` as `now-ms`;
 * the module uses it for the chain check when the receipt or JWS carries no
 * signing date, and for `request_date` in the endpoint response. A
 * caller-supplied clock must be safe to call from several requests.
 */
final readonly class Config
{
    /** @param list<string>|null $roots DER bytes of the trust anchors; null means the module's built-in Apple roots */
    public function __construct(
        public ?array $roots,
        public ClockInterface $clock,
    ) {
    }

    /** The module's built-in Apple roots and the system clock. */
    public static function defaults(): self
    {
        return new self(null, new SystemClock());
    }

    public static function builder(): ConfigBuilder
    {
        return new ConfigBuilder();
    }
}
