<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Psr\Clock\ClockInterface;

/**
 * What a {@see Verifier} trusts and what time it thinks it is
 * (docs/design/0.7-api.md, "Setup"). Immutable.
 *
 * **Roots** are the caller's trust anchors as DER or PEM strings, which
 * `aprv` tells apart, or `null` for the module's built-in ones: no roots
 * given means the three pinned Apple roots that `aprv` carries. This
 * package holds no copy of them, so `new Config()` names none. An empty
 * list is not "no roots": it is a mistake, and {@see Verifier::create()}
 * refuses it. "Apple's roots plus mine" is written by passing all four,
 * Apple's three read from its PKI page or the repository's `certs/`. A
 * value that is not a certificate is refused by {@see Verifier::create()},
 * which is where `aprv` first reads the roots.
 *
 * **The clock** answers "what time is it now?" and nothing else. The
 * library reads it once per call and sends the value to `aprv` as `now-ms`;
 * the module uses it for the chain check when the receipt or JWS carries no
 * signing date, and for `request_date` in the endpoint response. A
 * caller-supplied clock must be safe to call from several requests.
 */
final readonly class Config
{
    /** @var list<string>|null DER or PEM bytes of the trust anchors; null means the module's built-in Apple roots */
    public ?array $roots;

    public ClockInterface $clock;

    /**
     * Pass only what differs from the defaults, by name:
     * `new Config(roots: $myRoots, clock: $myClock)`.
     *
     * @param iterable<string>|null $roots DER or PEM bytes of the trust anchors;
     *        null, the default, means the module's built-in Apple roots
     * @param ClockInterface $clock the system clock by default
     */
    public function __construct(
        ?iterable $roots = null,
        ClockInterface $clock = new SystemClock(),
    ) {
        if ($roots !== null) {
            $roots = is_array($roots) ? array_values($roots) : iterator_to_array($roots, false);
        }
        $this->roots = $roots;
        $this->clock = $clock;
    }
}
