<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * Path validation against the caller's pinned anchors and nothing else.
 *
 * There is no code path from here to the operating system's trust store, to
 * a distribution CA bundle, or to the network: no `openssl_cms_verify()`, no
 * `openssl_pkcs7_verify()`, no `openssl_x509_checkpurpose()` — all three
 * consult a CA file or path and would make the process's `openssl.cafile`
 * setting part of this library's trust decisions (PLAN.md §2.3, S1/S2).
 * Revocation is disabled by design: no OCSP, no CRL, no AIA (PLAN.md D12).
 *
 * Every entry point takes the validity instant as a required
 * `int $atEpochMillis` parameter with no default, so "forgot to pass the
 * signing time" cannot silently mean "now".
 *
 * @internal
 */
final class ChainValidator
{
    /**
     * Receipt chains embed their intermediates, so the walk is bounded. Six
     * is well past any Apple chain and stops a crafted mesh from costing
     * unbounded RSA checks.
     */
    private const MAX_PATH_LENGTH = 6;

    /**
     * The fixed JWS path: leaf → intermediate → one pinned anchor.
     *
     * Anchors are trusted by fiat — their own expiry is deliberately not
     * checked, which is standard PKIX trust-anchor semantics and is what lets
     * a historical payload verify under a since-expired chain.
     *
     * @param list<Certificate> $anchors
     *
     * @throws VerificationException
     */
    public static function validatePair(
        Certificate $leaf,
        Certificate $intermediate,
        array $anchors,
        int $atEpochMillis,
    ): void {
        if (!$leaf->isValidAt($atEpochMillis) || !$intermediate->isValidAt($atEpochMillis)) {
            throw new VerificationException(Reason::InvalidChain, 'certificate not valid at signing time');
        }
        if (!$intermediate->isCa) {
            throw new VerificationException(Reason::InvalidChain, 'intermediate is not a CA');
        }
        if (!$leaf->isIssuedBy($intermediate)) {
            throw new VerificationException(Reason::InvalidChain, 'leaf not issued by intermediate');
        }
        foreach ($anchors as $anchor) {
            if ($intermediate->isIssuedBy($anchor)) {
                return;
            }
        }
        throw new VerificationException(Reason::InvalidChain, 'intermediate not issued by a pinned root');
    }

    /**
     * Builds and validates a path from `$target` through `$candidates` to one
     * of the pinned `$anchors` — the shape legacy receipts use, where the
     * intermediates travel inside the CMS blob.
     *
     * @param list<Certificate> $candidates
     * @param list<Certificate> $anchors
     *
     * @throws VerificationException
     */
    public static function buildAndValidatePath(
        Certificate $target,
        array $candidates,
        array $anchors,
        int $atEpochMillis,
    ): void {
        $current = $target;
        for ($depth = 0; $depth < self::MAX_PATH_LENGTH; ++$depth) {
            if (!$current->isValidAt($atEpochMillis)) {
                throw new VerificationException(Reason::InvalidChain, 'certificate not valid at signing time');
            }
            if ($depth > 0 && !$current->isCa) {
                throw new VerificationException(Reason::InvalidChain, 'intermediate is not a CA');
            }
            foreach ($anchors as $anchor) {
                if ($current->isIssuedBy($anchor)) {
                    return;
                }
            }
            $issuer = null;
            foreach ($candidates as $candidate) {
                if ($candidate !== $current && $current->isIssuedBy($candidate)) {
                    $issuer = $candidate;
                    break;
                }
            }
            if ($issuer === null) {
                throw new VerificationException(Reason::InvalidChain, 'chain does not reach a pinned root');
            }
            $current = $issuer;
        }
        throw new VerificationException(Reason::InvalidChain, 'chain exceeds maximum length');
    }

    /**
     * Turns caller-supplied trust anchors (DER bytes, or PEM text) into
     * parsed certificates. An empty list is a configuration error, not a
     * verification verdict.
     *
     * This is where anchors enter the library, so the element type is
     * declared as it actually arrives: PHP does not enforce array element
     * types, and a caller outside static analysis can hand this a list of
     * anything. The `is_string()` below is that guard, not a formality — it
     * is what turns a wrong element into a named InvalidArgumentException
     * instead of a TypeError from somewhere further in.
     *
     * @param array<mixed> $trustedRoots DER bytes or PEM text of each anchor
     *
     * @return list<Certificate>
     *
     * @throws \InvalidArgumentException
     */
    public static function normalizeRoots(array $trustedRoots): array
    {
        if ($trustedRoots === []) {
            throw new \InvalidArgumentException('trustedRoots must be a non-empty list of DER or PEM certificates');
        }
        $roots = [];
        foreach ($trustedRoots as $index => $root) {
            if (!is_string($root) || $root === '') {
                throw new \InvalidArgumentException(
                    "trustedRoots[{$index}] must be a non-empty DER or PEM certificate string",
                );
            }
            try {
                $roots[] = Certificate::parse(self::pemToDer($root));
            } catch (ParseException $e) {
                throw new \InvalidArgumentException("trustedRoots[{$index}] is not a parseable certificate", 0, $e);
            }
        }

        return $roots;
    }

    /** Accepts DER bytes as they are; unwraps a PEM block when it sees one. */
    private static function pemToDer(string $input): string
    {
        if (!str_contains($input, '-----BEGIN')) {
            return $input;
        }
        if (preg_match('/-----BEGIN [^-]+-----(.*?)-----END [^-]+-----/s', $input, $m) !== 1) {
            throw new ParseException('malformed PEM block');
        }
        $der = base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
        if ($der === false || $der === '') {
            throw new ParseException('malformed PEM body');
        }

        return $der;
    }
}
