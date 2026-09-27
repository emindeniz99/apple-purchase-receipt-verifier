<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;

/**
 * Certificate chain validation against pinned trust anchors, walked
 * top-down (#161): a
 * certificate's signature is checked only with a key a pinned root has
 * already vouched for, and a certificate's own key is never decoded until
 * ITS signature has verified that way. This is what keeps a receipt or JWS
 * padded with a stranger certificate — including one carrying a key too
 * large to decode cheaply — from costing more than the handful of signature
 * checks a genuine chain needs: an unvouched candidate is never tried as an
 * issuer, so its key is never read.
 *
 * There is no code path from here to the operating system's trust store, to
 * a distribution CA bundle, or to the network. Revocation is out of scope
 * (deferred, docs/design/0.7-api.md "Room for revocation checks later).
 *
 * Validity windows are NOT checked here: the design's check order puts the
 * chain (structural + top-down trust) before validity, so a caller walks
 * the returned path and checks each certificate's own window itself
 * (`Certificate::isValidAt()`).
 *
 * @internal
 */
final class ChainValidator
{
    /**
     * Receipt chains embed their intermediates, so the walk is bounded. Six
     * is well past any Apple chain, matching the shared bound (anchor
     * excluded).
     */
    private const MAX_PATH_LENGTH = 6;

    /**
     * Extensions this library actually reads. RFC 5280 4.2: a certificate
     * carrying a critical extension outside this set is unusable to a
     * conforming implementation. The two Apple marker OIDs are included
     * even though genuine Apple certificates never mark them critical,
     * because the library does read and act on them.
     */
    private const RECOGNIZED_CRITICAL_EXTENSIONS = [
        '2.5.29.19', // basicConstraints
        '2.5.29.15', // keyUsage
        AppleMarkers::LEAF_OID,
        AppleMarkers::INTERMEDIATE_OID,
    ];

    /**
     * The fixed JWS path: leaf -> intermediate -> a pinned anchor, walked
     * top-down: the intermediate's signature is checked against the anchors
     * first, and only once that has verified is the intermediate's key used
     * to check the leaf's signature.
     *
     * Anchors are trusted by fiat: their own expiry is deliberately not
     * checked, which is standard PKIX trust-anchor semantics and is what
     * lets a historical payload verify under a since-expired chain.
     *
     * @param list<Certificate> $anchors
     *
     * @throws VerificationException {@see Reason::UntrustedChain} or {@see Reason::InvalidCertificate}
     */
    public static function authenticatePairTopDown(
        Certificate $leaf,
        Certificate $intermediate,
        array $anchors,
    ): void {
        self::requireChain(
            self::issuedByAny($intermediate, $anchors),
            'intermediate certificate is not signed by a pinned Apple root',
        );
        self::requireChain(self::isUsableIssuer($intermediate), 'intermediate is not a valid issuing CA');
        self::requireChain(
            self::issuedBy($leaf, $intermediate, strict: true),
            'leaf certificate is not signed by the intermediate',
        );
    }

    /**
     * The path from `$target` (not itself required to be in `$candidates`)
     * up to, but excluding, a pinned anchor: `[target, intermediate, ...]`.
     *
     * Walked top-down in two passes: first every embedded certificate a
     * pinned root vouches for AND may itself issue further certificates
     * (basicConstraints/keyUsage, no unrecognized critical extension) is
     * found — trying only certificates already vouched for as an issuer, so
     * a stranger's key, oversized or not, is never decoded to test whether
     * it issued anything. `$target`'s own path is then read off that
     * result.
     *
     * @param list<Certificate> $candidates
     * @param list<Certificate> $anchors
     *
     * @return list<Certificate>
     *
     * @throws VerificationException {@see Reason::UntrustedChain} when no
     *         such path exists or it is longer than {@see MAX_PATH_LENGTH},
     *         or {@see Reason::InvalidCertificate} when the certificate
     *         actually chosen as `$target`'s issuer has a key this build
     *         cannot decode
     */
    public static function buildPathTopDown(Certificate $target, array $candidates, array $anchors): array
    {
        foreach ($anchors as $anchor) {
            if (self::issuedBy($target, $anchor)) {
                return [$target];
            }
        }

        /** @var array<int, int|null> $acceptedBy candidate index => parent candidate index, or null for an anchor parent */
        $acceptedBy = [];
        /** @var array<int, Certificate> $pending */
        $pending = $candidates;
        /** @var list<array{int|null, Certificate}> $currentIssuers */
        $currentIssuers = array_map(static fn (Certificate $a): array => [null, $a], $anchors);

        for ($round = 0; $round < self::MAX_PATH_LENGTH; ++$round) {
            if ($pending === []) {
                break;
            }
            /** @var list<array{int, Certificate}> $acceptedThisRound */
            $acceptedThisRound = [];
            foreach ($pending as $idx => $candidate) {
                if (!self::isUsableIssuer($candidate)) {
                    continue;
                }
                foreach ($currentIssuers as [$parentIdx, $issuer]) {
                    if (self::issuedBy($candidate, $issuer)) {
                        $acceptedBy[$idx] = $parentIdx;
                        $acceptedThisRound[] = [$idx, $candidate];
                        break;
                    }
                }
            }
            if ($acceptedThisRound === []) {
                break;
            }
            foreach ($acceptedThisRound as [$idx, ]) {
                unset($pending[$idx]);
            }
            $currentIssuers = $acceptedThisRound;
        }

        foreach ($candidates as $idx => $cert) {
            if (!array_key_exists($idx, $acceptedBy)) {
                continue;
            }
            if (!self::issuedBy($target, $cert, strict: true)) {
                continue;
            }
            $path = [$target];
            $current = $idx;
            while ($current !== null) {
                $path[] = $candidates[$current];
                $current = $acceptedBy[$current];
            }
            self::requireChain(count($path) <= self::MAX_PATH_LENGTH, 'chain exceeds maximum length');

            return $path;
        }

        throw new VerificationException(Reason::UntrustedChain, 'chain does not reach a pinned root');
    }

    /** @param list<Certificate> $anchors */
    private static function issuedByAny(Certificate $cert, array $anchors): bool
    {
        foreach ($anchors as $anchor) {
            if (self::issuedBy($cert, $anchor)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether `$issuer`'s key verifies `$cert`'s signature AND `$cert`'s
     * issuer name byte-equals `$issuer`'s subject name. Only `$issuer`'s key
     * is ever decoded or used here (never `$cert`'s), which is what makes
     * the walks above top-down: a certificate is tried as an issuer only
     * once it is itself vouched for.
     *
     * `$strict`: when `$issuer` is the certificate this call is actually
     * settling on (not merely one candidate among several being explored),
     * a key OpenSSL cannot read at all is a defect of `$issuer` itself and
     * is raised as {@see Reason::InvalidCertificate} rather than silently
     * read as "not the issuer".
     *
     * @throws VerificationException {@see Reason::InvalidCertificate}, `$strict` only
     */
    private static function issuedBy(Certificate $cert, Certificate $issuer, bool $strict = false): bool
    {
        if (!hash_equals($issuer->subjectDer, $cert->issuerDer)) {
            return false;
        }
        $key = $issuer->publicKey();
        if ($key === null) {
            if ($strict) {
                throw new VerificationException(Reason::InvalidCertificate, 'certificate key does not decode');
            }

            return false;
        }
        $result = openssl_x509_verify($cert->pem(), $key);
        Certificate::drainOpenSslErrors();

        return $result === 1;
    }

    /**
     * Whether `$cert` may issue further certificates: basicConstraints
     * marks it a CA, keyUsage (when present) permits `keyCertSign`, and it
     * carries no unrecognized critical extension (RFC 5280 4.2, Q14: no
     * signature-algorithm allowlist beyond what OpenSSL itself verifies).
     */
    private static function isUsableIssuer(Certificate $cert): bool
    {
        return $cert->isCa && !$cert->hasUnrecognizedCriticalExtension(self::RECOGNIZED_CRITICAL_EXTENSIONS);
    }

    /** @throws VerificationException {@see Reason::UntrustedChain} */
    private static function requireChain(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new VerificationException(Reason::UntrustedChain, $message);
        }
    }

    /**
     * Turns caller-supplied trust anchors (DER bytes, or PEM text) into
     * parsed certificates. An empty list is a configuration error, not a
     * verification verdict.
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
            throw new \InvalidArgumentException('roots must be a non-empty list of DER or PEM certificates');
        }
        $roots = [];
        foreach ($trustedRoots as $index => $root) {
            if (!is_string($root) || $root === '') {
                throw new \InvalidArgumentException(
                    "roots[{$index}] must be a non-empty DER or PEM certificate string",
                );
            }
            try {
                $roots[] = Certificate::parse(self::pemToDer($root));
            } catch (ParseException $e) {
                throw new \InvalidArgumentException("roots[{$index}] is not a parseable certificate", 0, $e);
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
