<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Jws;

use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ChainValidator;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\JwsClaims;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Verifies Apple-signed JWS payloads — StoreKit 2 `jwsRepresentation`,
 * `signedTransactionInfo` / `signedRenewalInfo`, App Store Server
 * Notifications V2 — completely offline against pinned Apple roots
 * (PLAN.md §2.1).
 *
 * ```php
 * $verifier = new JwsVerifier(
 *     AppleRootCerts::jwsRoots(),
 *     'com.example.app',
 *     [Environment::Production, Environment::Sandbox],
 * );
 * $transaction = $verifier->verifyTransaction($jws);
 * ```
 *
 * ## What the clock can and cannot move
 *
 * The injected clock drives exactly one check: the max-signed-age
 * (`STALE_PAYLOAD`) rule. Certificate validity is judged at the payload's own
 * `signedDate` / `receiptCreationDate`, and where a payload carries neither,
 * at the SYSTEM clock — never at the injected one. A caller injecting a clock
 * to test staleness, or to work around skew, must not thereby be able to
 * accept an expired chain or expire a live one.
 */
final class JwsVerifier
{
    /**
     * Ceiling on the compact JWS this will look at, checked before the string
     * is split, decoded or parsed.
     *
     * The containment story on this path — the categorical `catch (Throwable)`
     * in {@see verifySignature()} — is worth nothing without a byte cap,
     * because what an attacker can provoke is a `memory_limit` exhaustion, and
     * that is a PHP fatal rather than a `Throwable`: it cannot be caught, and
     * the worker dies with no answer at all. Two ~5 MB inputs did exactly that
     * at the `php.ini-production` default of 128M, and neither is large by
     * HTTP standards: a JSON-bomb payload segment (`json_decode` expands a
     * breadth bomb ~48×, and the payload is decoded at step 3, BEFORE the
     * signature check at step 5, so no valid signature is needed), and an
     * `x5c` entry nested 32 deep around a few MB (see {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der}).
     *
     * Every JWS in the corpus — Apple's own mock notification data included —
     * is under 2.5 KB, so 256 KiB is a hundredfold headroom over anything
     * Apple has ever signed while bounding both amplifications to tens of MB.
     */
    public const MAX_JWS_BYTES = 262144;

    /** @var list<Certificate> */
    private readonly array $anchors;

    /** @var array<string, true> */
    private readonly array $acceptedEnvironments;

    private readonly ClockInterface $clock;

    /**
     * @param list<string> $trustedRoots DER bytes or PEM text of the pinned
     *        anchors. In production: {@see \EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts::jwsRoots()}.
     * @param string $bundleId the bundle id every payload must carry
     * @param list<Environment> $acceptedEnvironments include
     *        {@see Environment::Sandbox} on any endpoint App Review can
     *        reach: App Review runs production builds against sandbox
     *        (PLAN.md D3)
     * @param int|null $appAppleId required to accept a Production AppTransaction
     * @param int|null $maxSignedAgeSeconds reject payloads signed longer ago
     *        than this; null disables the rule (PLAN.md D5). The unit is in
     *        the name on purpose — a bare `300` at a call site says nothing.
     * @param ClockInterface|null $clock source of "now" for the staleness
     *        rule only; null installs {@see SystemClock}
     *
     * @throws InvalidArgumentException on misconfiguration — which is a
     *         programming error, never a verdict about a payload
     */
    public function __construct(
        array $trustedRoots,
        private readonly string $bundleId,
        array $acceptedEnvironments,
        private readonly ?int $appAppleId = null,
        private readonly ?int $maxSignedAgeSeconds = null,
        ?ClockInterface $clock = null,
    ) {
        ReceiptVerifier::requireSixtyFourBit();
        $this->anchors = ChainValidator::normalizeRoots($trustedRoots);
        if ($bundleId === '') {
            throw new InvalidArgumentException('bundleId is required');
        }
        $this->acceptedEnvironments = self::normalizeEnvironments($acceptedEnvironments);
        if ($maxSignedAgeSeconds !== null && $maxSignedAgeSeconds < 1) {
            throw new InvalidArgumentException('maxSignedAgeSeconds must be positive when set');
        }
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * The accepted environments as a set keyed by raw claim value.
     *
     * This is where the caller's list enters the verifier, so the element
     * type is declared as it actually arrives: PHP does not enforce array
     * element types, and a caller outside static analysis can hand this
     * strings. The `instanceof` below is that guard, not a formality — it is
     * what turns a wrong element into a named InvalidArgumentException
     * instead of a fatal property read on a non-object.
     *
     * @param array<mixed> $acceptedEnvironments
     *
     * @return array<string, true>
     *
     * @throws InvalidArgumentException
     */
    private static function normalizeEnvironments(array $acceptedEnvironments): array
    {
        if ($acceptedEnvironments === []) {
            throw new InvalidArgumentException('acceptedEnvironments must be a non-empty list of Environment');
        }
        $accepted = [];
        foreach ($acceptedEnvironments as $environment) {
            if (!$environment instanceof Environment) {
                throw new InvalidArgumentException('acceptedEnvironments must contain only Environment cases');
            }
            $accepted[$environment->value] = true;
        }

        return $accepted;
    }

    /**
     * Verifies a signed transaction and enforces bundle id and environment.
     *
     * @throws VerificationException
     */
    public function verifyTransaction(string $jws): TransactionPayload
    {
        $claims = $this->verifySignature($jws);
        $this->requireBundleId($claims['bundleId'] ?? null);
        $this->requireAcceptedEnvironment($claims['environment'] ?? null);

        return JwsClaims::toTransaction($claims);
    }

    /**
     * Verifies a signed AppTransaction and enforces bundle id, environment
     * (which lives in `receiptType` here) and — in Production — the app Apple
     * id.
     *
     * @throws VerificationException
     */
    public function verifyAppTransaction(string $jws): AppTransactionPayload
    {
        $claims = $this->verifySignature($jws);
        $this->requireBundleId($claims['bundleId'] ?? null);
        $environment = $this->requireAcceptedEnvironment($claims['receiptType'] ?? null);
        $this->requireAppAppleId($environment, $claims['appAppleId'] ?? null);

        return JwsClaims::toAppTransaction($claims);
    }

    /**
     * Verifies the chain and signature only and returns the raw claims — for
     * payload types this library does not model (renewal info, notification
     * envelopes).
     *
     * **No claim is enforced.** The caller checks bundle id, environment and
     * app Apple id in the returned array itself.
     *
     * @return array<string, mixed>
     *
     * @throws VerificationException
     */
    public function verifyRaw(string $jws): array
    {
        return $this->verifySignature($jws);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws VerificationException
     */
    private function verifySignature(string $jws): array
    {
        // Containment is categorical rather than a list of expected types: an
        // attacker-triggered TypeError deep in a parser is indistinguishable
        // from a bug at the call site, and neither may reach the caller as
        // anything but a VerificationException.
        try {
            return $this->verifySignatureInner($jws);
        } catch (VerificationException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new VerificationException(Reason::InvalidJwsFormat, 'malformed JWS', $e);
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws VerificationException
     */
    private function verifySignatureInner(string $jws): array
    {
        // First statement in the method on purpose: everything below allocates
        // proportionally to this string, and the fatal it would otherwise
        // provoke is not catchable (see MAX_JWS_BYTES).
        if (strlen($jws) > self::MAX_JWS_BYTES) {
            throw new VerificationException(
                Reason::InvalidJwsFormat,
                'JWS exceeds the maximum accepted size of ' . self::MAX_JWS_BYTES . ' bytes',
            );
        }
        [$headerB64, $payloadB64, $signatureB64, $x5c] = JwsClaims::split($jws);

        try {
            $leaf = Certificate::parse(Base64::decode($x5c[0]));
            $intermediate = Certificate::parse(Base64::decode($x5c[1]));
            // The third entry is parsed and then dropped: it is never
            // compared to an anchor and never trusted, so swapping in a
            // stranger's root still changes nothing — but an entry that is
            // not a certificate is INVALID_CERTIFICATE at every index
            // (transaction/reject-x5c-root-that-is-not-a-certificate).
            $suppliedRoot = Certificate::parse(Base64::decode($x5c[2]));
        } catch (ParseException $e) {
            throw new VerificationException(Reason::InvalidCertificate, 'x5c entry is not a valid certificate', $e);
        }
        // A SubjectPublicKeyInfo OpenSSL refuses — a namedCurve it does not
        // implement is enough — is a defect of the certificate, not of the
        // path it sits on: there is no key to check an issuance against.
        // Left to the chain it reads as INVALID_CHAIN, while java, swift and
        // go refuse the certificate in their decoders, which is the reading
        // the shared vector pins.
        if ($leaf->publicKey() === null
            || $intermediate->publicKey() === null
            || $suppliedRoot->publicKey() === null) {
            throw new VerificationException(Reason::InvalidCertificate, 'x5c entry has an unreadable public key');
        }

        // Marker OIDs are checked BEFORE the chain on this path (and after it
        // on the receipt path) — the order is observable and normative.
        if (!$leaf->hasExtension(JwsClaims::LEAF_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'leaf certificate lacks Apple marker OID ' . JwsClaims::LEAF_OID,
            );
        }
        if (!$intermediate->hasExtension(JwsClaims::INTERMEDIATE_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'intermediate certificate lacks Apple marker OID ' . JwsClaims::INTERMEDIATE_OID,
            );
        }

        $claims = JwsClaims::parseJsonSegment($payloadB64, 'payload');

        // Chain validity is judged at signing time so payloads signed with
        // since-rotated certificates keep verifying. Where the payload states
        // no date, the fallback reads the SYSTEM clock, not $this->clock.
        $signedAtMillis = JwsClaims::signedAtMillis($claims);
        $effectiveDate = $signedAtMillis ?? (int) (microtime(true) * 1000);
        ChainValidator::validatePair($leaf, $intermediate, $this->anchors, $effectiveDate);

        $this->verifyEs256($leaf, $headerB64 . '.' . $payloadB64, $signatureB64);

        $this->requireFresh($signedAtMillis);

        return $claims;
    }

    /** @throws VerificationException */
    private function verifyEs256(Certificate $leaf, string $signingInput, string $signatureB64): void
    {
        if ($leaf->publicKeyType() !== OPENSSL_KEYTYPE_EC) {
            throw new VerificationException(Reason::InvalidSignature, 'leaf key is not EC');
        }
        $signature = Base64::decodeStrict($signatureB64);
        if ($signature === null) {
            throw new VerificationException(Reason::InvalidJwsFormat, 'signature segment is not valid base64url');
        }
        if (strlen($signature) !== 64) {
            throw new VerificationException(
                Reason::InvalidSignature,
                'ES256 signature must be 64 bytes, got ' . strlen($signature),
            );
        }
        $key = $leaf->publicKey();
        if ($key === null) {
            throw new VerificationException(Reason::InvalidSignature, 'leaf public key is unreadable');
        }
        // openssl_verify() answers 1 valid, 0 invalid and -1 on error, and -1
        // is truthy in PHP. `=== 1` is the only acceptable comparison here.
        $result = openssl_verify($signingInput, self::p1363ToDer($signature), $key, OPENSSL_ALGO_SHA256);
        Certificate::drainOpenSslErrors();
        if ($result !== 1) {
            throw new VerificationException(Reason::InvalidSignature, 'ES256 signature check failed');
        }
    }

    /**
     * JWS ships an ES256 signature as raw `r ‖ s` (RFC 7515); OpenSSL wants
     * the ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`. No bignum extension
     * is involved — this is byte work on two fixed-width halves.
     */
    private static function p1363ToDer(string $signature): string
    {
        $encode = static function (string $half): string {
            $half = ltrim($half, "\x00");
            if ($half === '') {
                $half = "\x00";
            }
            if ((ord($half[0]) & 0x80) !== 0) {
                $half = "\x00" . $half;
            }

            return "\x02" . chr(strlen($half)) . $half;
        };
        $body = $encode(substr($signature, 0, 32)) . $encode(substr($signature, 32, 32));

        return "\x30" . chr(strlen($body)) . $body;
    }

    /** @throws VerificationException */
    private function requireBundleId(mixed $actual): void
    {
        if ($actual !== $this->bundleId) {
            throw new VerificationException(Reason::WrongBundleId, 'payload bundle id is not the configured one');
        }
    }

    /** @throws VerificationException */
    private function requireAcceptedEnvironment(mixed $claim): Environment
    {
        $environment = is_string($claim) ? Environment::tryFrom($claim) : null;
        if ($environment === null || !isset($this->acceptedEnvironments[$environment->value])) {
            throw new VerificationException(
                Reason::WrongEnvironment,
                'payload environment is not in the accepted set',
            );
        }

        return $environment;
    }

    /** @throws VerificationException */
    private function requireAppAppleId(Environment $environment, mixed $actual): void
    {
        if ($environment === Environment::Production
            && ($this->appAppleId === null || $this->appAppleId !== $actual)) {
            throw new VerificationException(
                Reason::WrongAppAppleId,
                'Production AppTransaction does not name the configured app Apple id',
            );
        }
    }

    /**
     * The one check that legitimately moves with wall-clock time, so the one
     * the injected clock drives.
     *
     * @throws VerificationException
     */
    private function requireFresh(?int $signedAtMillis): void
    {
        if ($this->maxSignedAgeSeconds === null || $signedAtMillis === null) {
            return;
        }
        $nowMillis = (int) $this->clock->now()->format('Uv');
        if ($nowMillis - $signedAtMillis > $this->maxSignedAgeSeconds * 1000) {
            throw new VerificationException(
                Reason::StalePayload,
                'payload was signed longer ago than the configured max signed age',
            );
        }
    }
}
