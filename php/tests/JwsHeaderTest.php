<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Header shapes a PHP decoder is prone to accept. `json_decode(..., true)`
 * turns a JSON object into the same PHP array a JSON list becomes, and
 * `alg` compared loosely would match `es256`; each must still be refused as
 * MALFORMED before any certificate is decoded. The shared cases cover
 * `alg` RS256 and a few x5c shapes; the rest are this port's traps.
 */
#[CoversClass(Verifier::class)]
final class JwsHeaderTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function malformedHeaderProvider(): iterable
    {
        $chain = array_map('base64_encode', [
            MintedPki::get()->jwsLeafDer,
            MintedPki::get()->intermediateDer,
            MintedPki::get()->rootDer,
        ]);

        yield 'alg none' => [['alg' => 'none', 'x5c' => $chain]];
        yield 'alg absent' => [['x5c' => $chain]];
        yield 'alg lowercase' => [['alg' => 'es256', 'x5c' => $chain]];
        yield 'alg not a string' => [['alg' => 256, 'x5c' => $chain]];
        yield 'x5c absent' => [['alg' => 'ES256']];
        yield 'x5c of two' => [['alg' => 'ES256', 'x5c' => array_slice($chain, 0, 2)]];
        yield 'x5c of four' => [['alg' => 'ES256', 'x5c' => [...$chain, $chain[2]]]];
        yield 'x5c not an array' => [['alg' => 'ES256', 'x5c' => $chain[0]]];
        yield 'x5c of non-strings' => [['alg' => 'ES256', 'x5c' => [1, 2, 3]]];
        yield 'x5c an object with an extra key' => [['alg' => 'ES256', 'x5c' => [...$chain, 'x' => 'y']]];
        yield 'x5c an object keyed 0 to 2' => [['alg' => 'ES256', 'x5c' => (object) $chain]];
    }

    /** @param array<string, mixed> $header */
    #[DataProvider('malformedHeaderProvider')]
    public function testAMalformedHeaderIsMalformed(array $header): void
    {
        $pki = MintedPki::get();
        $genuine = $pki->jws(MintedPki::transactionClaims());
        [, $payload, $signature] = explode('.', $genuine);
        $jws = TestPki::b64url(json_encode($header, JSON_THROW_ON_ERROR)) . '.' . $payload . '.' . $signature;

        $result = Verifier::create(Config::builder()->roots([$pki->rootDer])->build())->verifySignedData($jws);

        self::assertFalse($result->verified());
        self::assertSame(Reason::Malformed, $result->failure?->reason);
    }

    /**
     * The same object-for-array confusion with a signature that matches, so
     * nothing but the header check stands between it and a verified result.
     */
    public function testAGenuinelySignedX5cObjectIsMalformed(): void
    {
        $pki = MintedPki::get();
        $chain = array_map('base64_encode', [$pki->jwsLeafDer, $pki->intermediateDer, $pki->rootDer]);
        $header = TestPki::b64url(json_encode(['alg' => 'ES256', 'x5c' => (object) $chain], JSON_THROW_ON_ERROR));
        $payload = TestPki::b64url(json_encode(MintedPki::transactionClaims(), JSON_THROW_ON_ERROR));
        self::assertTrue(openssl_sign("{$header}.{$payload}", $der, $pki->jwsLeafKey, OPENSSL_ALGO_SHA256));
        $jws = "{$header}.{$payload}." . TestPki::b64url(TestPki::derToP1363($der));

        $result = Verifier::create(Config::builder()->roots([$pki->rootDer])->build())->verifySignedData($jws);

        self::assertSame(Reason::Malformed, $result->failure?->reason);
    }

    /**
     * An associative decode gives `[]` and `{}` the same PHP value. A
     * genuinely signed payload that is the empty JSON array is Apple-signed
     * content that is not a JSON object: UNREADABLE_PAYLOAD, as the shared
     * case signed-data/unreadable-json-array-payload pins for a non-empty
     * array.
     */
    public function testAGenuinelySignedEmptyArrayPayloadIsUnreadable(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws([]);
        self::assertSame('[]', base64_decode(strtr(explode('.', $jws)[1], '-_', '+/'), true));

        $result = Verifier::create(Config::builder()->roots([$pki->rootDer])->build())->verifySignedData($jws);

        self::assertSame(Reason::UnreadablePayload, $result->failure?->reason);
    }
}
