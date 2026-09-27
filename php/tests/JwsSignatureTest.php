<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * The pieces of {@see Verifier}'s JWS path that are specific to it and not
 * already pinned by the 310-case shared conformance suite or by
 * {@see MutationTest} / {@see HostileInputTest}: trust in `x5c[2]` (or
 * rather the deliberate absence of it), the EC-only key gate, reuse across
 * calls, and the raw-integer edge cases of the P1363-to-DER signature
 * conversion.
 *
 * The typed `verifyTransaction()` / `verifyAppTransaction()` / `verifyRaw()`
 * surface, bundle-id and environment filtering, and the accept-set concept
 * this file tested in 0.6 do not exist in 0.7: `verifySignedData()` returns
 * the payload as raw JSON text, and filtering on its claims is the caller's
 * job (docs/design/0.7-api.md, "Result").
 */
#[CoversClass(Verifier::class)]
final class JwsSignatureTest extends TestCase
{
    private static function verifier(?string $root = null): Verifier
    {
        return Verifier::create(Config::builder()->roots([$root ?? MintedPki::get()->rootDer])->build());
    }

    /**
     * `x5c[2]` is never trusted: the anchor set comes from {@see Config}, so
     * swapping the third element for another PKI's root must change
     * nothing, or an attacker could supply their own "root".
     */
    public function testTheThirdX5cEntryIsNeverTrusted(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws(MintedPki::transactionClaims(), $pki->foreignRootDer);

        $result = self::verifier()->verifySignedData($jws);
        self::assertTrue($result->verified());
        self::assertStringContainsString('"bundleId":"com.example.app"', $result->payload->json);
    }

    /**
     * Untrusted is not the same as unread: the third entry still has to BE a
     * certificate. `transaction/reject-x5c-root-that-is-not-a-certificate`
     * pins this same rule at the conformance level; this is the same check
     * from the code side, with an empty string as the second shape.
     */
    public function testTheThirdX5cEntryMustStillBeACertificate(): void
    {
        $pki = MintedPki::get();
        foreach (['not a certificate at all', ''] as $third) {
            $jws = $pki->jws(MintedPki::transactionClaims(), $third);
            $result = self::verifier()->verifySignedData($jws);
            self::assertFalse($result->verified(), $third);
            self::assertSame(Reason::InvalidCertificate, $result->failure->reason, $third);
        }
    }

    /** Only an EC leaf key is accepted; the gate fires before any signature bytes are checked. */
    public function testRejectsALeafWhoseKeyIsNotEc(): void
    {
        $pki = MintedPki::get();
        $rsaLeaf = TestPki::certificate(
            'RSA Leaf',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
        )['der'];
        $header = TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => array_map(base64_encode(...), [$rsaLeaf, $pki->intermediateDer, $pki->rootDer]),
        ]));
        $payload = TestPki::b64url((string) json_encode(MintedPki::transactionClaims()));
        $jws = $header . '.' . $payload . '.' . TestPki::b64url(str_repeat("\x02", 64));

        $result = self::verifier()->verifySignedData($jws);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
        self::assertStringContainsString('not EC', $result->failure->message);
    }

    /** @return iterable<string, array{int}> */
    public static function signatureLengthProvider(): iterable
    {
        yield '63 bytes' => [63];
        yield '65 bytes' => [65];
        yield '0 bytes' => [0];
        yield '128 bytes' => [128];
    }

    #[DataProvider('signatureLengthProvider')]
    public function testRejectsAnEs256SignatureOfTheWrongLength(int $length): void
    {
        $pki = MintedPki::get();
        $parts = explode('.', $pki->jws(MintedPki::transactionClaims()));
        $parts[2] = TestPki::b64url(str_repeat("\x01", $length));

        $result = self::verifier()->verifySignedData(implode('.', $parts));
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
    }

    /** No per-call mutation: one instance answers identically forever. */
    public function testTheVerifierIsStatelessAndReusable(): void
    {
        $pki = MintedPki::get();
        $verifier = self::verifier();
        $jws = $pki->jws(MintedPki::transactionClaims());

        $first = $verifier->verifySignedData($jws);
        self::assertTrue($first->verified());
        for ($i = 0; $i < 50; ++$i) {
            self::assertEquals($first->payload, $verifier->verifySignedData($jws)->payload);
        }
        // Interleaving a failure must not poison the instance either.
        $failed = $verifier->verifySignedData('nope');
        self::assertFalse($failed->verified());
        self::assertSame(Reason::Malformed, $failed->failure->reason);
        self::assertEquals($first->payload, $verifier->verifySignedData($jws)->payload);
    }

    /** @return iterable<string, array{string, string}> */
    public static function p1363Provider(): iterable
    {
        // r and s halves the conversion has to encode without a bignum
        // extension: leading zeros stripped, a high bit forced to take a
        // 0x00 prefix, an all-zero half collapsing to a single 0x00.
        yield 'both halves small' => [
            str_repeat("\x00", 31) . "\x01" . str_repeat("\x00", 31) . "\x02",
            '3006020101020102',
        ];
        yield 'high bit set in both halves' => [
            str_repeat("\xff", 64),
            '3046022100' . str_repeat('ff', 32) . '022100' . str_repeat('ff', 32),
        ];
        yield 'all-zero halves' => [str_repeat("\x00", 64), '3006020100020100'];
    }

    #[DataProvider('p1363Provider')]
    public function testP1363ToDerHandlesTheIntegerEncodingEdges(string $raw, string $expectedHex): void
    {
        $method = new ReflectionMethod(Verifier::class, 'p1363ToDer');

        self::assertSame($expectedHex, bin2hex(Shape::asString($method->invoke(null, $raw), 'p1363ToDer output')));
    }
}
