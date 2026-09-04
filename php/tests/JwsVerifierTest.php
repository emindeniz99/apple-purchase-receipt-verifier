<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

#[CoversClass(JwsVerifier::class)]
final class JwsVerifierTest extends TestCase
{
    private function verifier(?string $root = null, ?int $appAppleId = null): JwsVerifier
    {
        return new JwsVerifier(
            [$root ?? MintedPki::get()->rootDer],
            'com.example.app',
            [Environment::Sandbox, Environment::Production],
            $appAppleId,
        );
    }

    private function assertReason(Reason $expected, callable $call): VerificationException
    {
        try {
            $call();
        } catch (VerificationException $e) {
            self::assertSame($expected, $e->reason, $e->getMessage());

            return $e;
        }
        self::fail('expected ' . $expected->value . ' but the call returned a value');
    }

    public function testVerifiesAMintedTransaction(): void
    {
        $payload = $this->verifier()->verifyTransaction(MintedPki::get()->jws(MintedPki::transactionClaims()));

        self::assertSame('com.example.app', $payload->bundleId);
        self::assertSame('Sandbox', $payload->environment);
        self::assertSame('com.example.app.pro', $payload->productId);
        self::assertSame(1722945600000, $payload->signedDate, 'epoch millis, exactly as Apple ships them');
        self::assertSame(1, $payload->quantity);
    }

    /**
     * `x5c[2]` is never parsed and never trusted: the anchor set is the
     * constructor's. Swapping the third element for arbitrary bytes must
     * change nothing, or an attacker could supply their own "root".
     */
    public function testTheThirdX5cEntryIsIgnoredEntirely(): void
    {
        $pki = MintedPki::get();
        foreach ([$pki->foreignRootDer, 'not a certificate at all', ''] as $third) {
            $payload = $this->verifier()->verifyTransaction($pki->jws(MintedPki::transactionClaims(), $third));
            self::assertSame('com.example.app', $payload->bundleId);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function malformedJwsProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'one segment' => ['abc'];
        yield 'two segments' => ['abc.def'];
        yield 'four segments' => ['a.b.c.d'];
        yield 'header is not base64url JSON' => ['!!!!.e30.sig'];
        yield 'header is a JSON array' => [TestPki::b64url('[1,2]') . '.e30.sig'];
        yield 'header is a JSON scalar' => [TestPki::b64url('42') . '.e30.sig'];
    }

    #[DataProvider('malformedJwsProvider')]
    public function testRejectsMalformedJwsShapes(string $jws): void
    {
        $this->assertReason(Reason::InvalidJwsFormat, fn () => $this->verifier()->verifyTransaction($jws));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function malformedHeaderProvider(): iterable
    {
        yield 'alg none' => [['alg' => 'none', 'x5c' => ['a', 'b', 'c']]];
        yield 'alg RS256' => [['alg' => 'RS256', 'x5c' => ['a', 'b', 'c']]];
        yield 'alg absent' => [['x5c' => ['a', 'b', 'c']]];
        yield 'alg lowercase' => [['alg' => 'es256', 'x5c' => ['a', 'b', 'c']]];
        yield 'x5c absent' => [['alg' => 'ES256']];
        yield 'x5c of two' => [['alg' => 'ES256', 'x5c' => ['a', 'b']]];
        yield 'x5c of four' => [['alg' => 'ES256', 'x5c' => ['a', 'b', 'c', 'd']]];
        yield 'x5c not an array' => [['alg' => 'ES256', 'x5c' => 'abc']];
        yield 'x5c of non-strings' => [['alg' => 'ES256', 'x5c' => [1, 2, 3]]];
        yield 'x5c as an object' => [['alg' => 'ES256', 'x5c' => ['0' => 'a', '1' => 'b', '2' => 'c', 'x' => 'y']]];
    }

    /** @param array<string, mixed> $header */
    #[DataProvider('malformedHeaderProvider')]
    public function testRejectsMalformedHeaders(array $header): void
    {
        $jws = TestPki::b64url((string) json_encode($header)) . '.' . TestPki::b64url('{}') . '.sig';
        $this->assertReason(Reason::InvalidJwsFormat, fn () => $this->verifier()->verifyTransaction($jws));
    }

    public function testRejectsAnX5cEntryThatIsNotACertificate(): void
    {
        $jws = TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => [base64_encode('nonsense'), base64_encode('nonsense'), ''],
        ])) . '.' . TestPki::b64url('{}') . '.sig';

        $this->assertReason(Reason::InvalidCertificate, fn () => $this->verifier()->verifyTransaction($jws));
    }

    /**
     * On the JWS path the marker OIDs are checked BEFORE the chain. The order
     * is observable, so this pins it with an input that fails both: a leaf
     * with no marker OID under a root the verifier does not trust must report
     * the purpose, not the chain.
     */
    public function testMarkerOidsAreCheckedBeforeTheChain(): void
    {
        $pki = MintedPki::get();
        $jws = TestPki::jws(
            MintedPki::transactionClaims(),
            [$pki->jwsLeafNoOidDer, $pki->intermediateDer, $pki->rootDer],
            $pki->jwsLeafKey,
        );

        $this->assertReason(
            Reason::InvalidCertificatePurpose,
            fn () => $this->verifier($pki->foreignRootDer)->verifyTransaction($jws),
        );
    }

    public function testRejectsAnIntermediateWithoutTheWwdrMarkerOid(): void
    {
        $pki = MintedPki::get();
        $jws = TestPki::jws(
            MintedPki::transactionClaims(),
            [$pki->jwsLeafDer, $pki->intermediateNoOidDer, $pki->rootDer],
            $pki->jwsLeafKey,
        );

        $this->assertReason(Reason::InvalidCertificatePurpose, fn () => $this->verifier()->verifyTransaction($jws));
    }

    public function testRejectsAChainThatDoesNotReachAPinnedAnchor(): void
    {
        $pki = MintedPki::get();
        $this->assertReason(
            Reason::InvalidChain,
            fn () => $this->verifier($pki->foreignRootDer)
                ->verifyTransaction($pki->jws(MintedPki::transactionClaims())),
        );
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
        $jws = $pki->jws(MintedPki::transactionClaims());
        $parts = explode('.', $jws);
        $parts[2] = TestPki::b64url(str_repeat("\x01", $length));

        $this->assertReason(
            Reason::InvalidSignature,
            fn () => $this->verifier()->verifyTransaction(implode('.', $parts)),
        );
    }

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
        // Signed with the RSA key so the header/payload are well formed; the
        // key-type gate fires before the signature is ever checked.
        $header = TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => array_map(base64_encode(...), [$rsaLeaf, $pki->intermediateDer, $pki->rootDer]),
        ]));
        $payload = TestPki::b64url((string) json_encode(MintedPki::transactionClaims()));
        $jws = $header . '.' . $payload . '.' . TestPki::b64url(str_repeat("\x02", 64));

        $e = $this->assertReason(Reason::InvalidSignature, fn () => $this->verifier()->verifyTransaction($jws));
        self::assertStringContainsString('not EC', $e->getMessage());
    }

    public function testRejectsATamperedPayload(): void
    {
        $pki = MintedPki::get();
        $parts = explode('.', $pki->jws(MintedPki::transactionClaims()));
        $parts[1] = TestPki::b64url((string) json_encode(
            ['bundleId' => 'com.example.app', 'environment' => 'Sandbox', 'productId' => 'com.example.app.free'],
        ));

        $this->assertReason(
            Reason::InvalidSignature,
            fn () => $this->verifier()->verifyTransaction(implode('.', $parts)),
        );
    }

    /** Bundle id is checked before environment; a payload failing both says so. */
    public function testBundleIdIsCheckedBeforeEnvironment(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws(['bundleId' => 'com.other.app', 'environment' => 'Xcode', 'signedDate' => 1722945600000]);

        $this->assertReason(Reason::WrongBundleId, fn () => $this->verifier()->verifyTransaction($jws));
    }

    public function testRejectsAnEnvironmentOutsideTheAcceptSet(): void
    {
        $pki = MintedPki::get();
        $verifier = new JwsVerifier([$pki->rootDer], 'com.example.app', [Environment::Production]);

        $this->assertReason(
            Reason::WrongEnvironment,
            fn () => $verifier->verifyTransaction($pki->jws(MintedPki::transactionClaims())),
        );
    }

    public function testRejectsAnUnknownEnvironmentClaim(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws(['bundleId' => 'com.example.app', 'environment' => 'Staging', 'signedDate' => 1722945600000]);

        $this->assertReason(Reason::WrongEnvironment, fn () => $this->verifier()->verifyTransaction($jws));
    }

    public function testProductionAppTransactionRequiresTheConfiguredAppAppleId(): void
    {
        $pki = MintedPki::get();
        $claims = [
            'bundleId' => 'com.example.app',
            'receiptType' => 'Production',
            'appAppleId' => 123456789,
            'applicationVersion' => '1.2.3',
            'receiptCreationDate' => 1722945600000,
        ];
        $jws = $pki->jws($claims);

        self::assertSame(123456789, $this->verifier(null, 123456789)->verifyAppTransaction($jws)->appAppleId);
        $this->assertReason(Reason::WrongAppAppleId, fn () => $this->verifier(null, 999)->verifyAppTransaction($jws));
        $this->assertReason(Reason::WrongAppAppleId, fn () => $this->verifier()->verifyAppTransaction($jws));
    }

    public function testSandboxAppTransactionDoesNotRequireAnAppAppleId(): void
    {
        $pki = MintedPki::get();
        $jws = $pki->jws([
            'bundleId' => 'com.example.app',
            'receiptType' => 'Sandbox',
            'receiptCreationDate' => 1722945600000,
        ]);

        self::assertSame('Sandbox', $this->verifier()->verifyAppTransaction($jws)->receiptType);
    }

    /**
     * verifyRaw enforces no claim — but it still enforces the chain and the
     * signature, which is the whole point of it existing.
     */
    public function testVerifyRawSkipsClaimChecksButNotTheSignature(): void
    {
        $pki = MintedPki::get();
        $verifier = new JwsVerifier([$pki->rootDer], 'com.nothing.matches', [Environment::LocalTesting]);

        $claims = $verifier->verifyRaw($pki->jws(MintedPki::transactionClaims()));
        self::assertSame('com.example.app', $claims['bundleId']);
        self::assertSame('Sandbox', $claims['environment']);

        $parts = explode('.', $pki->jws(MintedPki::transactionClaims()));
        $parts[2] = TestPki::b64url(str_repeat("\x00", 64));
        $this->assertReason(Reason::InvalidSignature, fn () => $verifier->verifyRaw(implode('.', $parts)));
    }

    public function testUnmodelledClaimsStayReachableThroughTheEscapeHatch(): void
    {
        $pki = MintedPki::get();
        $claims = MintedPki::transactionClaims();
        $claims['somethingAppleAddsLater'] = ['nested' => true];
        $payload = $this->verifier()->verifyTransaction($pki->jws($claims));

        self::assertSame(['nested' => true], $payload->claims['somethingAppleAddsLater']);
        self::assertSame('com.example.app.pro', $payload->claims['productId']);
    }

    /**
     * `json_decode` degrades an integer beyond PHP_INT_MAX to a float. A
     * claim that is not an int is treated as absent rather than coerced, so a
     * huge `signedDate` cannot become a timestamp.
     */
    public function testAnOversizedIntegerClaimIsTreatedAsAbsentNotCoerced(): void
    {
        $pki = MintedPki::get();
        $header = TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => array_map(base64_encode(...), [$pki->jwsLeafDer, $pki->intermediateDer, $pki->rootDer]),
        ]));
        $payload = TestPki::b64url(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":123456789012345678901234567890}',
        );
        $signingInput = $header . '.' . $payload;
        openssl_sign($signingInput, $der, $pki->jwsLeafKey, OPENSSL_ALGO_SHA256);
        $jws = $signingInput . '.' . TestPki::b64url(TestPki::derToP1363((string) $der));

        $result = $this->verifier()->verifyTransaction($jws);
        self::assertNull($result->signedDate);
        self::assertIsFloat($result->claims['signedDate'], 'the raw claim is still reachable, as a float');
    }

    public function testIsActiveAtReadsTheSignedClaims(): void
    {
        $pki = MintedPki::get();
        $verifier = $this->verifier();
        $at = new DateTimeImmutable('2025-01-01T00:00:00Z');

        $noExpiry = $verifier->verifyTransaction($pki->jws(MintedPki::transactionClaims()));
        self::assertTrue($noExpiry->isActiveAt($at), 'a non-subscription is active');

        $expired = $verifier->verifyTransaction($pki->jws(
            MintedPki::transactionClaims() + ['expiresDate' => 1722945600000],
        ));
        self::assertFalse($expired->isActiveAt($at));

        $live = $verifier->verifyTransaction($pki->jws(
            MintedPki::transactionClaims() + ['expiresDate' => 4102444800000],
        ));
        self::assertTrue($live->isActiveAt($at));

        $revoked = $verifier->verifyTransaction($pki->jws(
            MintedPki::transactionClaims() + ['expiresDate' => 4102444800000, 'revocationDate' => 1722945600000],
        ));
        self::assertFalse($revoked->isActiveAt($at), 'revocation wins over an unexpired subscription');
    }

    /** No per-call mutation: one instance answers identically forever. */
    public function testTheVerifierIsStatelessAndReusable(): void
    {
        $pki = MintedPki::get();
        $verifier = $this->verifier();
        $jws = $pki->jws(MintedPki::transactionClaims());

        $first = $verifier->verifyTransaction($jws);
        for ($i = 0; $i < 50; ++$i) {
            self::assertEquals($first, $verifier->verifyTransaction($jws));
        }
        // Interleaving a failure must not poison the instance either.
        $this->assertReason(Reason::InvalidJwsFormat, fn () => $verifier->verifyTransaction('nope'));
        self::assertEquals($first, $verifier->verifyTransaction($jws));
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
        $method = new ReflectionMethod(JwsVerifier::class, 'p1363ToDer');

        self::assertSame($expectedHex, bin2hex((string) $method->invoke(null, $raw)));
    }
}
