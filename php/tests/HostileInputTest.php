<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Hostile and malformed input across every public entry point.
 *
 * Two properties are asserted everywhere: nothing escapes as an unhandled
 * `Throwable` (the design promises the three `Verifier` methods never
 * throw), and no hostile input is ever verified. Containment is categorical
 * rather than a list of expected types — an attacker-triggered `TypeError`
 * deep in a parser is indistinguishable from a bug at the call site, and
 * neither may reach a caller as a 500.
 */
#[CoversNothing]
final class HostileInputTest extends TestCase
{
    private static function verifier(): Verifier
    {
        return Verifier::create(Config::builder()->roots([MintedPki::get()->rootDer])->build());
    }

    /** @return iterable<string, array{string}> */
    public static function hostileReceiptProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'one byte' => ["\x30"];
        yield 'four bytes' => ["\x01\x02\x03\x04"];
        yield 'bare indefinite length' => ["\x30\x80"];
        yield 'a lone NUL' => ["\x00"];
        yield 'a SEQUENCE claiming 4 GB' => ["\x30\x84\xff\xff\xff\xff"];
        yield 'a valid SEQUENCE of nothing' => [DerWriter::tlv(DerWriter::SEQUENCE)];
        yield 'a CMS OID with no content' => [
            DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::oid(TestPki::OID_SIGNED_DATA_HEX)),
        ];
        yield 'SignedData with no SignerInfo' => [
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid(TestPki::OID_SIGNED_DATA_HEX),
                DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::tlv(
                    DerWriter::SEQUENCE,
                    DerWriter::int(1),
                    DerWriter::tlv(DerWriter::SET),
                    DerWriter::tlv(
                        DerWriter::SEQUENCE,
                        DerWriter::oid(TestPki::OID_DATA_HEX),
                        DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::tlv(DerWriter::OCTET_STRING, 'x')),
                    ),
                    DerWriter::tlv(DerWriter::SET),
                )),
            ),
        ];
        yield 'SignedData with no encapsulated content' => [
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid(TestPki::OID_SIGNED_DATA_HEX),
                DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::tlv(
                    DerWriter::SEQUENCE,
                    DerWriter::int(1),
                    DerWriter::tlv(DerWriter::SET),
                    DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::oid(TestPki::OID_DATA_HEX)),
                    DerWriter::tlv(DerWriter::SET),
                )),
            ),
        ];
        yield 'base64 of nothing' => ['===='];
        yield 'base64 with invalid characters' => ['!!!not base64!!!'];
        yield 'html' => ['<html><body>404</body></html>'];
        yield 'a JSON object' => ['{"receipt-data":"x"}'];
        yield 'trailing bytes after a genuine receipt' => [MintedPki::get()->receipt() . "\x00"];
        yield 'a genuine receipt with its first byte flipped' => [
            "\x00" . substr(MintedPki::get()->receipt(), 1),
        ];

        // 200 nested SEQUENCE openers. An unbounded recursive parser
        // segfaults or exhausts the C stack rather than raising, so the
        // depth bound is the only thing between this input and a crashed
        // FPM worker.
        yield '200 nested SEQUENCE openers' => [str_repeat("\x30\x80", 200)];
        yield '5000 nested SEQUENCE openers' => [str_repeat("\x30\x80", 5000)];
        yield 'deep definite-length nesting' => [self::nested(200)];

        // Degenerate signed attributes: shapes whose walk runs off the end of
        // a child list rather than finding an attribute.
        foreach (self::degenerateSignedAttrs() as $label => $attrs) {
            yield "signed attributes: {$label}" => [self::forgeWithSignedAttrs($attrs)];
        }
    }

    /**
     * Every entry above is raw bytes — a hostile client's receipt, DER or
     * not — and 0.7 takes only base64 (docs/design/0.7-api.md §1), so each
     * one is base64-encoded here, once, the way a real client transports it.
     */
    #[DataProvider('hostileReceiptProvider')]
    public function testHostileReceiptInputIsRejectedAsAResultFailure(string $raw): void
    {
        try {
            $result = self::verifier()->verifyReceipt(base64_encode($raw));
        } catch (Throwable $e) {
            self::fail('verifyReceipt escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        self::assertFalse($result->verified(), 'a hostile receipt was ACCEPTED');
        self::assertNotSame(Reason::InternalError, $result->failure?->reason, (string) $result->failure?->message);
    }

    /**
     * The same corpus through the endpoint, which promises never to throw.
     * 21009 would mean it hit something it did not expect, so a malformed
     * receipt reaching 21009 is a defect even though no exception escaped.
     */
    #[DataProvider('hostileReceiptProvider')]
    public function testHostileReceiptInputNeverReachesTheEndpointsInternalError(string $raw): void
    {
        $requestJson = json_encode(['receipt-data' => base64_encode($raw)], JSON_THROW_ON_ERROR);
        try {
            $response = self::verifier()->verifyReceiptEndpoint(Environment::Sandbox, $requestJson);
        } catch (Throwable $e) {
            self::fail('verifyReceiptEndpoint escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        /** @var array{status: int} $decoded */
        $decoded = json_decode($response, true, 8, JSON_THROW_ON_ERROR);

        self::assertNotSame(21009, $decoded['status']);
        self::assertNotSame(0, $decoded['status'], 'a hostile receipt was ACCEPTED');
    }

    /** @return iterable<string, array{string}> */
    public static function hostileJwsProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'a single dot' => ['.'];
        yield 'two dots' => ['..'];
        yield 'three dots' => ['...'];
        yield 'a very long segment' => [str_repeat('A', 100000) . '.b.c'];
        yield 'NUL bytes' => ["\x00.\x00.\x00"];
        yield 'invalid UTF-8' => ["\xff\xfe.\xff\xfe.\xff\xfe"];
        yield 'a JSON array header' => [TestPki::b64url('[]') . '.' . TestPki::b64url('{}') . '.x'];
        yield 'a JSON array payload' => [self::headerWithRealChain() . '.' . TestPki::b64url('[]') . '.x'];
        yield 'a JSON scalar payload' => [self::headerWithRealChain() . '.' . TestPki::b64url('7') . '.x'];
        yield 'a payload that is not JSON' => [self::headerWithRealChain() . '.!!!!.x'];
        yield 'a 600-deep JSON payload' => [
            self::headerWithRealChain() . '.'
            . TestPki::b64url(str_repeat('{"a":', 600) . '1' . str_repeat('}', 600)) . '.x',
        ];
        yield 'x5c holding a JSON object' => [
            TestPki::b64url((string) json_encode(['alg' => 'ES256', 'x5c' => [['nested'], 'b', 'c']]))
            . '.' . TestPki::b64url('{}') . '.x',
        ];
    }

    #[DataProvider('hostileJwsProvider')]
    public function testHostileJwsInputIsRejectedAsAResultFailure(string $jws): void
    {
        try {
            $result = self::verifier()->verifySignedData($jws);
        } catch (Throwable $e) {
            self::fail('verifySignedData escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        self::assertFalse($result->verified(), 'a hostile JWS was ACCEPTED');
        self::assertNotSame(Reason::InternalError, $result->failure?->reason, (string) $result->failure?->message);
    }

    /**
     * The transport form is canonical standard base64 and nothing else, as
     * Apple's verifyReceipt accepts it: the canonical string verifies, and
     * each spelling a lenient decoder would map to the same DER is refused,
     * as it is by Apple and by every other port.
     */
    public function testBase64TransportIsCanonicalStandardBase64Only(): void
    {
        $der = MintedPki::get()->receipt();
        $standard = base64_encode($der);
        $ok = self::verifier()->verifyReceipt($standard);
        self::assertTrue($ok->verified());
        self::assertSame('com.example.app', $ok->payload->bundleId);

        foreach ([
            'wrapped' => chunk_split($standard, 64, "\n"),
            'spaced' => implode(' ', str_split($standard, 40)),
            'url-safe' => strtr($standard, '+/', '-_'),
            // Whichever way the padding is wrong for this DER's length.
            'mis-padded' => str_ends_with($standard, '=') ? rtrim($standard, '=') : $standard . '=',
        ] as $label => $variant) {
            self::assertNotSame($standard, $variant, $label);
            $result = self::verifier()->verifyReceipt($variant);
            self::assertFalse($result->verified(), "{$label}: a non-canonical spelling was accepted");
            self::assertSame(Reason::Malformed, $result->failure?->reason, $label);
        }
    }

    /** @return array<string, string> */
    private static function degenerateSignedAttrs(): array
    {
        $digestOid = DerWriter::oid(TestPki::OID_MESSAGE_DIGEST_HEX);

        return [
            '[0] wrapping a primitive' => DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::int(0)),
            'attribute carrying only the OID' => DerWriter::tlv(
                DerWriter::CONTEXT_0,
                DerWriter::tlv(DerWriter::SEQUENCE, $digestOid),
            ),
            'primitive attribute value' => DerWriter::tlv(
                DerWriter::CONTEXT_0,
                DerWriter::tlv(DerWriter::SEQUENCE, $digestOid, DerWriter::int(0)),
            ),
            'empty attribute value SET' => DerWriter::tlv(
                DerWriter::CONTEXT_0,
                DerWriter::tlv(DerWriter::SEQUENCE, $digestOid, DerWriter::tlv(DerWriter::SET)),
            ),
            'empty [0]' => DerWriter::tlv(DerWriter::CONTEXT_0),
        ];
    }

    private static function forgeWithSignedAttrs(string $signedAttrs): string
    {
        $pki = MintedPki::get();

        return TestPki::receipt(
            MintedPki::payload(),
            $pki->chain(),
            $pki->receiptSignerSid,
            null,
            TestPki::OID_SHA256_HEX,
            "\x00",
            $signedAttrs,
        );
    }

    private static function headerWithRealChain(): string
    {
        $pki = MintedPki::get();

        return TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => array_map(base64_encode(...), [$pki->jwsLeafDer, $pki->intermediateDer, $pki->rootDer]),
        ]));
    }

    private static function nested(int $depth): string
    {
        $node = DerWriter::int(1);
        for ($i = 0; $i < $depth; ++$i) {
            $node = DerWriter::tlv(DerWriter::SEQUENCE, $node);
        }

        return $node;
    }
}
