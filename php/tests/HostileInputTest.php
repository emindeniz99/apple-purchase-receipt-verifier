<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Hostile and malformed input across every public entry point.
 *
 * Two properties are asserted everywhere: nothing but `VerificationException`
 * escapes, and no hostile input is ever ACCEPTED. Containment is categorical
 * rather than a list of expected types — an attacker-triggered `TypeError`
 * deep in a parser is indistinguishable from a bug at the call site, and
 * neither may reach a caller as a 500.
 */
#[CoversNothing]
final class HostileInputTest extends TestCase
{
    private static function receiptVerifier(): ReceiptVerifier
    {
        return new ReceiptVerifier([MintedPki::get()->rootDer], 'com.example.app');
    }

    private static function jwsVerifier(): JwsVerifier
    {
        return new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox]);
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

        // 200 nested SEQUENCE openers. On PHP 8.1 — which has no
        // zend.max_allowed_stack_size — an unbounded recursive parser
        // segfaults rather than raising, so the depth bound is the only thing
        // between this input and a crashed FPM worker.
        yield '200 nested SEQUENCE openers' => [str_repeat("\x30\x80", 200)];
        yield '5000 nested SEQUENCE openers' => [str_repeat("\x30\x80", 5000)];
        yield 'deep definite-length nesting' => [self::nested(200)];

        // Degenerate signed attributes: shapes whose walk runs off the end of
        // a child list rather than finding an attribute.
        foreach (self::degenerateSignedAttrs() as $label => $attrs) {
            yield "signed attributes: {$label}" => [self::forgeWithSignedAttrs($attrs)];
        }
    }

    #[DataProvider('hostileReceiptProvider')]
    public function testHostileReceiptInputIsRejectedAsAVerificationException(string $input): void
    {
        try {
            self::receiptVerifier()->verify($input);
            self::fail('a hostile receipt was ACCEPTED');
        } catch (VerificationException $e) {
            self::assertContains($e->reason, [
                Reason::InvalidReceiptFormat,
                Reason::InvalidChain,
                Reason::InvalidSignature,
                Reason::InvalidCertificatePurpose,
                Reason::WrongBundleId,
            ], $e->getMessage());
        } catch (Throwable $e) {
            self::fail('escaped as ' . $e::class . ': ' . $e->getMessage());
        }
    }

    /**
     * The same corpus through the endpoint, which promises never to throw.
     * 21009 would mean it hit something it did not expect, so a malformed
     * receipt reaching 21009 is a defect even though no exception escaped.
     */
    #[DataProvider('hostileReceiptProvider')]
    public function testHostileReceiptInputNeverReachesTheEndpointsInternalError(string $input): void
    {
        $endpoint = new VerifyReceiptEndpoint([MintedPki::get()->rootDer], Environment::Sandbox);
        $status = $endpoint->verifyReceipt(['receipt-data' => base64_encode($input)])['status'];

        self::assertNotSame(21009, $status);
        self::assertNotSame(0, $status, 'a hostile receipt was ACCEPTED');
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
    public function testHostileJwsInputIsRejectedAsAVerificationException(string $input): void
    {
        foreach (['verifyTransaction', 'verifyAppTransaction', 'verifyRaw'] as $operation) {
            try {
                self::jwsVerifier()->{$operation}($input);
                self::fail("a hostile JWS was ACCEPTED by {$operation}");
            } catch (VerificationException) {
                $this->addToAssertionCount(1);
            } catch (Throwable $e) {
                self::fail("{$operation} escaped as " . $e::class . ': ' . $e->getMessage());
            }
        }
    }

    /**
     * Base64 leniency is not a security property, but it does have to be the
     * same leniency the other ports have, or the same client transport form
     * would work in one language and not another.
     */
    public function testBase64TransportAcceptsWhitespaceAndTheUrlSafeAlphabet(): void
    {
        $der = MintedPki::get()->receipt();
        $standard = base64_encode($der);

        foreach ([
            'wrapped' => chunk_split($standard, 64, "\n"),
            'spaced' => implode(' ', str_split($standard, 40)),
            'url-safe' => rtrim(strtr($standard, '+/', '-_'), '='),
            'unpadded' => rtrim($standard, '='),
        ] as $label => $variant) {
            self::assertSame(
                'com.example.app',
                self::receiptVerifier()->verify($variant)->bundleId,
                $label,
            );
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
