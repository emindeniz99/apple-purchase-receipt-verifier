<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use OpenSSLAsymmetricKey;

/**
 * One generated PKI, built once per process and shared by every test that
 * needs one. RSA key generation is the expensive part of this suite, so the
 * keys are minted once and the certificates that hang off them are cheap.
 *
 * Shape mirrors Apple's: root → WWDR-style intermediate carrying
 * `1.2.840.113635.100.6.2.1` and `CA:TRUE` → leaves carrying
 * `1.2.840.113635.100.6.11.1`.
 */
final class MintedPki
{
    private static ?self $instance = null;

    public readonly OpenSSLAsymmetricKey $rootKey;
    public readonly OpenSSLAsymmetricKey $intermediateKey;
    public readonly OpenSSLAsymmetricKey $jwsLeafKey;
    public readonly OpenSSLAsymmetricKey $receiptSignerKey;
    public readonly OpenSSLAsymmetricKey $strangerKey;

    /** DER of the root; this is what a verifier is anchored to. */
    public readonly string $rootDer;
    public readonly string $intermediateDer;
    /** An intermediate with no WWDR marker OID. */
    public readonly string $intermediateNoOidDer;
    public readonly string $jwsLeafDer;
    /** A JWS leaf with no Apple marker OID. */
    public readonly string $jwsLeafNoOidDer;
    public readonly string $receiptSignerDer;
    public readonly string $receiptSignerSid;
    /** A receipt signer with no receipt-signing marker OID. */
    public readonly string $receiptSignerNoOidDer;
    public readonly string $receiptSignerNoOidSid;
    /** A signer whose key is EC rather than RSA. */
    public readonly string $ecSignerDer;
    public readonly string $ecSignerSid;
    /** A root nobody's chain reaches. */
    public readonly string $foreignRootDer;

    private function __construct()
    {
        $this->rootKey = TestPki::rsaKey();
        $this->intermediateKey = TestPki::rsaKey();
        $this->receiptSignerKey = TestPki::rsaKey();
        $this->strangerKey = TestPki::rsaKey();
        $this->jwsLeafKey = TestPki::ecKey();

        $root = TestPki::certificate('Minted Root', 'Minted Root', $this->rootKey, $this->rootKey, true);
        $this->rootDer = $root['der'];

        $this->intermediateDer = TestPki::certificate(
            'Minted WWDR',
            'Minted Root',
            $this->intermediateKey,
            $this->rootKey,
            true,
            [TestPki::INTERMEDIATE_OID_HEX],
        )['der'];
        $this->intermediateNoOidDer = TestPki::certificate(
            'Minted WWDR',
            'Minted Root',
            $this->intermediateKey,
            $this->rootKey,
            true,
        )['der'];

        $this->jwsLeafDer = TestPki::certificate(
            'Minted JWS Leaf',
            'Minted WWDR',
            $this->jwsLeafKey,
            $this->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
        )['der'];
        $this->jwsLeafNoOidDer = TestPki::certificate(
            'Minted JWS Leaf',
            'Minted WWDR',
            $this->jwsLeafKey,
            $this->intermediateKey,
        )['der'];

        $signer = TestPki::certificate(
            'Minted Receipt Signer',
            'Minted WWDR',
            $this->receiptSignerKey,
            $this->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
        );
        $this->receiptSignerDer = $signer['der'];
        $this->receiptSignerSid = $signer['sid'];

        $noOid = TestPki::certificate(
            'Minted Plain Signer',
            'Minted WWDR',
            $this->receiptSignerKey,
            $this->intermediateKey,
        );
        $this->receiptSignerNoOidDer = $noOid['der'];
        $this->receiptSignerNoOidSid = $noOid['sid'];

        $ecSigner = TestPki::certificate(
            'Minted EC Signer',
            'Minted WWDR',
            $this->jwsLeafKey,
            $this->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
        );
        $this->ecSignerDer = $ecSigner['der'];
        $this->ecSignerSid = $ecSigner['sid'];

        $this->foreignRootDer = TestPki::certificate(
            'Foreign Root',
            'Foreign Root',
            $this->strangerKey,
            $this->strangerKey,
            true,
        )['der'];
    }

    public static function get(): self
    {
        return self::$instance ??= new self();
    }

    /** The default receipt payload the negative tests mutate. */
    public static function payload(string $creationDate = '2024-08-06T12:00:00Z'): string
    {
        return TestPki::payload(
            TestPki::utf8Attribute(0, 'ProductionSandbox'),
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::utf8Attribute(3, '1.2.3'),
            TestPki::attribute(4, "\x01\x02\x03\x04\x05\x06\x07\x08"),
            TestPki::dateAttribute(12, $creationDate),
            TestPki::utf8Attribute(19, '1.0'),
        );
    }

    /** @return list<string> the full embedded chain a genuine receipt carries */
    public function chain(): array
    {
        return [$this->receiptSignerDer, $this->intermediateDer, $this->rootDer];
    }

    /** A genuinely valid receipt against {@see $rootDer}. */
    public function receipt(?string $payload = null): string
    {
        return TestPki::receipt(
            $payload ?? self::payload(),
            $this->chain(),
            $this->receiptSignerSid,
            $this->receiptSignerKey,
        );
    }

    /**
     * A genuinely valid JWS against {@see $rootDer}.
     *
     * @param array<string, mixed> $claims
     */
    public function jws(array $claims, ?string $x5cThird = null): string
    {
        return TestPki::jws(
            $claims,
            [$this->jwsLeafDer, $this->intermediateDer, $x5cThird ?? $this->rootDer],
            $this->jwsLeafKey,
        );
    }

    /** @return array<string, mixed> */
    public static function transactionClaims(): array
    {
        return [
            'bundleId' => 'com.example.app',
            'environment' => 'Sandbox',
            'productId' => 'com.example.app.pro',
            'transactionId' => '2000000000000001',
            'quantity' => 1,
            'signedDate' => 1722945600000,
        ];
    }
}
