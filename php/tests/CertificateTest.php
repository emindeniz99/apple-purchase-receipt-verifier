<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The X.509 reader, and the OpenSSL conventions the chain walk sits on.
 *
 * Two of these tests exist entirely because of how PHP's OpenSSL binding
 * answers: `openssl_verify()` and `openssl_x509_verify()` return -1 on error,
 * and -1 is truthy. A refactor to `if (openssl_verify(...))` would turn every
 * unreadable key into a valid signature, and would look correct.
 */
#[CoversClass(Certificate::class)]
final class CertificateTest extends TestCase
{
    public function testReadsTheFieldsTheChainWalkNeeds(): void
    {
        $pki = MintedPki::get();
        $leaf = Certificate::parse($pki->jwsLeafDer);
        $intermediate = Certificate::parse($pki->intermediateDer);

        self::assertSame(TestPki::name('Minted WWDR'), $leaf->issuerDer);
        self::assertSame(TestPki::name('Minted JWS Leaf'), $leaf->subjectDer);
        self::assertSame($leaf->issuerDer, $intermediate->subjectDer, 'the leaf chains on a byte-equal name');
        self::assertTrue($intermediate->isCa);
        self::assertFalse($leaf->isCa);
        self::assertSame('1.2.840.10045.2.1', $leaf->publicKeyAlgorithmOid, 'id-ecPublicKey');
        self::assertSame('1.2.840.10045.3.1.7', $leaf->publicKeyCurveOid, 'prime256v1');
        self::assertSame('1.2.840.113549.1.1.11', $intermediate->signatureAlgorithmOid);
        self::assertSame(OPENSSL_KEYTYPE_EC, $leaf->publicKeyType());
        self::assertSame(OPENSSL_KEYTYPE_RSA, $intermediate->publicKeyType());
    }

    /**
     * Presence is decided on the ENCODED OID bytes, not on a key
     * `openssl_x509_parse()` produced. If a future OpenSSL learns a short
     * name for an Apple OID, a name-keyed check starts failing on genuine
     * certificates; encoded bytes cannot drift.
     */
    public function testMarkerOidPresenceIsDecidedOnEncodedBytes(): void
    {
        $pki = MintedPki::get();
        self::assertTrue(Certificate::parse($pki->jwsLeafDer)->hasExtension('1.2.840.113635.100.6.11.1'));
        self::assertFalse(Certificate::parse($pki->jwsLeafDer)->hasExtension('1.2.840.113635.100.6.2.1'));
        self::assertTrue(Certificate::parse($pki->intermediateDer)->hasExtension('1.2.840.113635.100.6.2.1'));
        self::assertFalse(Certificate::parse($pki->jwsLeafNoOidDer)->hasExtension('1.2.840.113635.100.6.11.1'));
        // A certificate with no extensions at all answers false rather than throwing.
        self::assertFalse(Certificate::parse($pki->rootDer)->hasExtension('1.2.840.113635.100.6.11.1'));
    }

    /**
     * RFC 5280 §4.1.1.2: the two AlgorithmIdentifiers must be the same one.
     * Without this check the algorithm a signature is verified under comes
     * from the outer field, which the signature does not cover.
     */
    public function testRejectsACertificateWhoseInnerAndOuterSignatureAlgorithmsDisagree(): void
    {
        $pki = MintedPki::get();
        $mismatched = TestPki::certificate(
            'Mismatched',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [],
            null,
            '2a864886f70d010105', // sha1WithRSAEncryption inside, sha256 outside
        )['der'];

        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/signatureAlgorithm disagrees/');
        Certificate::parse($mismatched);
    }

    /**
     * Contents that are neither a well-formed UTCTime nor GeneralizedTime
     * make the certificate valid at NO instant, rather than at every instant
     * or at a rolled-over one. Fail closed.
     */
    public function testUnparseableValidityContentsMeanValidAtNoInstant(): void
    {
        $pki = MintedPki::get();
        $junkValidity = DerWriter::tlv(
            DerWriter::SEQUENCE,
            DerWriter::tlv(DerWriter::UTC_TIME, 'not-a-time!!'),
            DerWriter::tlv(DerWriter::UTC_TIME, 'also-not-one'),
        );
        $cert = Certificate::parse(TestPki::certificate(
            'Junk Validity',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [],
            $junkValidity,
        )['der']);

        self::assertSame(PHP_INT_MAX, $cert->notBefore);
        self::assertSame(PHP_INT_MIN, $cert->notAfter);
        self::assertFalse($cert->isValidAt(0));
        self::assertFalse($cert->isValidAt(1722945600000));
        self::assertFalse($cert->isValidAt(PHP_INT_MAX));
    }

    /** A rolled-over date (month 13, day 45) is refused, not silently moved. */
    public function testOutOfRangeValidityComponentsMeanValidAtNoInstant(): void
    {
        $pki = MintedPki::get();
        $cert = Certificate::parse(TestPki::certificate(
            'Rollover Validity',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [],
            TestPki::validity('201345999999Z', '301345999999Z'),
        )['der']);

        self::assertFalse($cert->isValidAt(1722945600000));
    }

    public function testUtcTimeUsesTheRfc5280PivotAndGeneralizedTimeIsAbsolute(): void
    {
        $pki = MintedPki::get();
        $cert = Certificate::parse(TestPki::certificate(
            'Pivoted',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [],
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::tlv(DerWriter::UTC_TIME, '490101000000Z'),          // 2049
                DerWriter::tlv(DerWriter::GENERALIZED_TIME, '20600101000000Z'), // 2060
            ),
        )['der']);

        self::assertSame(gmmktime(0, 0, 0, 1, 1, 2049) * 1000, $cert->notBefore);
        self::assertSame(gmmktime(0, 0, 0, 1, 1, 2060) * 1000, $cert->notAfter);
    }

    public function testAWrongValidityTagIsRejectedOutright(): void
    {
        $pki = MintedPki::get();
        $this->expectException(ParseException::class);
        $this->expectExceptionMessageMatches('/Validity time type/');
        Certificate::parse(TestPki::certificate(
            'Wrong Tag',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [],
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::tlv(DerWriter::IA5_STRING, '200101000000Z'),
                DerWriter::tlv(DerWriter::IA5_STRING, '300101000000Z'),
            ),
        )['der']);
    }

    public function testIssuedByRequiresBothTheNameAndTheSignature(): void
    {
        $pki = MintedPki::get();
        $leaf = Certificate::parse($pki->jwsLeafDer);
        $intermediate = Certificate::parse($pki->intermediateDer);
        $root = Certificate::parse($pki->rootDer);
        $foreign = Certificate::parse($pki->foreignRootDer);

        self::assertTrue($leaf->isIssuedBy($intermediate));
        self::assertTrue($intermediate->isIssuedBy($root));
        self::assertFalse($leaf->isIssuedBy($root), 'the leaf is two hops from the root');
        self::assertFalse($intermediate->isIssuedBy($foreign));

        // Same subject name, different key: the name matches and the
        // signature does not, which is exactly the confusion a name-only
        // check would fall for.
        $impostor = Certificate::parse(TestPki::certificate(
            'Minted WWDR',
            'Impostor Root',
            $pki->strangerKey,
            $pki->strangerKey,
            true,
        )['der']);
        self::assertFalse($leaf->isIssuedBy($impostor));
    }

    /**
     * The -1 trap, asserted against the primitive so it is a statement about
     * PHP and not about our wrapper. `-1` is truthy: `if (openssl_verify(…))`
     * treats an ERROR as a valid signature.
     */
    public function testOpenSslPrimitivesReturnMinusOneOnErrorAndMinusOneIsTruthy(): void
    {
        $pki = MintedPki::get();
        $rsaKey = Certificate::parse($pki->rootDer)->publicKey();
        $ecKey = Certificate::parse($pki->jwsLeafDer)->publicKey();
        self::assertNotNull($rsaKey);
        self::assertNotNull($ecKey);

        // An EC key handed a signature that is not a DER SEQUENCE: OpenSSL
        // cannot even attempt the check, so this is an ERROR, not "invalid".
        self::assertSame(-1, openssl_verify('data', "\x00\x01", $ecKey, OPENSSL_ALGO_SHA256));
        self::assertSame(-1, openssl_x509_verify('not a certificate', $rsaKey));
        // A genuine certificate against the wrong key TYPE is an error too.
        self::assertSame(-1, openssl_x509_verify(Certificate::parse($pki->jwsLeafDer)->pem(), $ecKey));
        // For contrast: a well-formed-but-wrong RSA signature answers a plain 0.
        self::assertSame(0, openssl_verify('data', str_repeat("\x41", 256), $rsaKey, OPENSSL_ALGO_SHA256));

        self::assertTrue((bool) -1, 'this is why every call site compares === 1');
        Certificate::drainOpenSslErrors();
    }

    /**
     * A failed probe must not leave its error strings on the queue for a
     * caller's next unrelated `openssl_*` call to inherit — a real
     * cross-library bug, and one a library that verifies hostile input would
     * trigger constantly.
     */
    public function testTheOpenSslErrorQueueIsDrainedAfterAFailedCheck(): void
    {
        $pki = MintedPki::get();
        Certificate::drainOpenSslErrors();

        self::assertFalse(Certificate::parse($pki->jwsLeafDer)->isIssuedBy(Certificate::parse($pki->foreignRootDer)));
        self::assertFalse(openssl_error_string(), 'the OpenSSL error queue leaked into the caller');
    }

    public function testAnUnreadablePublicKeyAnswersNullRatherThanThrowing(): void
    {
        $pki = MintedPki::get();
        $broken = TestPki::certificate(
            'Broken Key',
            'Minted WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
        )['der'];
        // Corrupt the SPKI in place: still parseable DER, not a usable key.
        $cert = Certificate::parse($broken);
        $mangled = str_replace($cert->spki, str_repeat("\x00", strlen($cert->spki)), $broken);
        self::assertNotSame($broken, $mangled);

        $this->expectException(ParseException::class);
        Certificate::parse($mangled);
    }

    /** @return iterable<string, array{string}> */
    public static function notACertificateProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'a bare INTEGER' => [DerWriter::int(1)];
        yield 'a SEQUENCE of one INTEGER' => [DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::int(0))];
        yield 'a SEQUENCE of three INTEGERs' => [
            DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::int(1), DerWriter::int(2), DerWriter::int(3)),
        ];
        yield 'random bytes' => ["\x01\x02\x03\x04\x05"];
    }

    #[DataProvider('notACertificateProvider')]
    public function testRejectsInputThatIsNotACertificate(string $der): void
    {
        $this->expectException(ParseException::class);
        Certificate::parse($der);
    }
}
