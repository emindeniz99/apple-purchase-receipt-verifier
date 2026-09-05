<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\AppReceipt;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ReceiptVerifier::class)]
final class ReceiptVerifierTest extends TestCase
{
    private const GUID = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";

    private function verifier(?string $root = null, string $bundleId = 'com.example.app'): ReceiptVerifier
    {
        return new ReceiptVerifier([$root ?? MintedPki::get()->rootDer], $bundleId);
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

    public function testVerifiesAMintedReceipt(): void
    {
        $receipt = $this->verifier()->verify(MintedPki::get()->receipt());

        self::assertSame('ProductionSandbox', $receipt->receiptType);
        self::assertSame('com.example.app', $receipt->bundleId);
        self::assertSame('1.2.3', $receipt->appVersion);
        self::assertSame('1.0', $receipt->originalAppVersion);
        self::assertSame('0102030405060708', bin2hex((string) $receipt->opaqueValue));
        self::assertSame('2024-08-06T12:00:00+00:00', $receipt->creationDate?->format('c'));
        self::assertSame([], $receipt->inAppPurchases);
        self::assertSame([], $receipt->unknownAttributes);
    }

    /**
     * C6: every input form must be reachable with and without the device
     * GUID. PHP gets there with one optional parameter, but the 2×2 still has
     * to be exercised or three of its four corners are untested.
     */
    public function testTheDeviceGuidMatrixCoversBothInputForms(): void
    {
        $pki = MintedPki::get();
        // Attribute 5 covers the raw attribute VALUE bytes of the bundle id
        // — the encoded UTF8String, not the decoded text and not the whole
        // SEQUENCE. Getting that wrong is the usual reason a correct GUID
        // still produces DEVICE_HASH_MISMATCH.
        $bundleValue = DerWriter::tlv(DerWriter::UTF8_STRING, 'com.example.app');
        $payload = TestPki::payload(
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::attribute(4, "\x01\x02\x03\x04"),
            TestPki::attribute(5, sha1(self::GUID . "\x01\x02\x03\x04" . $bundleValue, true)),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        );
        $der = $pki->receipt($payload);
        $base64 = base64_encode($der);

        self::assertSame('com.example.app', $this->verifier()->verify($der)->bundleId);
        self::assertSame('com.example.app', $this->verifier()->verify($base64)->bundleId);
        self::assertSame('com.example.app', $this->verifier()->verify($der, self::GUID)->bundleId);
        self::assertSame('com.example.app', $this->verifier()->verify($base64, self::GUID)->bundleId);

        $wrongGuid = "\x00" . substr(self::GUID, 1);
        $this->assertReason(Reason::DeviceHashMismatch, fn () => $this->verifier()->verify($der, $wrongGuid));
        // The most likely misuse: passing the GUID as hex text rather than raw bytes.
        $hexGuid = bin2hex(self::GUID);
        $this->assertReason(Reason::DeviceHashMismatch, fn () => $this->verifier()->verify($der, $hexGuid));
    }

    public function testADeviceGuidCheckOnAReceiptLackingTheAttributesFailsClosed(): void
    {
        // The minted receipt carries attribute 4 but no attribute 5.
        $this->assertReason(
            Reason::DeviceHashMismatch,
            fn () => $this->verifier()->verify(MintedPki::get()->receipt(), self::GUID),
        );
    }

    public function testRejectsAWrongBundleId(): void
    {
        $this->assertReason(
            Reason::WrongBundleId,
            fn () => $this->verifier(null, 'com.other.app')->verify(MintedPki::get()->receipt()),
        );
    }

    /**
     * C4: `verifyReceiptCore` is public, and documented as skipping the
     * bundle-id check. The endpoint needs it; the alternative Java and Swift
     * actually ship is a magic-string bundle id inside a security library.
     */
    public function testVerifyReceiptCoreIsPublicAndSkipsTheBundleIdCheck(): void
    {
        $pki = MintedPki::get();
        $receipt = ReceiptVerifier::verifyReceiptCore($pki->receipt(), [$pki->rootDer]);

        self::assertInstanceOf(AppReceipt::class, $receipt);
        self::assertSame('com.example.app', $receipt->bundleId, 'the caller checks this itself');

        // It still enforces everything else.
        $this->assertReason(
            Reason::InvalidChain,
            static fn () => ReceiptVerifier::verifyReceiptCore($pki->receipt(), [$pki->foreignRootDer]),
        );
    }

    /**
     * On the receipt path the marker OID is checked AFTER the chain, which is
     * the opposite of the JWS path and is deliberate: a foreign chain must
     * report INVALID_CHAIN rather than leaking that its purpose was wrong too.
     */
    public function testTheSignerMarkerOidIsCheckedAfterTheChain(): void
    {
        $pki = MintedPki::get();
        $noOid = TestPki::receipt(
            MintedPki::payload(),
            [$pki->receiptSignerNoOidDer, $pki->intermediateDer, $pki->rootDer],
            $pki->receiptSignerNoOidSid,
            $pki->receiptSignerKey,
        );

        $this->assertReason(Reason::InvalidCertificatePurpose, fn () => $this->verifier()->verify($noOid));
        // Same receipt, an anchor it does not reach: the chain speaks first.
        $this->assertReason(
            Reason::InvalidChain,
            fn () => $this->verifier($pki->foreignRootDer)->verify($noOid),
        );
    }

    public function testRejectsASignerWhoseKeyIsNotRsa(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            MintedPki::payload(),
            [$pki->ecSignerDer, $pki->intermediateDer, $pki->rootDer],
            $pki->ecSignerSid,
            null,
            TestPki::OID_SHA256_HEX,
            "\x00",
        );

        $e = $this->assertReason(Reason::InvalidSignature, fn () => $this->verifier()->verify($receipt));
        self::assertStringContainsString('not RSA', $e->getMessage());
    }

    public function testRejectsAnUnsupportedDigestAlgorithm(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            MintedPki::payload(),
            $pki->chain(),
            $pki->receiptSignerSid,
            null,
            TestPki::OID_MD5_HEX,
            "\x00",
        );

        $this->assertReason(Reason::InvalidReceiptFormat, fn () => $this->verifier()->verify($receipt));
    }

    public function testAcceptsBothDigestsAppleUses(): void
    {
        $pki = MintedPki::get();
        foreach ([TestPki::OID_SHA1_HEX, TestPki::OID_SHA256_HEX] as $digest) {
            $receipt = TestPki::receipt(
                MintedPki::payload(),
                $pki->chain(),
                $pki->receiptSignerSid,
                $pki->receiptSignerKey,
                $digest,
            );
            self::assertSame('com.example.app', $this->verifier()->verify($receipt)->bundleId);
        }
    }

    public function testRejectsATamperedPayloadUnderAGenuineSignature(): void
    {
        $pki = MintedPki::get();
        $forged = TestPki::receipt(
            MintedPki::payload('2024-08-06T12:00:00Z'),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );
        // Same everything, a different payload: the signature no longer covers it.
        $swapped = TestPki::receipt(
            TestPki::payload(
                TestPki::utf8Attribute(0, 'Production'),
                TestPki::utf8Attribute(2, 'com.example.app'),
                TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
            ),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
            TestPki::OID_SHA1_HEX,
            self::signatureOf($forged),
        );

        $this->assertReason(Reason::InvalidSignature, fn () => $this->verifier()->verify($swapped));
    }

    public function testRejectsASignerInfoNamingACertificateThatIsNotEmbedded(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            MintedPki::payload(),
            [$pki->intermediateDer, $pki->rootDer],
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        $e = $this->assertReason(Reason::InvalidReceiptFormat, fn () => $this->verifier()->verify($receipt));
        self::assertStringContainsString('signer certificate not embedded', $e->getMessage());
    }

    /**
     * RFC 5652 §5.4: when signedAttrs are present the signature covers them
     * re-encoded as an explicit SET, and the messageDigest attribute must
     * match the content. Both halves get their own negative case, because
     * signing the `[0]`-tagged bytes as they appear on the wire is the
     * classic mistake and it verifies nothing.
     */
    public function testVerifiesTheSignedAttributesBranch(): void
    {
        $pki = MintedPki::get();
        $payload = MintedPki::payload();
        $attrs = self::signedAttrs(hash('sha256', $payload, true));

        $good = TestPki::receipt(
            $payload,
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
            TestPki::OID_SHA256_HEX,
            null,
            $attrs,
        );
        self::assertSame('com.example.app', $this->verifier()->verify($good)->bundleId);

        $wrongDigest = TestPki::receipt(
            $payload,
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
            TestPki::OID_SHA256_HEX,
            null,
            self::signedAttrs(str_repeat("\x00", 32)),
        );
        $e = $this->assertReason(Reason::InvalidSignature, fn () => $this->verifier()->verify($wrongDigest));
        self::assertStringContainsString('messageDigest attribute does not match', $e->getMessage());

        // Signed over the [0]-tagged bytes instead of the SET re-encoding.
        openssl_sign($attrs, $wrong, $pki->receiptSignerKey, OPENSSL_ALGO_SHA256);
        $mistagged = TestPki::receipt(
            $payload,
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
            TestPki::OID_SHA256_HEX,
            Shape::asString($wrong, 'openssl_sign output'),
            $attrs,
        );
        $this->assertReason(Reason::InvalidSignature, fn () => $this->verifier()->verify($mistagged));
    }

    /** @return iterable<string, array{list<int>, Reason}> */
    public static function attributeTypeProvider(): iterable
    {
        // 2^31 is the first attribute type outside the signed 32-bit space.
        // The leading 0x00 keeps it positive, so this is genuinely 2147483648
        // and not a negative INTEGER.
        yield '2^31' => [[0x00, 0x80, 0, 0, 0], Reason::InvalidReceiptFormat];
        yield 'a leading byte of 0x80 (negative)' => [[0x80], Reason::InvalidReceiptFormat];
        yield 'nine bytes' => [[0, 0, 0, 0, 0, 0, 0, 0, 1], Reason::InvalidReceiptFormat];
    }

    /** @param list<int> $typeBytes */
    #[DataProvider('attributeTypeProvider')]
    public function testAttributeTypesAreBoundedToTheSigned32BitSpace(array $typeBytes, Reason $expected): void
    {
        $this->assertReason($expected, fn () => $this->verifier()->verify(self::receiptWithAttributeType($typeBytes)));
    }

    /**
     * The other side of the same boundary: 2^31-1 is the largest
     * representable type and must PARSE. A comparison one step wider would
     * reject a legal attribute, and no negative test can catch that.
     */
    public function testTheLargestRepresentableAttributeTypeIsAccepted(): void
    {
        $receipt = self::receiptWithAttributeType([0x7f, 0xff, 0xff, 0xff]);
        $unknown = $this->verifier()->verify($receipt)->unknownAttributes;

        self::assertArrayHasKey(2147483647, $unknown);
        self::assertSame([''], $unknown[2147483647]);
    }

    /** @param list<int> $typeBytes */
    private static function receiptWithAttributeType(array $typeBytes): string
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::tlv(DerWriter::INTEGER, implode('', array_map(chr(...), $typeBytes))),
                DerWriter::int(1),
                DerWriter::tlv(DerWriter::OCTET_STRING),
            ),
        );

        return TestPki::receipt($payload, $pki->chain(), $pki->receiptSignerSid, $pki->receiptSignerKey);
    }

    /**
     * The 32-bit cap is on the attribute TYPE only. `web_order_line_item_id`
     * is genuinely a 7-byte integer, so the cap must not leak onto values.
     */
    public function testAttributeValuesKeepTheWiderRange(): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
            TestPki::attribute(17, TestPki::payload(
                TestPki::utf8Attribute(1702, 'com.example.app.vip'),
                // 2^31, well past the type cap, as a VALUE.
                TestPki::attribute(1711, DerWriter::tlv(DerWriter::INTEGER, "\x00\x80\x00\x00\x00")),
            )),
        );
        $receipt = TestPki::receipt($payload, $pki->chain(), $pki->receiptSignerSid, $pki->receiptSignerKey);

        $purchases = $this->verifier()->verify($receipt)->inAppPurchases;
        self::assertCount(1, $purchases);
        self::assertSame(2147483648, $purchases[0]->webOrderLineItemId);
    }

    /** @return iterable<string, array{string}> */
    public static function badDateProvider(): iterable
    {
        yield 'no timezone designator' => ['2024-08-06T12:00:00'];
        yield 'rolled-over components' => ['2020-13-45T99:99:99Z'];
        yield 'day 31 of February' => ['2020-02-31T00:00:00Z'];
        yield 'trailing junk' => ['2024-08-06T12:00:00Zjunk'];
        yield 'a date only' => ['2024-08-06'];
        yield 'an epoch number' => ['1722945600'];
    }

    /**
     * `new DateTimeImmutable()` ROLLS OVER nonsense rather than failing:
     * `2020-13-45T99:99:99Z` becomes 2021-02-18. Since this date is the
     * instant the chain's validity is judged at, a rollover is a security
     * bug, not a cosmetic one.
     */
    #[DataProvider('badDateProvider')]
    public function testRejectsAnUnparseableOrRolledOverCreationDate(string $text): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            TestPki::payload(TestPki::dateAttribute(12, $text)),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        $this->assertReason(Reason::InvalidReceiptFormat, fn () => $this->verifier()->verify($receipt));
    }

    public function testAnEmptyDateAttributeMeansAbsentWhichRealReceiptsDo(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            TestPki::payload(
                TestPki::utf8Attribute(2, 'com.example.app'),
                TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
                TestPki::dateAttribute(21, ''),
            ),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        self::assertNull($this->verifier()->verify($receipt)->expirationDate);
    }

    public function testAcceptsAnOffsetDateAndNormalisesItToUtc(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            TestPki::payload(
                TestPki::utf8Attribute(2, 'com.example.app'),
                TestPki::dateAttribute(12, '2024-08-06T14:00:00+02:00'),
            ),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        self::assertSame('2024-08-06T12:00:00+00:00', $this->verifier()->verify($receipt)->creationDate?->format('c'));
    }

    public function testExposesUnmodelledAttributesRawAndUndecoded(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            TestPki::payload(
                TestPki::utf8Attribute(2, 'com.example.app'),
                TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
                TestPki::attribute(9999, "\x01\x02\x03"),
                TestPki::attribute(9999, "\x04\x05\x06"),
            ),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        $unknown = $this->verifier()->verify($receipt)->unknownAttributes;
        self::assertSame(["\x01\x02\x03", "\x04\x05\x06"], $unknown[9999], 'a type may legitimately repeat');
    }

    public function testAcceptsAPayloadDoubleWrappedInAnOctetString(): void
    {
        $pki = MintedPki::get();
        $inner = TestPki::payload(
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        );
        $receipt = TestPki::receipt(
            DerWriter::tlv(DerWriter::OCTET_STRING, $inner),
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        self::assertSame('com.example.app', $this->verifier()->verify($receipt)->bundleId);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedPayloadProvider(): iterable
    {
        yield 'a SEQUENCE rather than a SET' => [
            DerWriter::tlv(DerWriter::SEQUENCE, TestPki::dateAttribute(12, '2024-08-06T12:00:00Z')),
        ];
        yield 'an attribute of two fields' => [
            DerWriter::tlv(DerWriter::SET, DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::int(12), DerWriter::int(1))),
        ];
        yield 'an attribute whose type is not an INTEGER' => [
            DerWriter::tlv(DerWriter::SET, DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::tlv(DerWriter::UTF8_STRING, '12'),
                DerWriter::int(1),
                DerWriter::tlv(DerWriter::OCTET_STRING),
            )),
        ];
        yield 'an attribute whose value is not an OCTET STRING' => [
            DerWriter::tlv(DerWriter::SET, DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::int(12),
                DerWriter::int(1),
                DerWriter::int(0),
            )),
        ];
        yield 'a bundle id that is not an ASN.1 string' => [
            DerWriter::tlv(DerWriter::SET, TestPki::attribute(2, DerWriter::int(1))),
        ];
        yield 'an attribute type INTEGER of 40 bytes' => [
            DerWriter::tlv(DerWriter::SET, DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::tlv(DerWriter::INTEGER, "\x01" . str_repeat("\x00", 39)),
                DerWriter::int(1),
                DerWriter::tlv(DerWriter::OCTET_STRING),
            )),
        ];
        yield 'not ASN.1 at all' => ['not asn.1'];
    }

    #[DataProvider('malformedPayloadProvider')]
    public function testRejectsAMalformedAttributeSet(string $payload): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt($payload, $pki->chain(), $pki->receiptSignerSid, $pki->receiptSignerKey);

        $this->assertReason(Reason::InvalidReceiptFormat, fn () => $this->verifier()->verify($receipt));
    }

    public function testRejectsTrailingBytesAfterTheCmsBlob(): void
    {
        $this->assertReason(
            Reason::InvalidReceiptFormat,
            fn () => $this->verifier()->verify(MintedPki::get()->receipt() . "\x00\x00"),
        );
    }

    public function testRejectsAnUnparseableEmbeddedCertificate(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            MintedPki::payload(),
            [$pki->receiptSignerDer, "\x30\x03\x02\x01\x00"],
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        $this->assertReason(Reason::InvalidReceiptFormat, fn () => $this->verifier()->verify($receipt));
    }

    /**
     * S13: what the caller gets back is a copy. PHP strings are immutable
     * values, so this is a property of the language rather than of a defensive
     * clone — but it is exactly the property the other ports had to write code
     * for, so it is worth an assertion rather than a comment.
     */
    public function testByteFieldsHandedBackAreIndependentValues(): void
    {
        $der = MintedPki::get()->receipt();
        $receipt = $this->verifier()->verify($der);
        $opaque = $receipt->opaqueValue;

        $mutated = $der;
        $mutated[0] = "\x00";
        $copy = (string) $receipt->opaqueValue;
        $copy[0] = "\xff";

        self::assertSame($opaque, $receipt->opaqueValue);
        self::assertSame('0102030405060708', bin2hex((string) $receipt->opaqueValue));
    }

    private static function signedAttrs(string $digest): string
    {
        return DerWriter::tlv(
            DerWriter::CONTEXT_0,
            DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid(TestPki::OID_MESSAGE_DIGEST_HEX),
                DerWriter::tlv(DerWriter::SET, DerWriter::tlv(DerWriter::OCTET_STRING, $digest)),
            ),
        );
    }

    /** Pulls the SignerInfo signature out of a built receipt, for re-use in a forgery. */
    private static function signatureOf(string $receipt): string
    {
        $offset = strrpos($receipt, "\x04\x82\x01\x00");
        self::assertNotFalse($offset, 'expected a 256-byte SignerInfo signature');

        return substr($receipt, $offset + 4, 256);
    }
}
