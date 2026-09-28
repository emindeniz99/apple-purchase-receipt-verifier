<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationResult;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The pieces of {@see Verifier}'s receipt path that are specific to it and
 * not already pinned by the 311-case shared conformance suite or by
 * {@see MutationTest} / {@see HostileInputTest} / {@see ResourceBoundsTest}:
 * marker-OID/chain check ordering, signature algorithm coverage, the
 * signedAttrs branch of RFC 5652 §5.4, attribute-type boundary width, and
 * the receipt-decode-specific ASN.1 shapes.
 *
 * 0.7 removed bundle-id and device-GUID filtering from the verifier itself
 * (docs/design/0.7-api.md, "Result"): {@see ReceiptPayload} carries
 * `bundleId`, `bundleIdBytes` and `sha1Hash` and both checks are now the
 * caller's job, done after verification (the README's post-verification
 * checklist and device-hash example). `ReceiptVerifier::verifyReceiptCore`
 * does not exist either — `verifyReceipt()` is the one entry point, and it
 * never filtered by bundle id to begin with.
 */
#[CoversClass(Verifier::class)]
final class ReceiptDecodeTest extends TestCase
{
    private static function verifier(?string $root = null): Verifier
    {
        return Verifier::create(Config::builder()->roots([$root ?? MintedPki::get()->rootDer])->build());
    }

    /** @return VerificationResult<ReceiptPayload> */
    private static function verify(string $der, ?string $root = null): VerificationResult
    {
        return self::verifier($root)->verifyReceipt(base64_encode($der));
    }

    public function testVerifiesAMintedReceipt(): void
    {
        $result = self::verify(MintedPki::get()->receipt());
        self::assertTrue($result->verified());
        /** @var ReceiptPayload $receipt */
        $receipt = $result->payload;

        self::assertSame('ProductionSandbox', $receipt->receiptType);
        self::assertSame('com.example.app', $receipt->bundleId);
        self::assertSame('1.2.3', $receipt->applicationVersion);
        self::assertSame('1.0', $receipt->originalApplicationVersion);
        self::assertSame('0102030405060708', bin2hex((string) $receipt->opaqueValue));
        self::assertSame(1722945600000, $receipt->receiptCreationDateMs);
        self::assertSame([], $receipt->inApp);
        self::assertSame([], $receipt->unknownAttributes);
    }

    /**
     * On the receipt path the marker OID is checked AFTER the chain, which
     * is the opposite of the JWS path and is deliberate: a foreign chain
     * must report UNTRUSTED_CHAIN rather than leaking that its purpose was
     * wrong too.
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

        $result = self::verify($noOid);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidCertificatePurpose, $result->failure->reason);

        // Same receipt, an anchor it does not reach: the chain speaks first.
        $result = self::verify($noOid, $pki->foreignRootDer);
        self::assertFalse($result->verified());
        self::assertSame(Reason::UntrustedChain, $result->failure->reason);
    }

    /**
     * Not a key-type allowlist: an ECDSA signer verifies in 0.7 (shared case
     * receipt/verify-signer-ecdsa-p256). This pins the family check: a
     * SignerInfo whose signatureAlgorithm says rsaEncryption must come from
     * an RSA key, so an EC key under an RSA label is refused before
     * openssl_verify() is asked to reconcile the two.
     */
    public function testRejectsAnRsaLabelledSignerWhoseKeyIsEc(): void
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

        $result = self::verify($receipt);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
        self::assertStringContainsString('not RSA', $result->failure->message);
    }

    /**
     * This port refuses RSA-PSS receipt signers (php/README.md). PHP's
     * openssl_verify() has no PSS mode and the alternative is hand-written
     * EMSA-PSS on the forgery path, so a genuine PSS signature under the
     * pinned chain must fail closed as INVALID_SIGNATURE, through the
     * unsupported-algorithm refusal rather than a failed check. The shared
     * case receipt/signer-rsa-pss-does-not-crash leaves PSS port-defined.
     */
    public function testRefusesAGenuineRsaPssSigner(): void
    {
        $result = self::verify(Fixtures07::bytes('receipt-signer-rsa-pss'), Fixtures07::bytes('signer-alg-root'));
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
        self::assertStringContainsString('unsupported signature algorithm', $result->failure->message);
    }

    /** A tampered PSS signature never verifies, in any port (receipt/reject-signer-rsa-pss-tampered). */
    public function testRejectsATamperedRsaPssSigner(): void
    {
        $result = self::verify(
            Fixtures07::bytes('review-receipt-signer-rsa-pss-tampered'),
            Fixtures07::bytes('signer-alg-root'),
        );
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
    }

    /**
     * A genuinely unsupported digest OID — not MD5, which 0.7 widened
     * support to (#160; see {@see testAcceptsEveryModelledDigestAlgorithm}).
     */
    public function testRejectsAGenuinelyUnknownDigestAlgorithm(): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt(
            MintedPki::payload(),
            $pki->chain(),
            $pki->receiptSignerSid,
            null,
            '2b0601040182371514', // an arbitrary OID nothing maps to a digest
            "\x00",
        );

        $result = self::verify($receipt);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
        self::assertStringContainsString('unsupported digest', $result->failure->message);
    }

    /**
     * The guaranteed-minimum digest set 0.7 widened to (#160): MD5 through
     * SHA-512, all under
     * the same RSA PKCS#1 v1.5 signer.
     */
    public function testAcceptsEveryModelledDigestAlgorithm(): void
    {
        $pki = MintedPki::get();
        foreach ([
            TestPki::OID_MD5_HEX,
            TestPki::OID_SHA1_HEX,
            TestPki::OID_SHA256_HEX,
        ] as $digest) {
            $receipt = TestPki::receipt(
                MintedPki::payload(),
                $pki->chain(),
                $pki->receiptSignerSid,
                $pki->receiptSignerKey,
                $digest,
            );
            $result = self::verify($receipt);
            self::assertTrue($result->verified(), $digest);
            self::assertSame('com.example.app', $result->payload->bundleId, $digest);
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

        $result = self::verify($swapped);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
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

        $result = self::verify($receipt);
        self::assertFalse($result->verified());
        self::assertSame(Reason::Malformed, $result->failure->reason);
        self::assertStringContainsString('signer certificate not embedded', $result->failure->message);
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

        $result = self::verify($receipt);
        self::assertFalse($result->verified());
        self::assertSame(Reason::Malformed, $result->failure->reason);
    }

    public function testRejectsTrailingBytesAfterTheCmsBlob(): void
    {
        $result = self::verify(MintedPki::get()->receipt() . "\x00\x00");
        self::assertFalse($result->verified());
        self::assertSame(Reason::Malformed, $result->failure->reason);
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
        $result = self::verify($good);
        self::assertTrue($result->verified());
        self::assertSame('com.example.app', $result->payload->bundleId);

        $wrongDigest = TestPki::receipt(
            $payload,
            $pki->chain(),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
            TestPki::OID_SHA256_HEX,
            null,
            self::signedAttrs(str_repeat("\x00", 32)),
        );
        $result = self::verify($wrongDigest);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
        self::assertStringContainsString('messageDigest attribute does not match', $result->failure->message);

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
        $result = self::verify($mistagged);
        self::assertFalse($result->verified());
        self::assertSame(Reason::InvalidSignature, $result->failure->reason);
    }

    /** @return iterable<string, array{list<int>}> */
    public static function attributeTypeOverflowProvider(): iterable
    {
        // 2^31 is the first attribute type outside the signed 32-bit space.
        // The leading 0x00 keeps it positive, so this is genuinely
        // 2147483648 and not a negative INTEGER. All three are a malformed
        // top-level attribute SET, so the whole payload is unreadable.
        yield '2^31' => [[0x00, 0x80, 0, 0, 0]];
        yield 'a leading byte of 0x80 (negative)' => [[0x80]];
        yield 'nine bytes' => [[0, 0, 0, 0, 0, 0, 0, 0, 1]];
    }

    /** @param list<int> $typeBytes */
    #[DataProvider('attributeTypeOverflowProvider')]
    public function testAttributeTypesAreBoundedToTheSigned32BitSpace(array $typeBytes): void
    {
        $result = self::verify(self::receiptWithAttributeType($typeBytes));
        self::assertFalse($result->verified());
        self::assertSame(Reason::UnreadablePayload, $result->failure->reason);
    }

    /**
     * The other side of the same boundary: 2^31-1 is the largest
     * representable type and must PARSE. A comparison one step wider would
     * reject a legal attribute, and no negative test can catch that.
     */
    public function testTheLargestRepresentableAttributeTypeIsAccepted(): void
    {
        $result = self::verify(self::receiptWithAttributeType([0x7f, 0xff, 0xff, 0xff]));
        self::assertTrue($result->verified());

        self::assertArrayHasKey(2147483647, $result->payload->unknownAttributes);
        self::assertSame([''], $result->payload->unknownAttributes[2147483647]);
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

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        $purchases = $result->payload->inApp;
        self::assertCount(1, $purchases);
        self::assertSame(2147483648, $purchases[0]->webOrderLineItemId);
    }

    /**
     * The strict grammar (`YYYY-MM-DDTHH:MM:SSZ` only, no offset) is
     * exhaustively covered by the conformance suite's `receipt/date-grammar`
     * and `receipt/unreadable-creation-date-decodes-to-null` families. This
     * pins the one property those cases do not: a date that carries an
     * OFFSET rather than `Z` reads as absent — normalising it to UTC, as
     * 0.6 did via `DateTimeImmutable`, is no longer the behaviour.
     */
    public function testAnOffsetDateDoesNotParseRatherThanBeingNormalised(): void
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

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        self::assertNull($result->payload->receiptCreationDateMs);
        // Kept raw: the undecoded octet-string content, DER tag included —
        // not the decoded text.
        self::assertSame(
            [DerWriter::tlv(DerWriter::IA5_STRING, '2024-08-06T14:00:00+02:00')],
            $result->payload->unknownAttributes[12],
        );
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

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        self::assertNull($result->payload->expirationDateMs);
    }

    /**
     * A known attribute whose VALUE content does not match its expected
     * ASN.1 shape is a per-attribute failure, not a whole-payload one: the
     * typed field stays null and the receipt still verifies.
     */
    public function testABundleIdThatIsNotAnAsn1StringLeavesTheFieldNullButStillVerifies(): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::attribute(2, DerWriter::int(1)),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        );
        $receipt = TestPki::receipt($payload, $pki->chain(), $pki->receiptSignerSid, $pki->receiptSignerKey);

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        self::assertNull($result->payload->bundleId);
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

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        self::assertSame(["\x01\x02\x03", "\x04\x05\x06"], $result->payload->unknownAttributes[9999], 'a type may legitimately repeat');
    }

    /** @return iterable<string, array{string}> */
    public static function malformedTopLevelAttributeSetProvider(): iterable
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

    /**
     * Every shape here breaks the top-level attribute SET's own structure,
     * as opposed to one known attribute's value content — so the whole
     * payload is unreadable, not just one field (contrast
     * {@see testABundleIdThatIsNotAnAsn1StringLeavesTheFieldNullButStillVerifies}).
     */
    #[DataProvider('malformedTopLevelAttributeSetProvider')]
    public function testRejectsAMalformedTopLevelAttributeSet(string $payload): void
    {
        $pki = MintedPki::get();
        $receipt = TestPki::receipt($payload, $pki->chain(), $pki->receiptSignerSid, $pki->receiptSignerKey);

        $result = self::verify($receipt);
        self::assertFalse($result->verified());
        self::assertSame(Reason::UnreadablePayload, $result->failure->reason);
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

        $result = self::verify($receipt);
        self::assertTrue($result->verified());
        self::assertSame('com.example.app', $result->payload->bundleId);
    }

    /**
     * Legacy receipt ids: app-level attributes 1 (app item id), 15
     * (download id) and 16 (version external identifier), and in-app
     * attribute 1713 (is trial period). None is on Apple's archived Receipt
     * Fields chapter; their meaning was established by comparing a genuine
     * production receipt with Apple's own verifyReceipt answer for it. The
     * download id is 2^63-1, a nineteen-digit, eight-byte integer an
     * IEEE-754 double rounds to 2^63: asserting the exact digits, including
     * through a string cast, proves PHP's 64-bit int carries it rather than
     * rounding it through a float.
     */
    public function testLegacyReceiptIdsAreDecoded(): void
    {
        $result = self::verify(Fixtures07::bytes('receipt-ids'), Fixtures07::bytes('receipt-ids-root'));
        self::assertTrue($result->verified());
        $receipt = $result->payload;

        self::assertSame(1234567890, $receipt->appItemId);
        self::assertSame(9223372036854775807, $receipt->downloadId);
        self::assertSame('9223372036854775807', (string) $receipt->downloadId);
        self::assertSame(456789012, $receipt->versionExternalIdentifier);

        $coins = self::purchase($receipt, 'com.example.app.coins100');
        $vip = self::purchase($receipt, 'com.example.app.vip');
        self::assertFalse($coins->isTrialPeriod);
        self::assertTrue($vip->isTrialPeriod);

        // The four types leave unknownAttributes; the fixture's other
        // unknown attribute, 9999, must still be there.
        self::assertArrayNotHasKey(1, $receipt->unknownAttributes);
        self::assertArrayNotHasKey(15, $receipt->unknownAttributes);
        self::assertArrayNotHasKey(16, $receipt->unknownAttributes);
        self::assertArrayHasKey(9999, $receipt->unknownAttributes);
        self::assertArrayNotHasKey(1713, $coins->unknownAttributes);
        self::assertArrayNotHasKey(1713, $vip->unknownAttributes);
    }

    /**
     * Absent and present-but-zero are different answers: a receipt that
     * carries none of the four attributes reports them null rather than a
     * default.
     */
    public function testLegacyReceiptIdsAreAbsentWhenTheReceiptDoesNotCarryThem(): void
    {
        $result = self::verify(Fixtures07::bytes('receipt'), Fixtures07::bytes('receipt-root'));
        self::assertTrue($result->verified());
        $receipt = $result->payload;

        self::assertNull($receipt->appItemId);
        self::assertNull($receipt->downloadId);
        self::assertNull($receipt->versionExternalIdentifier);
        self::assertNull(self::purchase($receipt, 'com.example.app.coins100')->isTrialPeriod);
    }

    private static function purchase(ReceiptPayload $receipt, string $productId): InAppPurchase
    {
        foreach ($receipt->inApp as $purchase) {
            if ($purchase->productId === $productId) {
                return $purchase;
            }
        }
        self::fail("no in-app purchase with product id {$productId}");
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
