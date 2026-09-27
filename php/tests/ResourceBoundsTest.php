<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Resource bounds — the PHP-specific chapter.
 *
 * PHP has no zero-copy slice: every `substr()` allocates and every node is a
 * real object, so a DER reader here amplifies its input tens of times in
 * memory where a zero-copy port's views cost nothing. Against a
 * `php.ini-production` default `memory_limit` of 128M, that turns a megabyte
 * of attacker bytes into an out-of-memory fatal, from an input any HTTP
 * body-size limit would wave through.
 *
 * The assertions below have deliberate headroom over what was measured on
 * PHP 8.4.19 — they are regression fences, not benchmarks. What matters is
 * that they fail if a bound is removed, which is checked by asserting the
 * *rejection* as well as the cost.
 */
#[CoversNothing]
final class ResourceBoundsTest extends TestCase
{
    /** docs/design/0.7-api.md, "Bounds": the base64 receipt cap, in UTF-8 bytes. */
    private const MAX_RECEIPT_BYTES = 3145728;

    private static function verifier(): Verifier
    {
        return Verifier::create(Config::builder()->roots([MintedPki::get()->rootDer])->build());
    }

    /**
     * A megabyte of minimal two-byte nodes. Without the budget this costs
     * roughly 72 MB of parser state; with it, the parse stops almost
     * immediately.
     */
    public function testANodeFloodIsRejectedByTheBudgetBeforeItCostsMemory(): void
    {
        $flood = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 500000));
        self::assertGreaterThan(1000000, strlen($flood));

        gc_collect_cycles();
        $before = memory_get_usage();
        $start = microtime(true);
        try {
            Der::parse($flood);
            self::fail('the node budget did not fire');
        } catch (ParseException $e) {
            self::assertStringContainsString('node budget', $e->getMessage());
        }
        $elapsed = (microtime(true) - $start) * 1000;
        $grew = memory_get_usage() - $before;

        self::assertLessThan(2000, $elapsed, 'the budget should stop the parse in milliseconds');
        self::assertLessThan(16 * 1024 * 1024, $grew, 'the budget did not bound the allocation');
    }

    /** The same flood as a receipt: a reason, not a fatal. */
    public function testANodeFloodThroughTheVerifierIsMalformed(): void
    {
        $flood = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 500000));

        $result = self::verifier()->verifyReceipt(base64_encode($flood));
        self::assertFalse($result->verified(), 'a node flood was ACCEPTED');
        self::assertSame(Reason::Malformed, $result->failure?->reason);
    }

    /**
     * The size limit is checked before anything is decoded, so an oversized
     * input costs no parse at all. Asserted by timing: base64-decoding and
     * parsing several megabytes of DER would take milliseconds, and this
     * must not.
     */
    public function testAnOversizedReceiptIsRejectedBeforeParsing(): void
    {
        $verifier = self::verifier();
        $big = base64_encode(DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 2000000)));
        self::assertGreaterThan(self::MAX_RECEIPT_BYTES, strlen($big));

        $start = microtime(true);
        $result = $verifier->verifyReceipt($big);
        self::assertFalse($result->verified(), 'an oversized receipt was ACCEPTED');
        self::assertSame(Reason::TooLarge, $result->failure?->reason);
        self::assertStringContainsString('maximum accepted size', (string) $result->failure?->message);
        self::assertLessThan(50, (microtime(true) - $start) * 1000, 'the parser appears to have run');
    }

    /**
     * The <=10 embedded-certificate bound is enforced BEFORE any certificate
     * is decoded, because decoding and RSA-checking candidate issuers is the
     * expensive half. This asserts both the verdict and that rejecting a
     * flood costs about what rejecting a small receipt costs.
     */
    public function testACertificateFloodIsRejectedBeforeAnyCertificateIsDecoded(): void
    {
        $pki = MintedPki::get();
        $eleven = array_merge($pki->chain(), array_fill(0, 8, $pki->intermediateDer));
        self::assertCount(11, $eleven);

        $flooded = TestPki::receipt(MintedPki::payload(), $eleven, $pki->receiptSignerSid, $pki->receiptSignerKey);
        $huge = TestPki::receipt(
            MintedPki::payload(),
            array_fill(0, 400, $pki->intermediateDer),
            $pki->receiptSignerSid,
            $pki->receiptSignerKey,
        );

        foreach (['eleven' => $flooded, 'four hundred' => $huge] as $label => $receipt) {
            $result = self::verifier()->verifyReceipt(base64_encode($receipt));
            self::assertFalse($result->verified(), "a {$label}-certificate receipt was ACCEPTED");
            self::assertSame(Reason::Malformed, $result->failure?->reason, $label);
            self::assertStringContainsString('more than 10 certificates', (string) $result->failure?->message, $label);
        }

        // A genuine ten-certificate receipt still gets a full walk, so the
        // bound is on the count and not on doing the work.
        $start = microtime(true);
        self::verifier()->verifyReceipt(base64_encode($huge));
        self::assertLessThan(200, (microtime(true) - $start) * 1000, 'the flood was decoded before being counted');
    }

    /**
     * A cross-signed mesh inside the ten slots the count bound allows: many
     * certificates that are equally plausible issuers, so a path builder
     * that backtracks over every partial chain would blow up here. The
     * top-down walk tries only vouched-for candidates as issuers and is
     * capped by path length, so cost stays bounded and flat as the mesh
     * gets denser.
     */
    #[Group('slow')]
    public function testADenseIssuerMeshStaysBoundedAndIsRejected(): void
    {
        $timings = [];
        foreach ([2, 6] as $layers) {
            $receipt = self::meshReceipt($layers);
            $start = microtime(true);
            $result = self::verifier()->verifyReceipt(base64_encode($receipt));
            self::assertFalse($result->verified(), 'a mesh receipt was ACCEPTED');
            self::assertSame(Reason::UntrustedChain, $result->failure?->reason);
            $timings[$layers] = (microtime(true) - $start) * 1000;
        }

        self::assertLessThan(500, $timings[6], 'rejecting a dense mesh should cost milliseconds');
        self::assertLessThan(
            max(50.0, $timings[2] * 8),
            $timings[6],
            'the walk appears to backtrack: cost grew sharply with mesh density',
        );
    }

    public function testDeepButNarrowNestingIsBoundedAtTheDeclaredDepth(): void
    {
        self::assertSame(Der::TAG_SEQUENCE, Der::parse(self::nested(Der::MAX_DEPTH - 1))->tag);
        self::assertSame(Der::TAG_SEQUENCE, Der::parse(self::nested(Der::MAX_DEPTH))->tag);

        $this->expectException(ParseException::class);
        Der::parse(self::nested(Der::MAX_DEPTH + 1));
    }

    /**
     * The whole point of the bounds is that a genuine receipt is nowhere
     * near them. The largest public fixture is a 79 KB legacy receipt
     * carrying 187 in-app purchases; it must stay an order of magnitude
     * inside the node budget and cost a few megabytes, not tens.
     */
    public function testTheLargestGenuineReceiptStaysWellInsideEveryBound(): void
    {
        $legacyDer = Fixtures07::bytes('public-receipt-sandbox-legacy');
        self::assertGreaterThan(70000, strlen($legacyDer));

        gc_collect_cycles();
        $before = memory_get_usage();
        $start = microtime(true);
        $verifier = Verifier::create(Config::builder()->roots(AppleRootCerts::pinnedRoots())->build());
        $result = $verifier->verifyReceipt(base64_encode($legacyDer));
        $elapsed = (microtime(true) - $start) * 1000;
        $grew = memory_get_usage() - $before;

        self::assertTrue($result->verified());
        self::assertCount(187, $result->payload->inApp);
        self::assertLessThan(60 * 1024 * 1024, $grew, 'a genuine receipt should not cost tens of megabytes');
        self::assertLessThan(2000, $elapsed);
    }

    private static function meshReceipt(int $layers): string
    {
        $pki = MintedPki::get();
        $left = $pki->rootKey;
        $right = $pki->intermediateKey;
        $stranger = $pki->strangerKey;

        $leaf = TestPki::certificate('Mesh Leaf', 'Mesh CA 1', $stranger, $left, false, [TestPki::LEAF_OID_HEX]);
        $certificates = [$leaf['der']];
        for ($layer = 1; $layer <= $layers; ++$layer) {
            foreach ([$left, $right] as $subjectKey) {
                foreach ([$left, $right] as $issuerKey) {
                    $certificates[] = TestPki::certificate(
                        'Mesh CA ' . $layer,
                        'Mesh CA ' . ($layer + 1),
                        $subjectKey,
                        $issuerKey,
                        true,
                    )['der'];
                }
            }
        }

        // The count bound would fire first, so the mesh is handed over in
        // the ten slots the walk is actually allowed to search.
        return TestPki::receipt(
            MintedPki::payload(),
            array_slice($certificates, 0, 10),
            $leaf['sid'],
            $stranger,
        );
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
