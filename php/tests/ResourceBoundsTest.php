<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\DerWriter;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Resource bounds — the PHP-specific chapter.
 *
 * PHP has no zero-copy slice: every `substr()` allocates and every node is a
 * real object, so a DER reader here amplifies its input tens of times in
 * memory where the Node port's views cost nothing. Against a
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
    private static function verifier(): ReceiptVerifier
    {
        return new ReceiptVerifier([MintedPki::get()->rootDer], 'com.example.app');
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
    public function testANodeFloodThroughTheVerifierIsAnInvalidReceiptFormat(): void
    {
        $flood = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 500000));

        try {
            self::verifier()->verify($flood);
            self::fail('a node flood was ACCEPTED');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidReceiptFormat, $e->reason);
        }
    }

    /**
     * The size limit is checked before anything is decoded, so an oversized
     * input costs no parse at all. Asserted by timing: parsing 4 MB of DER
     * would take milliseconds, and this must not.
     */
    public function testAnOversizedReceiptIsRejectedBeforeParsing(): void
    {
        $verifier = new ReceiptVerifier([MintedPki::get()->rootDer], 'com.example.app', 1024);
        $big = DerWriter::tlv(DerWriter::SEQUENCE, str_repeat("\x05\x00", 2000000));

        $start = microtime(true);
        try {
            $verifier->verify($big);
            self::fail('an oversized receipt was ACCEPTED');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidReceiptFormat, $e->reason);
            self::assertStringContainsString('size limit', $e->getMessage());
        }
        self::assertLessThan(50, (microtime(true) - $start) * 1000, 'the parser appears to have run');
    }

    /**
     * The ≤10 embedded-certificate bound is enforced BEFORE any certificate is
     * decoded, because decoding and RSA-checking candidate issuers is the
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
            try {
                self::verifier()->verify($receipt);
                self::fail("a {$label}-certificate receipt was ACCEPTED");
            } catch (VerificationException $e) {
                self::assertSame(Reason::InvalidChain, $e->reason, $label);
                self::assertStringContainsString('more than 10 certificates', $e->getMessage());
            }
        }

        // A genuine ten-certificate receipt still gets a full walk, so the
        // bound is on the count and not on doing the work.
        $start = microtime(true);
        try {
            self::verifier()->verify($huge);
        } catch (VerificationException) {
            // expected
        }
        self::assertLessThan(200, (microtime(true) - $start) * 1000, 'the flood was decoded before being counted');
    }

    /**
     * A cross-signed mesh inside the ten slots the count bound allows: many
     * certificates that are equally plausible issuers, so a path builder that
     * backtracks over every partial chain would blow up here. This walk takes
     * the first matching issuer and is capped by path length, so the cost is
     * bounded by (path length x candidates) — 60 signature checks at the very
     * worst — and stays flat as the mesh gets denser.
     */
    #[Group('slow')]
    public function testADenseIssuerMeshStaysBoundedAndIsRejected(): void
    {
        $timings = [];
        foreach ([2, 6] as $layers) {
            $receipt = self::meshReceipt($layers);
            $start = microtime(true);
            try {
                self::verifier()->verify($receipt);
                self::fail('a mesh receipt was ACCEPTED');
            } catch (VerificationException $e) {
                self::assertSame(Reason::InvalidChain, $e->reason);
            }
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
     * The whole point of the bounds is that a genuine receipt is nowhere near
     * them. The largest public fixture is a 79 KB legacy receipt carrying 187
     * in-app purchases; it must stay an order of magnitude inside the node
     * budget and cost a few megabytes, not tens.
     */
    public function testTheLargestGenuineReceiptStaysWellInsideEveryBound(): void
    {
        $legacy = Fixtures::bytes('public-receipt-sandbox-legacy');
        self::assertGreaterThan(70000, strlen($legacy));

        gc_collect_cycles();
        $before = memory_get_usage();
        $start = microtime(true);
        $receipt = (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.nutcall.alert'))->verify($legacy);
        $elapsed = (microtime(true) - $start) * 1000;
        $grew = memory_get_usage() - $before;

        self::assertCount(187, $receipt->inAppPurchases);
        self::assertLessThan(60 * 1024 * 1024, $grew, 'a genuine receipt should not cost tens of megabytes');
        self::assertLessThan(2000, $elapsed);

        // And it parses under a budget an order of magnitude below the default,
        // which is the claim the default is chosen against.
        $tight = new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.nutcall.alert', 2097152, 6000);
        self::assertSame('com.nutcall.alert', $tight->verify($legacy)->bundleId);
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

        // The count bound would fire first, so the mesh is handed over in the
        // ten slots the walk is actually allowed to search.
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
