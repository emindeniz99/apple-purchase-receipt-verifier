<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\ConfigBuilder;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Failure;
use EminDeniz99\ApplePurchaseReceiptVerifier\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\JsonPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FakeTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Outcome;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\InputTooLargeException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ServerProcessException;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationResult;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use Error;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * The public API surface, and the invariants that are not about verifying
 * anything: the error vocabulary, the value objects, misconfiguration, and
 * the shape of the source tree itself.
 */
#[CoversNothing]
final class ApiShapeTest extends TestCase
{
    /**
     * The eight reasons, read out of `fixtures/cases.schema.json` rather
     * than restated here — a typo in a case name, or a ninth reason added
     * without a cross-port change, fails here. 0.7 has a single unified
     * vocabulary (docs/design/0.7-api.md, "Result"): every path returns a
     * {@see VerificationResult}, so there is no separate "thrown" versus
     * "result-only" split the way 0.6's schema had one.
     */
    public function testTheReasonVocabularyIsExactlyTheOneTheSchemaDefines(): void
    {
        /** @var array{'$defs': array{reason: array{enum: list<string>}}} $schema */
        $schema = json_decode(
            (string) file_get_contents(Fixtures07::directory() . '/cases.schema.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );
        $expected = $schema['$defs']['reason']['enum'];
        $actual = array_map(static fn (Reason $r): string => $r->value, Reason::cases());
        sort($expected);
        sort($actual);

        self::assertCount(8, $schema['$defs']['reason']['enum']);
        self::assertSame($expected, $actual, 'the Reason vocabulary drifted from the schema');
    }

    /** Reading a reason must never mean parsing a message. */
    public function testAReasonRoundTripsThroughItsCanonicalToken(): void
    {
        foreach (Reason::cases() as $reason) {
            self::assertSame($reason, Reason::from($reason->value));
            self::assertMatchesRegularExpression('/^[A-Z][A-Z_]+[A-Z]$/', $reason->value);
        }
    }

    /**
     * The schema's wire vocabulary is SCREAMING_SNAKE (`PRODUCTION`,
     * `SANDBOX`); {@see Environment}'s own backing values are Title Case
     * (`Production`, `Sandbox`, matching the receipt/JWS claim spellings it
     * also parses). The two vocabularies are related by the conformance
     * harness's own mapping, not by string equality, so this checks case
     * count and coverage rather than raw backing values.
     */
    public function testTheEnvironmentVocabularyIsExactlyTheOneTheSchemaDefines(): void
    {
        /** @var array{'$defs': array{endpointConfig: array{properties: array{environment: array{enum: list<string>}}}}} $schema */
        $schema = json_decode(
            (string) file_get_contents(Fixtures07::directory() . '/cases.schema.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );

        $expected = $schema['$defs']['endpointConfig']['properties']['environment']['enum'];
        sort($expected);
        self::assertSame(['PRODUCTION', 'SANDBOX'], $expected);
        self::assertCount(count($expected), Environment::cases());

        foreach ($expected as $wire) {
            $mapped = match ($wire) {
                'PRODUCTION' => Environment::Production,
                'SANDBOX' => Environment::Sandbox,
            };
            self::assertInstanceOf(Environment::class, $mapped);
        }
    }

    /**
     * A {@see VerificationResult} carries exactly one of payload and
     * failure; constructing it any other way is a programming error, not a
     * verdict about a payload.
     */
    public function testAVerificationResultRequiresExactlyOneOfPayloadAndFailure(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new VerificationResult();
    }

    public function testAVerificationResultCannotCarryBoth(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new VerificationResult(payload: 'x', failure: new Failure(Reason::Malformed, 'x'));
    }

    /** @return iterable<string, array{callable(): mixed}> */
    public static function misconfigurationProvider(): iterable
    {
        yield 'an empty-string root' => [
            static fn () => Verifier::create(Config::builder()->roots([''])->build(), FakeTransport::answering('{}')),
        ];
        yield 'a non-string root' => [
            /** @phpstan-ignore-next-line deliberate misuse */
            static fn () => Verifier::create(Config::builder()->roots([123])->build(), FakeTransport::answering('{}')),
        ];
    }

    /**
     * Misconfiguration is a programming error, not a verdict about a
     * payload: it is a different type (`InvalidArgumentException`) from
     * anything `VerificationResult` carries, so a caller who only checks
     * `$result->verified()` cannot mistake its own bug for a rejected
     * receipt.
     *
     * @param callable(): mixed $construct
     */
    #[DataProvider('misconfigurationProvider')]
    public function testMisconfigurationRaisesAnArgumentErrorNotAVerdict(callable $construct): void
    {
        $this->expectException(InvalidArgumentException::class);
        $construct();
    }

    /** @return iterable<string, array{class-string}> */
    public static function publicClassProvider(): iterable
    {
        foreach ([
            Verifier::class, Config::class, ConfigBuilder::class,
            ReceiptPayload::class, InAppPurchase::class, JsonPayload::class,
            VerificationResult::class, Failure::class, Reason::class, Environment::class,
            AppleRootCerts::class, SystemClock::class,
            CliTransport::class, HttpTransport::class,
            InputTooLargeException::class, ModuleFaultException::class, ServerProcessException::class,
        ] as $class) {
            yield $class => [$class];
        }
    }

    /**
     * Every public class is final (enums are implicitly final). A subclass
     * of the verifier or of a value object is a way to produce a
     * partially-verified result that still passes an `instanceof` check.
     *
     * @param class-string $class
     */
    #[DataProvider('publicClassProvider')]
    public function testEveryPublicClassIsFinal(string $class): void
    {
        self::assertTrue((new ReflectionClass($class))->isFinal(), $class . ' is not final');
    }

    /**
     * No serialization gadget surface: nothing defines the magic methods an
     * `unserialize()` chain would reach for.
     *
     * @param class-string $class
     */
    #[DataProvider('publicClassProvider')]
    public function testNoClassDefinesASerializationGadget(string $class): void
    {
        $reflection = new ReflectionClass($class);
        // The two transports declare __destruct to delete a roots file and close a curl handle; nothing else may.
        $magics = ['__wakeup', '__unserialize', '__call', '__get', '__set', '__invoke'];
        if (!in_array($class, [CliTransport::class, HttpTransport::class], true)) {
            $magics[] = '__destruct';
        }
        foreach ($magics as $magic) {
            $declared = $reflection->hasMethod($magic)
                && $reflection->getMethod($magic)->getDeclaringClass()->getName() === $class;
            self::assertFalse($declared, $class . ' declares ' . $magic . '()');
        }
    }

    public function testValueObjectsAreReadOnly(): void
    {
        $result = self::verifiedReceipt();

        $this->expectException(Error::class);
        $this->expectExceptionMessageMatches('/readonly/');
        /** @phpstan-ignore-next-line deliberate misuse */
        $result->payload->bundleId = 'com.attacker.app';
    }

    public function testAVerifiedReceiptSurvivesASerializationRoundTrip(): void
    {
        $receipt = Outcome::payload(self::verifiedReceipt());

        /** @var ReceiptPayload $restored */
        $restored = unserialize(serialize($receipt));

        self::assertEquals($receipt, $restored);
        self::assertSame($receipt->bundleId, $restored->bundleId);
        self::assertSame($receipt->receiptCreationDateMs, $restored->receiptCreationDateMs);
    }

    public function testEverySourceFileDeclaresStrictTypes(): void
    {
        $files = self::sourceFiles();
        self::assertNotEmpty($files);
        foreach ($files as $file) {
            self::assertStringContainsString(
                'declare(strict_types=1);',
                (string) file_get_contents($file),
                basename($file) . ' does not declare strict types',
            );
        }
    }

    /**
     * The reason code is the entire observability surface. No logging, no
     * metrics, no callbacks, and nothing that writes to output.
     */
    public function testTheLibraryNeverWritesAnywhere(): void
    {
        foreach (self::sourceFiles() as $file) {
            $code = '';
            foreach (token_get_all((string) file_get_contents($file)) as $token) {
                if (is_array($token)) {
                    if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                        continue;
                    }
                    $code .= $token[1];
                    continue;
                }
                $code .= $token;
            }
            foreach (['error_log', 'trigger_error', 'var_dump', 'print_r', 'syslog', 'echo ', 'printf('] as $writer) {
                self::assertStringNotContainsString($writer, $code, basename($file) . ' writes output');
            }
        }
    }

    /**
     * 64-bit ids and epoch-millisecond dates are load-bearing throughout
     * this library (docs/design/0.7-api.md's port table: "64-bit ids =
     * int"), so `Verifier::create()` must refuse a 32-bit build rather than
     * silently letting `json_decode` degrade a date past `PHP_INT_MAX` to a
     * float. This machine's PHP is 64-bit, so the guard cannot be exercised
     * by actually calling `create()`; this pins its presence in the source
     * instead, the same way {@see testTheLibraryNeverWritesAnywhere} pins an
     * absence.
     */
    public function testCreateRefusesA32BitBuild(): void
    {
        $source = (string) file_get_contents(__DIR__ . '/../src/Verifier.php');

        self::assertMatchesRegularExpression(
            '/PHP_INT_SIZE\s*<\s*8/',
            $source,
            'Verifier::create() must guard against a 32-bit PHP build',
        );
    }

    /**
     * The compiled-in roots must be byte-identical to `php/certs/`, which CI
     * separately diffs against the repository-root `certs/`. Otherwise the
     * package could ship trust anchors nobody reviewed.
     */
    public function testTheCompiledInRootsMatchTheCheckedCopy(): void
    {
        $dir = __DIR__ . '/../certs';
        $files = ['AppleIncRootCertificate.cer', 'AppleRootCA-G2.cer', 'AppleRootCA-G3.cer'];
        $onDisk = array_map(static fn (string $f): string => (string) file_get_contents($dir . '/' . $f), $files);

        self::assertSame($onDisk, AppleRootCerts::pinnedRoots());
    }

    /**
     * All three published Apple roots, one shared set for both verification
     * paths in 0.7 (docs/design/0.7-api.md, "Setup"). Do not "optimise" the
     * set down — Apple documents the JWS chain as ending in "an Apple root
     * certificate" without naming one.
     */
    public function testThePinnedRootsCarryAllThreePublishedAppleRoots(): void
    {
        $roots = AppleRootCerts::pinnedRoots();

        self::assertSame(
            [
                'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                'c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050',
                '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179',
            ],
            array_map(static fn (string $der): string => hash('sha256', $der), $roots),
            'Apple Inc. Root CA, Apple Root CA - G2 and G3, as published by Apple',
        );
    }

    /** @return VerificationResult<ReceiptPayload> */
    private static function verifiedReceipt(): VerificationResult
    {
        $wire = '{"verified":true,"payload":{"receipt_type":"ProductionSandbox","bundle_id":"com.example.app",'
            . '"receipt_creation_date_ms":1722945600000,"in_app":[],"unknown_attributes":{}}}';
        $result = Verifier::create(Config::defaults(), FakeTransport::answering($wire))->verifyReceipt('x');
        self::assertTrue($result->verified());

        return $result;
    }

    /** @return list<string> */
    private static function sourceFiles(): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../src'));
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        sort($files);

        return $files;
    }
}
