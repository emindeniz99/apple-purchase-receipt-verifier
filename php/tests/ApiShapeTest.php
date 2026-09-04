<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\AppTransactionPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\TransactionPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\AppReceipt;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\InAppPurchase;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
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
     * The eleven reasons, read out of `fixtures/cases.schema.json` rather
     * than restated here. The schema is the source of truth for the
     * vocabulary, so a typo in a case name — or a twelfth reason added
     * without a cross-port change — fails here.
     */
    public function testTheReasonVocabularyIsExactlyTheOneTheSchemaDefines(): void
    {
        /** @var array{'$defs': array{reason: array{enum: list<string>}}} $schema */
        $schema = json_decode(
            (string) file_get_contents(Fixtures::directory() . '/cases.schema.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );
        $expected = $schema['$defs']['reason']['enum'];
        $actual = array_map(static fn (Reason $r): string => $r->value, Reason::cases());
        sort($expected);
        sort($actual);

        self::assertCount(11, $expected);
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

    public function testTheEnvironmentVocabularyIsExactlyTheOneTheSchemaDefines(): void
    {
        /** @var array{'$defs': array{environment: array{enum: list<string>}}} $schema */
        $schema = json_decode(
            (string) file_get_contents(Fixtures::directory() . '/cases.schema.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );

        $expected = $schema['$defs']['environment']['enum'];
        $actual = array_map(static fn (Environment $e): string => $e->value, Environment::cases());
        sort($expected);
        sort($actual);

        self::assertSame($expected, $actual);
    }

    public function testTheExceptionCarriesTheReasonAsAValueAndFormatsItsMessagePredictably(): void
    {
        $e = new VerificationException(Reason::InvalidChain, 'some detail');

        self::assertSame(Reason::InvalidChain, $e->reason);
        self::assertSame('INVALID_CHAIN: some detail', $e->getMessage());
        self::assertInstanceOf(\RuntimeException::class, $e);
    }

    /**
     * Detail strings get logged by integrators, so they must not carry
     * receipt bytes, claim values or key material (PLAN.md D11). This walks
     * the real failure paths and checks the message against the secrets the
     * input actually contained.
     */
    public function testFailureMessagesDoNotEchoTheInputBack(): void
    {
        $pki = MintedPki::get();
        $secretBundle = 'com.secret.internal.build';
        $verifier = new ReceiptVerifier([$pki->foreignRootDer], 'com.example.app');

        $receipt = $pki->receipt(Support\TestPki::payload(
            Support\TestPki::utf8Attribute(2, $secretBundle),
            Support\TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        ));

        try {
            $verifier->verify($receipt);
            self::fail('expected a rejection');
        } catch (VerificationException $e) {
            self::assertStringNotContainsString($secretBundle, $e->getMessage());
            self::assertStringNotContainsString(base64_encode($receipt), $e->getMessage());
            self::assertLessThan(200, strlen($e->getMessage()), 'a detail string this long is carrying data');
        }
    }

    /** @return iterable<string, array{callable(): mixed}> */
    public static function misconfigurationProvider(): iterable
    {
        $root = static fn (): string => MintedPki::get()->rootDer;

        yield 'jws: empty roots' => [
            static fn () => new JwsVerifier([], 'com.example.app', [Environment::Sandbox]),
        ];
        yield 'jws: empty bundle id' => [
            static fn () => new JwsVerifier([$root()], '', [Environment::Sandbox]),
        ];
        yield 'jws: empty accept set' => [
            static fn () => new JwsVerifier([$root()], 'com.example.app', []),
        ];
        yield 'jws: a non-Environment in the accept set' => [
            /** @phpstan-ignore-next-line deliberate misuse */
            static fn () => new JwsVerifier([$root()], 'com.example.app', ['Sandbox']),
        ];
        yield 'jws: a zero max signed age' => [
            static fn () => new JwsVerifier([$root()], 'com.example.app', [Environment::Sandbox], null, 0),
        ];
        yield 'jws: a negative max signed age' => [
            static fn () => new JwsVerifier([$root()], 'com.example.app', [Environment::Sandbox], null, -1),
        ];
        yield 'receipt: empty roots' => [static fn () => new ReceiptVerifier([], 'com.example.app')];
        yield 'receipt: empty bundle id' => [static fn () => new ReceiptVerifier([$root()], '')];
        yield 'receipt: a zero size limit' => [
            static fn () => new ReceiptVerifier([$root()], 'com.example.app', 0),
        ];
        yield 'receipt: a zero node budget' => [
            static fn () => new ReceiptVerifier([$root()], 'com.example.app', 2097152, 0),
        ];
        yield 'endpoint: empty roots' => [
            static fn () => new VerifyReceiptEndpoint([], Environment::Sandbox),
        ];
        yield 'endpoint: the Xcode environment' => [
            static fn () => new VerifyReceiptEndpoint([$root()], Environment::Xcode),
        ];
        yield 'core: empty roots' => [
            static fn () => ReceiptVerifier::verifyReceiptCore(MintedPki::get()->receipt(), []),
        ];
    }

    /**
     * Misconfiguration is a programming error, not a verdict about a payload.
     * It must be a different type from `VerificationException`, or a caller's
     * `catch (VerificationException)` swallows its own bug as "the receipt
     * was bad".
     *
     * @param callable(): mixed $construct
     */
    #[DataProvider('misconfigurationProvider')]
    public function testMisconfigurationRaisesAnArgumentErrorNotAVerdict(callable $construct): void
    {
        try {
            $construct();
            self::fail('misconfiguration was accepted');
        } catch (VerificationException $e) {
            self::fail('misconfiguration surfaced as a verification verdict: ' . $e->getMessage());
        } catch (InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    /** @return iterable<string, array{class-string}> */
    public static function publicClassProvider(): iterable
    {
        foreach ([
            JwsVerifier::class, TransactionPayload::class, AppTransactionPayload::class,
            ReceiptVerifier::class, AppReceipt::class, InAppPurchase::class,
            VerifyReceiptEndpoint::class, VerificationException::class,
            AppleRootCerts::class, SystemClock::class,
        ] as $class) {
            yield $class => [$class];
        }
    }

    /**
     * Every public class is final. A subclass of a verifier or of a value
     * object is a way to produce a partially-verified result that still
     * passes an `instanceof` check.
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
        foreach (['__wakeup', '__unserialize', '__destruct', '__call', '__get', '__set', '__invoke'] as $magic) {
            // Inherited only counts against the parent — \Exception itself
            // declares __wakeup(), and that is not ours to remove.
            $declared = $reflection->hasMethod($magic)
                && $reflection->getMethod($magic)->getDeclaringClass()->getName() === $class;
            self::assertFalse($declared, $class . ' declares ' . $magic . '()');
        }
    }

    public function testValueObjectsAreReadOnly(): void
    {
        $receipt = (new ReceiptVerifier([MintedPki::get()->rootDer], 'com.example.app'))
            ->verify(MintedPki::get()->receipt());

        $this->expectException(Error::class);
        $this->expectExceptionMessageMatches('/readonly/');
        /** @phpstan-ignore-next-line deliberate misuse */
        $receipt->bundleId = 'com.attacker.app';
    }

    public function testAVerifiedReceiptSurvivesASerializationRoundTrip(): void
    {
        $receipt = (new ReceiptVerifier([MintedPki::get()->rootDer], 'com.example.app'))
            ->verify(MintedPki::get()->receipt());

        /** @var AppReceipt $restored */
        $restored = unserialize(serialize($receipt));

        self::assertEquals($receipt, $restored);
        self::assertSame($receipt->bundleId, $restored->bundleId);
        self::assertEquals($receipt->creationDate, $restored->creationDate);
    }

    /**
     * `verifyReceiptCore` is public in every port of this library (contract
     * C4), so the endpoint does not have to build a wildcard-bundle-id
     * verifier to reach it. No conformance vector can hold this, so it lives
     * here.
     */
    public function testVerifyReceiptCoreIsPartOfThePublicSurface(): void
    {
        $method = (new ReflectionClass(ReceiptVerifier::class))->getMethod('verifyReceiptCore');

        self::assertTrue($method->isPublic());
        self::assertTrue($method->isStatic());
        self::assertStringContainsString(
            'check `$receipt->bundleId` yourself',
            (string) $method->getDocComment(),
            'the bundle-id caveat must be documented on the method itself',
        );
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
     * D11: the reason code is the entire observability surface. No logging,
     * no metrics, no callbacks, and nothing that writes to output.
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
     * The compiled-in roots must be byte-identical to `php/certs/`, which CI
     * separately diffs against the repository-root `certs/`. Otherwise the
     * package could ship trust anchors nobody reviewed.
     */
    public function testTheCompiledInRootsMatchTheCheckedCopy(): void
    {
        $dir = __DIR__ . '/../certs';
        $files = ['AppleIncRootCertificate.cer', 'AppleRootCA-G2.cer', 'AppleRootCA-G3.cer'];
        $onDisk = array_map(static fn (string $f): string => (string) file_get_contents($dir . '/' . $f), $files);

        self::assertSame($onDisk, AppleRootCerts::jwsRoots());
        self::assertSame($onDisk, AppleRootCerts::receiptRoots());
    }

    /**
     * D15: all three published Apple roots, in both sets. Do not "optimise"
     * either set down — Apple documents the JWS chain as ending in "an Apple
     * root certificate" without naming one.
     */
    public function testBothRootSetsCarryAllThreePublishedAppleRoots(): void
    {
        $roots = AppleRootCerts::receiptRoots();
        self::assertCount(3, $roots);
        self::assertSame(AppleRootCerts::jwsRoots(), $roots);

        $subjects = array_map(
            static fn (string $der): string => Certificate::parse($der)->subjectDer,
            $roots,
        );
        self::assertSame($subjects, array_unique($subjects), 'the three roots must be distinct');

        foreach ($roots as $der) {
            $cert = Certificate::parse($der);
            self::assertTrue($cert->isCa);
            self::assertSame($cert->subjectDer, $cert->issuerDer, 'a root is self-issued');
        }
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
