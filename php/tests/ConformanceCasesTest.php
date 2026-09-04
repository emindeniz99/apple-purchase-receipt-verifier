<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Throwable;

/**
 * Runs `fixtures/cases.json` — the normative cross-language conformance
 * vectors — against this implementation.
 *
 * This adapter knows nothing about any individual case. It loads the file,
 * resolves fixture ids to digest-checked bytes, builds a verifier from the
 * generic config, dispatches on `operation`, normalises the result and reads
 * the reason off a failure. There is no skip list, no per-case fixup and no
 * hardcoded count: a case it cannot map is a hard harness failure.
 *
 * A vector that disagrees with the library is a bug report against one of the
 * two (CONTRIBUTING.md). It is never something to special-case here.
 */
#[CoversNothing]
final class ConformanceCasesTest extends TestCase
{
    /**
     * verifyRaw enforces no claim, so its cases may omit `bundleId` and
     * `acceptedEnvironments` — but the constructor still demands both. These
     * stand-ins match nothing any fixture carries, so a claim check that
     * leaked into verifyRaw surfaces as a failure. An empty string, a
     * wildcard, or "all four environments" would turn that leak into a
     * silent pass.
     */
    private const UNMATCHABLE_BUNDLE_ID = 'conformance.unset.bundle.id';

    /** @var array<string, true> case ids this run actually executed */
    private static array $executed = [];

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function caseProvider(): iterable
    {
        /** @var list<array<string, mixed>> $cases */
        $cases = Fixtures::cases()['cases'];
        foreach ($cases as $case) {
            /** @var string $id */
            $id = $case['id'];
            yield $id => [$case];
        }
    }

    /**
     * Read before any case runs: a fixture no case happens to reference would
     * otherwise drift unnoticed, and the registry is the thing being guarded.
     */
    public function testEveryRegisteredFixtureMatchesItsRecordedDigest(): void
    {
        $ids = array_keys(Fixtures::registry());
        self::assertNotEmpty($ids, 'cases.json must register fixtures');
        foreach ($ids as $id) {
            // Throws on a digest mismatch; one checked fixture, one assertion.
            Fixtures::bytes($id);
            $this->addToAssertionCount(1);
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('caseProvider')]
    public function testCase(array $case): void
    {
        /** @var string $id */
        $id = $case['id'];
        self::$executed[$id] = true;

        /** @var array<string, mixed> $config */
        $config = $case['config'];
        /** @var array{fixture: string} $input */
        $input = $case['input'];
        $bytes = Fixtures::bytes($input['fixture']);
        $clock = self::caseClock($case);
        // cases.schema.json makes these types normative, so a case that does
        // not have them is a harness failure rather than a verdict.
        $operation = Shape::asString($case['operation'], 'operation');
        $expected = Shape::asArray($case['expected'], 'expected');

        try {
            $result = $this->dispatch($operation, $config, $bytes, $clock);
        } catch (VerificationException $e) {
            self::assertSame(
                'error',
                $expected['status'],
                'expected success but threw ' . $e->reason->value,
            );
            self::assertSame($expected['reason'], $e->reason->value, 'reason');

            return;
        } catch (Throwable $e) {
            // Only a VerificationException carries a canonical Reason.
            // Anything else is a defect in the library or in this harness and
            // must never be read as one of the expected reasons.
            self::fail(sprintf(
                'harness error: %s threw %s (%s), which is not a VerificationException',
                $operation,
                $e::class,
                $e->getMessage(),
            ));
        }

        self::assertSame(
            'ok',
            $expected['status'],
            'expected ' . Shape::asString($expected['reason'] ?? '?', 'expected.reason')
                . ' but the call returned a value',
        );
        $actual = self::normalize($result);
        /** @var array<string, scalar|null> $fields */
        $fields = $expected['fields'];
        foreach ($fields as $path => $expected) {
            $value = self::resolvePath($actual, $path);
            if ($expected === null) {
                // null means "absent or unset".
                self::assertNull($value, $path . ': expected absent, got ' . var_export($value, true));
            } else {
                self::assertSame($expected, $value, $path);
            }
        }
    }

    /**
     * A silently dropped operation, or a provider that quietly stopped
     * yielding, cannot hide behind a green suite. Asserted against the parsed
     * length of the file, never a literal.
     */
    #[Depends('testCase')]
    public function testEveryCaseInTheFileRan(): void
    {
        /** @var list<array<string, mixed>> $cases */
        $cases = Fixtures::cases()['cases'];
        $ids = array_map(static fn (array $c): string => Shape::asString($c['id'], 'case id'), $cases);
        self::assertSame(count($ids), count(array_unique($ids)), 'case ids must be unique');
        $missing = array_values(array_diff($ids, array_keys(self::$executed)));
        self::assertSame([], $missing, 'cases in the file that never ran');
        self::assertCount(count($ids), self::$executed);
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws VerificationException
     */
    private function dispatch(string $operation, array $config, string $input, ?ClockInterface $clock): mixed
    {
        return match ($operation) {
            'verifyTransaction' => $this->jwsVerifier($config, $clock)->verifyTransaction($input),
            'verifyAppTransaction' => $this->jwsVerifier($config, $clock)->verifyAppTransaction($input),
            'verifyRaw' => $this->jwsVerifier($config, $clock)->verifyRaw($input),
            'verifyReceipt' => $this->receiptVerifier($config, $clock)->verify(
                $input,
                isset($config['deviceGuidHex'])
                    ? (string) hex2bin(Shape::asString($config['deviceGuidHex'], 'deviceGuidHex'))
                    : null,
            ),
            'verifyReceiptEndpoint' => (new VerifyReceiptEndpoint(
                self::trustedRoots($config),
                Environment::from(Shape::asString($config['environment'], 'environment')),
                $clock,
            ))->verifyReceipt(['receipt-data' => base64_encode($input)]),
            default => throw new RuntimeException("harness error: no adapter for operation \"{$operation}\""),
        };
    }

    /** @param array<string, mixed> $config */
    private function jwsVerifier(array $config, ?ClockInterface $clock): JwsVerifier
    {
        $environments = isset($config['acceptedEnvironments'])
            ? array_map(
                static fn (mixed $name): Environment => Environment::from(
                    Shape::asString($name, 'acceptedEnvironments entry'),
                ),
                (array) $config['acceptedEnvironments'],
            )
            // Unmatchable by design; see UNMATCHABLE_BUNDLE_ID.
            : [Environment::LocalTesting];

        return new JwsVerifier(
            self::trustedRoots($config),
            isset($config['bundleId']) ? Shape::asString($config['bundleId'], 'bundleId') : self::UNMATCHABLE_BUNDLE_ID,
            array_values($environments),
            isset($config['appAppleId']) ? Shape::asInt($config['appAppleId'], 'appAppleId') : null,
            // The port's option is already in seconds, so the conversion the
            // millisecond ports do here is a no-op rather than a hidden one.
            isset($config['maxSignedAgeSeconds'])
                ? Shape::asInt($config['maxSignedAgeSeconds'], 'maxSignedAgeSeconds')
                : null,
            $clock,
        );
    }

    /** @param array<string, mixed> $config */
    private function receiptVerifier(array $config, ?ClockInterface $clock): ReceiptVerifier
    {
        // ReceiptVerifier takes no clock in any port: its only "now" is the
        // certificate-validity fallback, which an injected clock must not be
        // able to move. A case that pinned one would be a harness error, and
        // the cases.json schema refuses to express one.
        if ($clock !== null) {
            throw new RuntimeException('harness error: verifyReceipt has no clock seam, but the case pins one');
        }

        return new ReceiptVerifier(self::trustedRoots($config), Shape::asString($config['bundleId'], 'bundleId'));
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return list<string>
     */
    private static function trustedRoots(array $config): array
    {
        /** @var array{source: string, name?: string, fixtures?: list<string>} $spec */
        $spec = $config['trustedRoots'];
        if ($spec['source'] === 'builtin') {
            return match ($spec['name'] ?? '') {
                'apple-jws-roots' => AppleRootCerts::jwsRoots(),
                'apple-receipt-roots' => AppleRootCerts::receiptRoots(),
                default => throw new RuntimeException(
                    'harness error: unknown builtin root set "' . ($spec['name'] ?? '') . '"',
                ),
            };
        }
        if ($spec['source'] !== 'fixtures') {
            throw new RuntimeException('harness error: unknown trustedRoots source "' . $spec['source'] . '"');
        }

        return array_map(Fixtures::bytes(...), $spec['fixtures'] ?? []);
    }

    /** @param array<string, mixed> $case */
    private static function caseClock(array $case): ?ClockInterface
    {
        if (!isset($case['clock'])) {
            return null;
        }
        /** @var array{now: string} $clock */
        $clock = $case['clock'];
        try {
            $now = new DateTimeImmutable($clock['now'], new DateTimeZone('UTC'));
        } catch (Throwable $e) {
            throw new RuntimeException('harness error: unparseable clock "' . $clock['now'] . '"', 0, $e);
        }

        return new FrozenClock($now);
    }

    // --- result normalisation ------------------------------------------

    /**
     * Renders a returned value into the language-neutral shape the field
     * paths are written against: dates as ISO-8601 UTC, bytes as lowercase
     * hex (also under `<name>Hex`, the spelling cases.json uses for a byte
     * field), maps as objects with stringified keys.
     *
     * PHP spells bytes and text both `string`, so which properties hold bytes
     * comes from the value object's own `BINARY_PROPERTIES` constant rather
     * than from a table in this file.
     */
    private static function normalize(mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }
        if ($value instanceof DateTimeInterface) {
            return self::isoUtc($value);
        }
        if (is_object($value)) {
            $binary = defined($value::class . '::BINARY_PROPERTIES')
                ? constant($value::class . '::BINARY_PROPERTIES')
                : [];
            if (!is_array($binary)) {
                throw new RuntimeException(
                    'harness error: ' . $value::class . '::BINARY_PROPERTIES is not an array',
                );
            }
            $out = [];
            foreach (get_object_vars($value) as $key => $property) {
                if (in_array($key, $binary, true)) {
                    $out[$key] = self::normalizeBinary($property);
                    $out[$key . 'Hex'] = $out[$key];
                } else {
                    $out[$key] = self::normalize($property);
                }
            }

            return $out;
        }
        if (is_array($value)) {
            if ($value !== [] && !array_is_list($value)) {
                $out = [];
                foreach ($value as $key => $element) {
                    $out[(string) $key] = self::normalize($element);
                }

                return $out;
            }

            return array_map(self::normalize(...), $value);
        }

        return $value;
    }

    private static function normalizeBinary(mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }
        if (is_string($value)) {
            return bin2hex($value);
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $element) {
                $out[(string) $key] = self::normalizeBinary($element);
            }

            return $value !== [] && array_is_list($value) ? array_values($out) : $out;
        }

        return $value;
    }

    private static function isoUtc(DateTimeInterface $date): string
    {
        $utc = DateTimeImmutable::createFromInterface($date)->setTimezone(new DateTimeZone('UTC'));
        $millis = (int) $utc->format('v');

        return $millis === 0
            ? $utc->format('Y-m-d\TH:i:s\Z')
            : $utc->format('Y-m-d\TH:i:s.v\Z');
    }

    // --- field paths ----------------------------------------------------

    /**
     * A path step is either a name (`bundleId`, `length`) or a bracket
     * (`[9999]`, `[0]`, `[productId=com.example.app.vip]`). Bracket contents
     * hold dots, so a plain `explode('.', $path)` is wrong.
     */
    private static function resolvePath(mixed $root, string $path): mixed
    {
        $current = $root;
        foreach (self::pathSteps($path) as [$isBracket, $step]) {
            if ($current === null) {
                return null;
            }
            if (!$isBracket) {
                if ($step === 'length' && is_array($current)) {
                    $current = count($current);
                    continue;
                }
                $current = is_array($current) ? ($current[$step] ?? null) : null;
                continue;
            }
            $separator = strpos($step, '=');
            if ($separator !== false && $separator > 0) {
                $key = substr($step, 0, $separator);
                $wanted = substr($step, $separator + 1);
                self::assertTrue(
                    is_array($current) && array_is_list($current),
                    $path . ': [' . $step . '] does not select from a list',
                );
                /** @var list<mixed> $current */
                $matches = array_values(array_filter(
                    $current,
                    static fn (mixed $e): bool => is_array($e) && ($e[$key] ?? null) === $wanted,
                ));
                self::assertCount(
                    1,
                    $matches,
                    $path . ': [' . $step . '] must select exactly one element, selected ' . count($matches),
                );
                $current = $matches[0];
                continue;
            }
            $current = is_array($current) ? ($current[$step] ?? $current[(int) $step] ?? null) : null;
        }

        return $current;
    }

    /** @return list<array{bool, string}> */
    private static function pathSteps(string $path): array
    {
        $steps = [];
        $consumed = 0;
        $pattern = '/\.?([^.\[\]]+)|\[([^\]]+)\]/';
        $flags = PREG_SET_ORDER | PREG_OFFSET_CAPTURE;
        if (preg_match_all($pattern, $path, $matches, $flags) === false) {
            throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
        }
        foreach ($matches as $match) {
            if ($match[0][1] !== $consumed) {
                throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
            }
            $consumed += strlen($match[0][0]);
            // One of the two alternatives always participates, so the
            // bracketed group is present whenever the bare one is not — the
            // throw states that rather than assuming it.
            $steps[] = ($match[1][0] ?? '') !== '' && $match[1][1] !== -1
                ? [false, $match[1][0]]
                : [true, $match[2][0] ?? throw new RuntimeException(
                    "harness error: unparseable field path \"{$path}\"",
                )];
        }
        if ($consumed !== strlen($path)) {
            throw new RuntimeException("harness error: unparseable field path \"{$path}\"");
        }

        return $steps;
    }
}
