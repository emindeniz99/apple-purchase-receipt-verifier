<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\JsonPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\JsonPointer;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationResult;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;

/**
 * Runs `fixtures/cases.json` — the normative cross-language 0.7
 * conformance vectors — through the façade and one transport of `aprv`.
 *
 * This adapter knows nothing about any individual case. It loads the file,
 * resolves fixture ids to digest-checked bytes, builds a `Config`/`Verifier`
 * from the generic config, dispatches on `operation`, and reads the
 * `VerificationResult`. The package holds no verification logic, so a case
 * that fails here is a fault of the module `aprv` runs (or of the façade's
 * mapping of its JSON), never of PHP code. There is no skip list and no
 * per-case fixup: a case it cannot map is a hard harness failure.
 */
#[CoversNothing]
abstract class ConformanceBase extends TestCase
{
    /** @var array<class-string, array<string, true>> case ids each concrete class actually executed */
    private static array $executed = [];

    /** A verifier for this case's roots and clock, over the transport under test. */
    abstract protected static function verifierFor(Config $config): Verifier;

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function caseProvider(): iterable
    {
        /** @var list<array<string, mixed>> $cases */
        $cases = Fixtures07::cases()['cases'];
        foreach ($cases as $case) {
            /** @var string $id */
            $id = $case['id'];
            yield $id => [$case];
        }
    }

    public function testEveryRegisteredFixtureMatchesItsRecordedDigest(): void
    {
        $ids = array_keys(Fixtures07::registry());
        self::assertNotEmpty($ids, 'cases.json must register fixtures');
        foreach ($ids as $id) {
            Fixtures07::bytes($id);
            $this->addToAssertionCount(1);
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('caseProvider')]
    public function testCase(array $case): void
    {
        /** @var string $id */
        $id = $case['id'];
        self::$executed[static::class][$id] = true;

        self::execute($case, static::verifierFor(...));
    }

    /**
     * A silently dropped operation, or a provider that quietly stopped
     * yielding, cannot hide behind a green suite.
     */
    #[Depends('testCase')]
    public function testEveryCaseInTheFileRan(): void
    {
        /** @var list<array<string, mixed>> $cases */
        $cases = Fixtures07::cases()['cases'];
        $ids = array_map(static fn (array $c): string => Shape::asString($c['id'], 'case id'), $cases);
        self::assertSame(count($ids), count(array_unique($ids)), 'case ids must be unique');
        $ran = self::$executed[static::class] ?? [];
        $missing = array_values(array_diff($ids, array_keys($ran)));
        self::assertSame([], $missing, 'cases in the file that never ran');
        self::assertCount(count($ids), $ran);
    }

    /**
     * Runs one case and asserts its expectation; throws on any mismatch.
     *
     * @param array<string, mixed> $case
     * @param Closure(Config): Verifier $factory
     */
    public static function execute(array $case, Closure $factory): void
    {
        /** @var string $id */
        $id = $case['id'];
        if ($case['operation'] === 'decodeBase64') {
            $failures = self::decodeBase64Failures($case, $factory);
            self::assertSame([], $failures, implode("\n", $failures));

            return;
        }

        $maxMillis = isset($case['maxMillis']) ? Shape::asInt($case['maxMillis'], 'maxMillis') : null;
        if ($maxMillis !== null) {
            self::runOperation($case, $factory); // warm-up, unmeasured
        }
        $started = hrtime(true);
        $result = self::runOperation($case, $factory);
        $elapsedMs = (hrtime(true) - $started) / 1_000_000;
        if ($maxMillis !== null) {
            self::assertLessThanOrEqual(
                $maxMillis,
                $elapsedMs,
                "{$id}: took " . round($elapsedMs, 1) . " ms, budget {$maxMillis} ms",
            );
        }

        $expected = Shape::asArray($case['expected'], 'expected');

        if ($case['operation'] === 'verifyReceiptEndpoint') {
            /** @var string $responseJson */
            $responseJson = $result;
            $actual = json_decode($responseJson, true, 65, JSON_THROW_ON_ERROR);
            if (isset($expected['oneOf'])) {
                // Port-defined within a list: the response's /status must be
                // listed, and nothing else is pinned.
                $status = is_array($actual) ? ($actual['status'] ?? null) : null;
                self::assertContains(
                    $status,
                    Shape::asArray($expected['oneOf'], 'oneOf'),
                    "{$id}: answered status " . json_encode($status),
                );

                return;
            }
            self::assertFields($id, $actual, $expected);

            return;
        }

        /** @var VerificationResult<mixed> $result */
        if (isset($expected['oneOf'])) {
            $outcome = $result->verified() ? 'ok' : $result->failure->reason->value;
            self::assertContains($outcome, Shape::asArray($expected['oneOf'], 'oneOf'), "{$id}: answered {$outcome}");

            return;
        }

        if (!$result->verified()) {
            $failure = $result->failure;
            self::assertSame('error', $expected['status'], "{$id}: expected success but got {$failure->reason->value}");
            self::assertSame($expected['reason'], $failure->reason->value, "{$id}: reason");
            /** @var list<int> $codePoints */
            $codePoints = $expected['messageMustNotContain'] ?? [];
            foreach ($codePoints as $codePoint) {
                $char = self::codepointToUtf8($codePoint);
                self::assertStringNotContainsString(
                    $char,
                    $failure->message,
                    sprintf('%s: message must not contain U+%04X: %s', $id, $codePoint, $failure->message),
                );
            }

            return;
        }

        self::assertSame(
            'ok',
            $expected['status'],
            "{$id}: expected " . Shape::asString($expected['reason'] ?? '?', 'reason') . ' but verified',
        );
        $payload = $result->payload;
        if ($case['operation'] === 'verifyReceipt') {
            /** @var ReceiptPayload $payload */
            $actual = json_decode($payload->toJson(), true, 65, JSON_THROW_ON_ERROR);
            if (isset($expected['toJson'])) {
                // Same value, not same bytes: key order and escaping are
                // free, so both sides are key-sorted before the strict
                // comparison.
                self::assertSame(
                    self::sortKeys(json_decode(Shape::asString($expected['toJson'], 'toJson'), true, 65, JSON_THROW_ON_ERROR)),
                    self::sortKeys($actual),
                    "{$id}: toJson value",
                );
            }
        } else {
            /** @var JsonPayload $payload */
            $actual = json_decode($payload->json, true, 65, JSON_THROW_ON_ERROR);
        }
        self::assertFields($id, $actual, $expected);
    }

    // --- dispatch --------------------------------------------------------

    /**
     * @param array<string, mixed> $case
     * @param Closure(Config): Verifier $factory
     */
    private static function runOperation(array $case, Closure $factory): mixed
    {
        $operation = Shape::asString($case['operation'], 'operation');

        return match ($operation) {
            'verifyReceipt' => self::verifier($case, $factory)->verifyReceipt(self::inputString($case)),
            'verifySignedData' => self::verifier($case, $factory)->verifySignedData(self::jwsInputString($case)),
            'verifyReceiptEndpoint' => self::runEndpoint($case, $factory),
            default => throw new RuntimeException("harness error: no adapter for operation \"{$operation}\""),
        };
    }

    /**
     * The fixture's logical bytes, as the exact JWS string a client sent —
     * never base64-re-encoded, unlike a receipt fixture: `utf8` and `text`
     * fixtures already ARE the JWS text (the schema's base64/raw codecs are
     * used only for receipt and certificate fixtures).
     *
     * @param array<string, mixed> $case
     */
    private static function jwsInputString(array $case): string
    {
        /** @var array{fixture: string} $input */
        $input = $case['input'];

        return Fixtures07::bytes(Shape::asString($input['fixture'], 'input.fixture'));
    }

    /**
     * @param array<string, mixed> $case
     * @param Closure(Config): Verifier $factory
     */
    private static function runEndpoint(array $case, Closure $factory): string
    {
        /** @var array<string, mixed> $config */
        $config = Shape::asArray($case['config'], 'config');
        $wire = Shape::asString($config['environment'], 'environment');
        $environment = match ($wire) {
            'PRODUCTION' => Environment::Production,
            'SANDBOX' => Environment::Sandbox,
            default => throw new RuntimeException('harness error: unknown environment "' . $wire . '"'),
        };
        /** @var array{fixture?: string, requestBody?: string} $input */
        $input = $case['input'];
        if (isset($input['requestBody'])) {
            $requestJson = Fixtures07::bytes($input['requestBody']);
        } else {
            $requestJson = json_encode(['receipt-data' => self::inputString($case)], JSON_THROW_ON_ERROR);
        }

        return self::verifier($case, $factory)->verifyReceiptEndpoint($environment, $requestJson);
    }

    /**
     * The fixture as the exact string handed to `verifyReceipt` /
     * `verifySignedData` / the endpoint's `receipt-data`: a text fixture
     * verbatim; a raw/base64 fixture's decoded bytes, base64-encoded, since
     * verifyReceipt takes only base64.
     *
     * @param array<string, mixed> $case
     */
    private static function inputString(array $case): string
    {
        /** @var array{fixture: string} $input */
        $input = $case['input'];
        $fixtureId = Shape::asString($input['fixture'], 'input.fixture');
        $bytes = Fixtures07::bytes($fixtureId);
        $codec = Fixtures07::registry()[$fixtureId]['codec'];

        return $codec === 'text' ? $bytes : base64_encode($bytes);
    }

    /**
     * @param array<string, mixed> $case
     * @param Closure(Config): Verifier $factory
     */
    private static function verifier(array $case, Closure $factory): Verifier
    {
        /** @var array<string, mixed> $config */
        $config = Shape::asArray($case['config'], 'config');
        $builder = Config::builder();
        $roots = self::trustedRoots($config);
        if ($roots !== null) {
            $builder = $builder->roots($roots);
        }
        $clock = self::caseClock($case);
        if ($clock !== null) {
            $builder = $builder->clock($clock);
        }

        return $factory($builder->build());
    }

    /**
     * The roots of a case as `Config` takes them: the fixture certificates'
     * DER, or null for the module's built-in Apple roots.
     *
     * @param array<string, mixed> $config
     *
     * @return list<string>|null
     */
    private static function trustedRoots(array $config): ?array
    {
        /** @var array{source: string, fixtures?: list<string>} $spec */
        $spec = Shape::asArray($config['trustedRoots'], 'config.trustedRoots');
        if ($spec['source'] === 'defaults') {
            return Config::defaults()->roots;
        }
        if ($spec['source'] !== 'fixtures') {
            throw new RuntimeException('harness error: unknown trustedRoots source "' . $spec['source'] . '"');
        }

        return array_map(Fixtures07::bytes(...), $spec['fixtures'] ?? []);
    }

    /** @param array<string, mixed> $case */
    private static function caseClock(array $case): ?FrozenClock
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

    // --- decodeBase64 ------------------------------------------------------

    /**
     * 0.7 exposes no public decoder, and this package holds none. The rule
     * is the module's, so each text runs through the public API where the
     * module reads it, and must land on its group's side of the rule:
     * refused as base64, or decoded and refused later for what the bytes
     * are. The two are told apart by the failure message naming base64,
     * which is the only place the module says which rule refused (a message
     * is not a contract, so only this harness reads it). A `receipt-data`
     * text is a receipt; an `x5c` text is the three chain entries of a JWS
     * header, which the module decodes in order.
     *
     * @param array<string, mixed> $case
     * @param Closure(Config): Verifier $factory
     *
     * @return list<string> every text that landed on the wrong side of the rule
     */
    private static function decodeBase64Failures(array $case, Closure $factory): array
    {
        $id = Shape::asString($case['id'], 'id');
        $expected = Shape::asArray($case['expected'], 'expected');
        $texts = Shape::asArray(Shape::asArray($case['input'], 'input')['texts'] ?? null, 'input.texts');
        $decoders = Shape::asArray($case['decoders'] ?? null, 'decoders');
        self::assertNotEmpty($texts, "harness error: {$id}: input.texts is empty");
        self::assertNotEmpty($decoders, "harness error: {$id}: decoders is empty");
        $verifier = $factory(Config::defaults());
        $failures = [];
        foreach ($decoders as $decoder) {
            $decoder = Shape::asString($decoder, 'decoder');
            foreach ($texts as $index => $text) {
                $text = Shape::asString($text, 'text');
                $refused = match ($decoder) {
                    'receipt-data' => self::refusedAsBase64($verifier->verifyReceipt($text), Reason::Malformed),
                    'x5c' => self::refusedAsBase64(
                        $verifier->verifySignedData(self::jwsWithX5c($text)),
                        Reason::InvalidCertificate,
                    ),
                    default => throw new RuntimeException("harness error: {$id}: unknown decoder \"{$decoder}\""),
                };
                $where = sprintf(
                    '%s: %s texts[%d] %s',
                    $id,
                    $decoder,
                    $index,
                    json_encode($text, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
                );
                if ($expected['status'] === 'ok' && $refused) {
                    $failures[] = "{$where} was refused as base64, want it decoded";
                } elseif ($expected['status'] === 'error' && !$refused) {
                    $failures[] = "{$where} was not refused as base64";
                }
            }
        }

        return $failures;
    }

    /** @param VerificationResult<mixed> $result */
    private static function refusedAsBase64(VerificationResult $result, Reason $reason): bool
    {
        $failure = $result->failure;

        // The module refuses an empty receipt-data before it decodes anything.
        return $failure !== null
            && $failure->reason === $reason
            && (str_contains(strtolower($failure->message), 'base64') || $failure->message === 'receipt is empty');
    }

    private static function jwsWithX5c(string $text): string
    {
        $segment = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        $header = json_encode(['alg' => 'ES256', 'x5c' => [$text, $text, $text]], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);

        return $segment($header) . '.' . $segment('{}') . '.' . $segment(str_repeat("\0", 64));
    }

    // --- field/length assertions ------------------------------------------

    /**
     * A decoded JSON value with every object's keys sorted, so two values
     * compare with assertSame regardless of the key order they were written in.
     */
    private static function sortKeys(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        $value = array_map(self::sortKeys(...), $value);
        ksort($value);

        return $value;
    }

    /**
     * @param mixed $actual
     * @param array<mixed> $expected
     */
    private static function assertFields(string $id, $actual, array $expected): void
    {
        /** @var array<string, mixed> $fields */
        $fields = $expected['fields'] ?? [];
        foreach ($fields as $path => $want) {
            $got = JsonPointer::resolve($actual, $path);
            if ($want === null) {
                self::assertTrue(
                    $got === null || JsonPointer::isMissing($got),
                    "{$id}: {$path}: expected absent, got " . var_export($got, true),
                );
            } else {
                self::assertTrue(
                    self::fieldsEqual($got, $want),
                    "{$id}: {$path}: expected " . var_export($want, true) . ', got ' . var_export($got, true),
                );
            }
        }
        /** @var array<string, int> $lengths */
        $lengths = $expected['lengths'] ?? [];
        foreach ($lengths as $path => $want) {
            $got = JsonPointer::resolveLength($actual, $path);
            self::assertSame($want, $got, "{$id}: length of {$path}");
        }
    }

    private static function fieldsEqual(mixed $got, mixed $want): bool
    {
        if (is_int($got) || is_float($got)) {
            return (is_int($want) || is_float($want)) && (float) $got === (float) $want;
        }

        return $got === $want;
    }

    private static function codepointToUtf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }

        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
            . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }
}
