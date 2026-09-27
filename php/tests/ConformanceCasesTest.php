<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
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
 * conformance vectors — against this implementation.
 *
 * This adapter knows nothing about any individual case. It loads the file,
 * resolves fixture ids to digest-checked bytes, builds a `Config`/`Verifier`
 * from the generic config, dispatches on `operation`, and reads the
 * `VerificationResult`. There is no skip list, no per-case fixup and no
 * hardcoded count: a case it cannot map is a hard harness failure. A vector
 * that disagrees with the library is a bug report against one of the two;
 * it is never something to special-case here.
 */
#[CoversNothing]
final class ConformanceCasesTest extends TestCase
{
    /** @var array<string, true> case ids this run actually executed */
    private static array $executed = [];

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
        self::$executed[$id] = true;

        if ($case['operation'] === 'decodeBase64') {
            $failures = self::decodeBase64Failures($case);
            self::assertSame([], $failures, implode("\n", $failures));

            return;
        }

        $maxMillis = $case['maxMillis'] ?? null;
        if ($maxMillis !== null) {
            self::runOperation($case); // warm-up, unmeasured
        }
        $started = hrtime(true);
        $result = self::runOperation($case);
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
            self::assertFields($id, $actual, $expected);

            return;
        }

        /** @var VerificationResult<mixed> $result */
        if (isset($expected['oneOf'])) {
            $outcome = $result->verified() ? 'ok' : $result->failure?->reason->value;
            self::assertContains($outcome, $expected['oneOf'], "{$id}: answered {$outcome}");

            return;
        }

        if (!$result->verified()) {
            $failure = $result->failure;
            self::assertNotNull($failure);
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
            "{$id}: expected " . ($expected['reason'] ?? '?') . ' but verified',
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
                    self::sortKeys(json_decode($expected['toJson'], true, 65, JSON_THROW_ON_ERROR)),
                    self::sortKeys($actual),
                    "{$id}: toJson value",
                );
            }
        } else {
            /** @var \EminDeniz99\ApplePurchaseReceiptVerifier\JsonPayload $payload */
            $actual = json_decode($payload->json, true, 65, JSON_THROW_ON_ERROR);
        }
        self::assertFields($id, $actual, $expected);
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
        $missing = array_values(array_diff($ids, array_keys(self::$executed)));
        self::assertSame([], $missing, 'cases in the file that never ran');
        self::assertCount(count($ids), self::$executed);
    }

    // --- dispatch --------------------------------------------------------

    /** @param array<string, mixed> $case */
    private static function runOperation(array $case): mixed
    {
        $operation = Shape::asString($case['operation'], 'operation');

        return match ($operation) {
            'verifyReceipt' => self::verifier($case)->verifyReceipt(self::inputString($case)),
            'verifySignedData' => self::verifier($case)->verifySignedData(self::jwsInputString($case)),
            'verifyReceiptEndpoint' => self::runEndpoint($case),
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

    /** @param array<string, mixed> $case */
    private static function runEndpoint(array $case): string
    {
        /** @var array<string, mixed> $config */
        $config = Shape::asArray($case['config'], 'config');
        $environment = match (Shape::asString($config['environment'], 'environment')) {
            'PRODUCTION' => Environment::Production,
            'SANDBOX' => Environment::Sandbox,
            default => throw new RuntimeException('harness error: unknown environment "' . $config['environment'] . '"'),
        };
        /** @var array{fixture?: string, requestBody?: string} $input */
        $input = $case['input'];
        if (isset($input['requestBody'])) {
            $requestJson = Fixtures07::bytes($input['requestBody']);
        } else {
            $requestJson = json_encode(['receipt-data' => self::receiptDataString($case)], JSON_THROW_ON_ERROR);
        }

        return self::verifier($case)->verifyReceiptEndpoint($environment, $requestJson);
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

    /** @param array<string, mixed> $case */
    private static function receiptDataString(array $case): string
    {
        return self::inputString($case);
    }

    /** @param array<string, mixed> $case */
    private static function verifier(array $case): Verifier
    {
        /** @var array<string, mixed> $config */
        $config = Shape::asArray($case['config'], 'config');
        $roots = self::trustedRoots($config);
        $builder = Config::builder()->roots($roots);
        $clock = self::caseClock($case);
        if ($clock !== null) {
            $builder = $builder->clock($clock);
        }

        return Verifier::create($builder->build());
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return list<string>
     */
    private static function trustedRoots(array $config): array
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
     * Every text of a decodeBase64 group that got the wrong answer from a
     * decoder the group names, by case id, decoder, index and JSON-escaped
     * text, rather than stopping at the first. Both decoders this schema
     * names ("receipt-data", "x5c") share one canonical-base64 decoder at
     * this level ({@see Base64::decodeCanonical()}); which public Reason
     * their refusal becomes is exercised through the real operations above.
     *
     * @param array<string, mixed> $case
     *
     * @return list<string>
     */
    private static function decodeBase64Failures(array $case): array
    {
        $id = Shape::asString($case['id'], 'id');
        $expected = Shape::asArray($case['expected'], 'expected');
        $texts = Shape::asArray(Shape::asArray($case['input'], 'input')['texts'] ?? null, 'input.texts');
        $decoders = Shape::asArray($case['decoders'] ?? null, 'decoders');
        self::assertNotEmpty($texts, "harness error: {$id}: input.texts is empty");
        self::assertNotEmpty($decoders, "harness error: {$id}: decoders is empty");
        $ok = $expected['status'] === 'ok';
        $want = $ok ? Shape::asString($expected['bytesHex'], 'expected.bytesHex') : '';
        $failures = [];
        foreach ($decoders as $decoder) {
            $decoder = Shape::asString($decoder, 'decoder');
            foreach ($texts as $index => $text) {
                $text = Shape::asString($text, 'text');
                $where = sprintf(
                    '%s: %s texts[%d] %s',
                    $id,
                    $decoder,
                    $index,
                    json_encode($text, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
                );
                $decoded = Base64::decodeCanonical($text);
                if ($decoded === null) {
                    if ($ok) {
                        $failures[] = "{$where} was refused, want {$want}";
                    }
                } elseif (!$ok) {
                    $failures[] = "{$where} was accepted (decoded to " . bin2hex($decoded) . ')';
                } elseif (bin2hex($decoded) !== $want) {
                    $failures[] = "{$where} decoded to " . bin2hex($decoded) . ", want {$want}";
                }
            }
        }

        return $failures;
    }

    // --- field/length assertions ------------------------------------------

    /**
     * @param mixed $actual
     * @param array<string, mixed> $expected
     */
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
