<?php

declare(strict_types=1);

/**
 * Runs the corpus (five call files, 6,179 rows) through the façade over one
 * transport of `aprv` and compares every row with the module's own answers,
 * byte for byte.
 *
 *   php -d memory_limit=1G tools/corpus.php --aprv PATH --calls DIR --reference DIR \
 *       [--suffix .pinned] [--mode cli|http] [--corpus cases,hostile,...] [--out DIR]
 *
 * DIR of --calls holds `<corpus><suffix>.jsonl` (id, fn, config, env, now, b64
 * per row; a `map` row is a call that has no public spelling). DIR of
 * --reference holds `module-<corpus>.jsonl`, the module's answers. The
 * façade's transport is wrapped in a recorder, so the module's raw JSON is
 * what is compared; the façade still maps every answer, and a row whose
 * mapping raised a wrapper-side INTERNAL_ERROR on a well-formed answer is a
 * `facade-fault`, never a pass.
 *
 * Categories: identical (equal to the reference), over-cap (the input is over
 * 3,145,728 bytes and aprv refused it before the module saw it: HTTP 413 or
 * CLI exit 3, where the module's own answer is the size refusal, TOO_LARGE or
 * status 21002), roots-refused (the reference is `init` refusing the roots,
 * and the façade or the server refused them the same way), DIFFERENT.
 * `--out` writes the rows the façade saw as `<mode>-<corpus>.jsonl`.
 * Exit status 1 when any row is DIFFERENT or a facade-fault.
 */

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\InputTooLargeException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Transport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../vendor/autoload.php';

const MAX_BODY = 3145728;
const CORPORA = ['cases', 'hostile', 'algorithms', 'substrate', 'fuzz'];

/** Passes every call to the real transport and remembers what it answered. */
final class Recorder implements Transport
{
    public ?string $raw = null;

    public bool $tooLarge = false;

    public ?Throwable $failure = null;

    public function __construct(private readonly Transport $inner)
    {
    }

    public function open(array $roots): void
    {
        $this->inner->open($roots);
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        $this->raw = null;
        $this->tooLarge = false;
        $this->failure = null;
        try {
            return $this->raw = $this->inner->call($operation, $input, $nowMs);
        } catch (InputTooLargeException $e) {
            $this->tooLarge = true;

            throw $e;
        } catch (Throwable $e) {
            $this->failure = $e;

            throw $e;
        }
    }
}

final class MillisClock implements ClockInterface
{
    public function __construct(private readonly int $ms)
    {
    }

    public function now(): DateTimeImmutable
    {
        return (new DateTimeImmutable('@' . intdiv($this->ms, 1000)))->modify('+' . (($this->ms % 1000) * 1000) . ' microseconds');
    }
}

/** @return array{Verifier, Recorder}|string a verifier, or the module's refusal text of the roots */
function open(string $mode, string $aprv, string $config, int $now, array &$servers, string $tmp): array|string
{
    $roots = [];
    if ($config !== '') {
        foreach (json_decode($config, true, 8, JSON_THROW_ON_ERROR)['roots'] as $b64) {
            $roots[] = (string) base64_decode($b64, true);
        }
    }
    $clock = new MillisClock($now);
    if ($mode === 'cli') {
        $recorder = new Recorder(new CliTransport($aprv));
        try {
            return [Verifier::create(Config::builder()->roots($roots)->clock($clock)->build(), $recorder), $recorder];
        } catch (InvalidArgumentException $e) {
            return $e->getMessage();
        }
    }
    if (!isset($servers[$config])) {
        $arguments = [$aprv, 'serve', '--listen', '127.0.0.1:0'];
        if ($roots !== []) {
            $file = $tmp . '/roots-' . count($servers) . '.txt';
            file_put_contents($file, implode("\n", array_map('base64_encode', $roots)) . "\n");
            array_push($arguments, '--roots', $file);
        }
        $process = proc_open($arguments, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $line = is_resource($process) ? fgets($pipes[1]) : false;
        if (!is_string($line) || !str_starts_with($line, 'APRV_LISTEN=')) {
            $servers[$config] = ['refused' => is_resource($process) ? trim((string) stream_get_contents($pipes[2])) : 'cannot start aprv'];
        } else {
            $servers[$config] = ['process' => $process, 'pipes' => $pipes, 'url' => 'http://' . trim(substr($line, strlen('APRV_LISTEN=')))];
        }
    }
    if (isset($servers[$config]['refused'])) {
        return $servers[$config]['refused'];
    }
    $recorder = new Recorder(new HttpTransport($servers[$config]['url']));

    return [Verifier::create(Config::builder()->roots($roots)->clock($clock)->build(), $recorder), $recorder];
}

$options = getopt('', ['aprv:', 'calls:', 'reference:', 'suffix:', 'mode:', 'corpus:', 'out:']);
$aprv = $options['aprv'] ?? null;
$callsDir = $options['calls'] ?? null;
$referenceDir = $options['reference'] ?? null;
$suffix = $options['suffix'] ?? '';
$mode = $options['mode'] ?? 'cli';
$only = isset($options['corpus']) ? explode(',', (string) $options['corpus']) : CORPORA;
$outDir = $options['out'] ?? null;
if (!is_string($aprv) || !is_string($callsDir) || !is_string($referenceDir) || !in_array($mode, ['cli', 'http'], true)) {
    fwrite(STDERR, "usage: php tools/corpus.php --aprv PATH --calls DIR --reference DIR [--suffix .pinned] [--mode cli|http] [--corpus a,b] [--out DIR]\n");
    exit(2);
}

$tmp = sys_get_temp_dir() . '/aprv-corpus-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700);
$servers = [];
$verifiers = [];
$bad = 0;
foreach ($only as $corpus) {
    $reference = [];
    foreach (file("{$referenceDir}/module-{$corpus}.jsonl", FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $row = json_decode($line, true, 16, JSON_THROW_ON_ERROR);
        $reference[$row['id']] = $row;
    }
    $counts = ['identical' => 0, 'over-cap' => 0, 'roots-refused' => 0, 'DIFFERENT' => 0, 'facade-fault' => 0];
    $examples = [];
    $out = is_string($outDir) ? fopen("{$outDir}/{$mode}-{$corpus}.jsonl", 'wb') : null;
    $file = fopen("{$callsDir}/{$corpus}{$suffix}.jsonl", 'rb');
    $rows = 0;
    while (is_string($line = fgets($file))) {
        $call = json_decode($line, true, 16, JSON_THROW_ON_ERROR);
        ++$rows;
        $ref = $reference[$call['id']];
        $got = [];
        $fault = false;
        if (isset($call['map'])) {
            $got = ['map' => $call['map']];
        } else {
            $body = (string) base64_decode($call['b64'], true);
            $config = (string) ($call['config'] ?? '');
            $key = $config . '|' . $call['now'];
            if (!isset($verifiers[$key])) {
                // Bounded: a corpus with thousands of clock values would otherwise keep as
                // many live verifiers (each with a roots file); evicting one runs its destructor.
                while (count($verifiers) >= 4) {
                    array_shift($verifiers);
                }
                $verifiers[$key] = open($mode, $aprv, $config, (int) $call['now'], $servers, $tmp);
            }
            $opened = $verifiers[$key];
            if (is_string($opened)) {
                $parts = explode('configuration: ', $opened, 2);
                $got = count($parts) === 2 ? ['out' => $parts[1]] : ['trap' => $opened];
            } else {
                [$verifier, $recorder] = $opened;
                $result = match ($call['fn']) {
                    'verify-receipt' => $verifier->verifyReceipt($body),
                    'verify-signed-data' => $verifier->verifySignedData($body),
                    'verify-receipt-endpoint' => $verifier->verifyReceiptEndpoint($call['env'] === 0 ? Environment::Production : Environment::Sandbox, $body),
                    default => throw new RuntimeException('no adapter for ' . $call['fn']),
                };
                if ($recorder->tooLarge) {
                    $got = ['over_cap' => true];
                } elseif ($recorder->failure !== null) {
                    $got = ['trap' => get_class($recorder->failure) . ': ' . $recorder->failure->getMessage()];
                } else {
                    $got = ['out' => (string) $recorder->raw];
                    // The façade mapped a well-formed answer: it must not have turned it into a wrapper fault.
                    if (is_string($result)) {
                        $fault = $result !== $recorder->raw;
                    } elseif (!$result->verified()) {
                        $fault = $result->failure?->cause !== null;
                    }
                }
            }
        }
        $a = $ref['out'] ?? $ref['trap'] ?? $ref['map'] ?? null;
        $b = $got['out'] ?? $got['trap'] ?? $got['map'] ?? null;
        $refused = is_string($a) && (str_contains($a, '"reason":"TOO_LARGE"') || $a === '{"status":21002}');
        $category = match (true) {
            $fault => 'facade-fault',
            $a === $b && isset($ref['trap']) === isset($got['trap']) => 'identical',
            isset($got['over_cap']) && strlen($body ?? '') > MAX_BODY && $refused => 'over-cap',
            default => 'DIFFERENT',
        };
        if ($category === 'identical' && is_string($a) && str_contains($a, '"ok":false')) {
            $category = 'roots-refused';
        }
        ++$counts[$category];
        if (($category === 'DIFFERENT' || $category === 'facade-fault') && count($examples) < 12) {
            $examples[] = $call['id'] . ' ' . $category . ' got ' . substr(json_encode($got, JSON_INVALID_UTF8_SUBSTITUTE) ?: '', 0, 200) . ' want ' . substr(json_encode($ref, JSON_INVALID_UTF8_SUBSTITUTE) ?: '', 0, 200);
        }
        if (is_resource($out)) {
            fwrite($out, json_encode(['id' => $call['id']] + $got, JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
        }
        unset($body);
    }
    fclose($file);
    if (is_resource($out)) {
        fclose($out);
    }
    $bad += $counts['DIFFERENT'] + $counts['facade-fault'];
    printf("%-10s %-4s %5d rows: %s\n", $corpus, $mode, $rows, implode(', ', array_map(static fn (string $k, int $v): string => "{$v} {$k}", array_keys($counts), $counts)));
    foreach ($examples as $example) {
        echo "  {$example}\n";
    }
}
foreach ($servers as $server) {
    if (isset($server['process'])) {
        proc_terminate($server['process']);
        proc_close($server['process']);
    }
}
foreach (glob($tmp . '/*') ?: [] as $file) {
    @unlink($file);
}
@rmdir($tmp);
exit($bad > 0 ? 1 : 0);
