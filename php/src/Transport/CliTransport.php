<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Info;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Text;
use InvalidArgumentException;
use LogicException;
use RuntimeException;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Exception\RuntimeException as ProcessRuntimeException;
use Symfony\Component\Process\Process;

/**
 * The default transport: one `aprv` process per call, its input on stdin
 * and its JSON on stdout (docs/rust-core/ARCHITECTURE.md §7.7, §7.9).
 *
 * symfony/process starts it from an argv array that carries only the
 * subcommand, the clock, the paths of the configuration files and the
 * `Config`'s distrust entries: nothing a receipt contains is ever on a
 * command line. It lives for one call
 * (about 12 ms) and ends with it: a hostile input reaches nothing that
 * outlives the call. Exit status 0 is a result (verified or not), 3 the
 * module's answer to an input over the size cap (on stdout, like any
 * result), 70 a trap, an ABI fault or a load failure.
 *
 * Custom roots go to `aprv` as one owner-only temporary file per transport
 * (`--roots FILE`), written by {@see open()} and deleted with the object;
 * so do the revocation issuers (`--revocation-issuer FILE`) and each
 * revocation list (`--revocation-list FILE`, the list's bytes as given).
 * Every call passes them, so every process's `init` runs on the same
 * configuration that `aprv info` accepted at {@see open()}.
 */
final class CliTransport implements Transport
{
    private ?string $binary = null;

    /** @var list<string> the temporary files this transport wrote, deleted with it */
    private array $files = [];

    /** @var list<string> the configuration's arguments: roots, revocation lists and issuers, distrust */
    private array $configArguments = [];

    private bool $opened = false;

    /**
     * The `limits.max_input_bytes` `aprv info` stated: the most of an input
     * sent on stdin. Null until {@see open()} has read it.
     */
    private ?int $maxInputBytes = null;

    /**
     * @param string|null $executable the `aprv` binary; null means the one
     *        `bin/aprv-install` put in this package's `php/bin/` directory
     * @param int $timeoutSeconds how long one process may run before it is
     *        killed, at least 1
     *
     * @throws InvalidArgumentException when the timeout is under one second
     */
    public function __construct(
        private readonly ?string $executable = null,
        private readonly int $timeoutSeconds = 30,
    ) {
        // symfony/process reads 0 as "no timeout"; a hung aprv must still end.
        if ($timeoutSeconds < 1) {
            throw new InvalidArgumentException('timeoutSeconds must be at least 1');
        }
    }

    /** Where `aprv-install` puts the binary, and where this transport looks by default. */
    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2) . '/bin/aprv' . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');
    }

    public function open(Config $config): RevocationState
    {
        if ($this->opened) {
            throw new LogicException('a transport serves one Verifier');
        }
        $this->opened = true;
        $missing = array_filter(
            ['proc_open', 'proc_get_status', 'proc_terminate', 'proc_close'],
            static fn (string $function): bool => !function_exists($function),
        );
        if ($missing !== []) {
            throw new RuntimeException(
                'the CLI transport needs ' . implode(', ', $missing) . ', which this PHP does not allow '
                . '(disable_functions): use HttpTransport with a server URL',
            );
        }
        $binary = $this->executable ?? self::defaultPath();
        if (!is_file($binary) || (PHP_OS_FAMILY !== 'Windows' && !is_executable($binary))) {
            throw new RuntimeException(
                'no aprv binary at ' . Text::printable($binary, 300) . ': run vendor/bin/aprv-install, '
                . 'pass CliTransport the path of an aprv binary, or use HttpTransport with a server URL',
            );
        }
        // Absolute, so a relative path runs that file rather than an aprv on PATH.
        $this->binary = realpath($binary) ?: $binary;

        $this->configArguments = $this->writeConfiguration($config);
        // `aprv info` runs the module's init on the configuration: a root,
        // list, issuer or distrust entry it refuses ends here, at create,
        // not in the first real call, and its answer states the input
        // length and the revocation state.
        [$code, $out, $err] = $this->execute(array_merge(['info'], $this->configArguments), '');
        // Exit 2 is also how the argument parser answers a flag it does not
        // know, which is what an aprv older than this package does with the
        // configuration flags; aprv itself prefixes every refusal of a
        // configuration with "aprv: ", the parser never does.
        if ($code === 2 && $this->configArguments !== [] && str_starts_with($err, 'aprv: ')) {
            throw new InvalidArgumentException('the verification module refused the configuration: ' . Text::printable($err));
        }
        if ($code === 2 && $this->configArguments !== []) {
            throw new RuntimeException(
                $this->describe('aprv info', $code, $err)
                . ': install the aprv binary that belongs to this package version',
            );
        }
        if ($code !== 0) {
            throw new RuntimeException($this->describe('aprv info', $code, $err));
        }
        $info = Info::decode($out, 'aprv info');
        $this->maxInputBytes = Info::maxInputBytes($info, 'aprv info');

        return Info::revocationState($info, 'aprv info');
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        $maxInputBytes = $this->maxInputBytes
            ?? throw new LogicException('call() before a successful open(): Verifier::create() opens a transport before its first call');
        $arguments = array_merge($operation->cliArguments(), ['--now-ms', (string) $nowMs], $this->configArguments);
        [$code, $out, $err] = $this->execute($arguments, substr($input, 0, $maxInputBytes));
        // 3: the input was over the cap; stdout is still the module's answer.
        if ($code === 0 || $code === 3) {
            return $out;
        }
        if ($code === 70) {
            throw new ModuleFaultException('EXIT_70', 'aprv trapped, broke the interface or could not load: ' . Text::printable($err));
        }
        throw new ServerProcessException($this->describe('aprv', $code, $err));
    }

    public function __destruct()
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }
        $this->files = [];
    }

    /**
     * Writes the configuration's files and returns its arguments: the
     * roots and the issuers each as one file of base64 lines (DER or PEM
     * bytes, which `aprv` tells apart), each list as a file of its bytes,
     * and each distrust entry as `--distrust=ISSUER:SERIAL`, written with
     * `=` so a value that starts with a dash stays a value.
     *
     * @return list<string>
     *
     * @throws InvalidArgumentException when a distrust entry holds a NUL byte, which no command line carries
     * @throws RuntimeException when a file cannot be written
     */
    private function writeConfiguration(Config $config): array
    {
        $arguments = [];
        if ($config->roots !== null) {
            array_push($arguments, '--roots', $this->writeFile('roots', self::base64Lines($config->roots)));
        }
        foreach ($config->revocationLists as $list) {
            array_push($arguments, '--revocation-list', $this->writeFile('revocation-list', $list));
        }
        if ($config->revocationIssuers !== []) {
            array_push($arguments, '--revocation-issuer', $this->writeFile('revocation-issuers', self::base64Lines($config->revocationIssuers)));
        }
        foreach ($config->distrust as $index => $entry) {
            $value = $entry->issuer . ':' . $entry->serial;
            if (str_contains($value, "\0")) {
                throw new InvalidArgumentException("distrust[{$index}] holds a NUL byte");
            }
            $arguments[] = '--distrust=' . $value;
        }

        return $arguments;
    }

    /** @param list<string> $certificates */
    private static function base64Lines(array $certificates): string
    {
        $lines = '';
        foreach ($certificates as $bytes) {
            $lines .= base64_encode($bytes) . "\n";
        }

        return $lines;
    }

    /** @throws RuntimeException */
    private function writeFile(string $what, string $contents): string
    {
        // tempnam() creates the file with mode 0600: owner-only.
        $path = @tempnam(sys_get_temp_dir(), "aprv-{$what}-");
        if ($path === false) {
            throw new RuntimeException("cannot create the {$what} file in " . Text::printable(sys_get_temp_dir(), 200));
        }
        $this->files[] = $path;
        if (@file_put_contents($path, $contents) !== strlen($contents)) {
            throw new RuntimeException("cannot write the {$what} file");
        }

        return $path;
    }

    private function describe(string $what, int $code, string $stderr): string
    {
        $detail = Text::printable($stderr);

        $ended = $code < 0 ? "{$what} ended without an exit status" : "{$what} exited with status {$code}";

        return $ended . ($detail === '' ? '' : ': ' . $detail);
    }

    /**
     * @param list<string> $arguments
     *
     * @return array{int, string, string} the exit status (-1 when a signal ended it), stdout and stderr
     *
     * @throws ServerProcessException when the process cannot be started or outlives its timeout
     */
    private function execute(array $arguments, string $stdin): array
    {
        $out = '';
        $err = '';
        try {
            $process = new Process(
                array_merge([(string) $this->binary], $arguments),
                null,
                self::environment(),
                $stdin,
                $this->timeoutSeconds,
            );
            // symfony/process would buffer the answer in php://temp, which
            // spills past 1 MiB to a temporary file; the callback keeps it
            // in these two strings instead.
            $process->disableOutput();
            $code = $process->run(static function (string $type, string $chunk) use (&$out, &$err): void {
                if ($type === Process::OUT) {
                    $out .= $chunk;
                } else {
                    $err .= $chunk;
                }
            });
        } catch (ProcessSignaledException) {
            $code = -1;
        } catch (ProcessTimedOutException) {
            throw new ServerProcessException('aprv did not answer within ' . $this->timeoutSeconds . ' seconds');
        } catch (ProcessRuntimeException) {
            throw new ServerProcessException('aprv could not be started');
        }

        return [$code, $out, $err];
    }

    /**
     * The child's environment: what the OS needs to start a binary, and
     * nothing else. symfony/process otherwise passes getenv() and $_ENV,
     * which holds what Dotenv loaded (and, under FPM before 6.4.41, 7.4.13
     * and 8.0.13, the request's variables). aprv's one-shot commands read
     * no variable. Every other name is set to false, which symfony/process
     * reads as "unset".
     *
     * @return array<string, string|false>
     */
    private static function environment(): array
    {
        $windows = PHP_OS_FAMILY === 'Windows';
        // cmd.exe, which starts the binary on Windows, needs SystemRoot and ComSpec.
        $keep = $windows ? ['PATH', 'SYSTEMROOT', 'COMSPEC'] : ['PATH'];
        $env = [];
        foreach (getenv() + $_ENV as $name => $value) {
            $name = (string) $name;
            $kept = in_array($windows ? strtoupper($name) : $name, $keep, true) && is_string($value);
            $env[$name] = $kept ? $value : false;
        }

        return $env;
    }
}
