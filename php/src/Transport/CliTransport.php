<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Info;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Input;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Text;
use InvalidArgumentException;
use LogicException;
use RuntimeException;

/**
 * The default transport: one `aprv` process per call, its input on stdin
 * and its JSON on stdout (docs/rust-core/ARCHITECTURE.md §7.7, §7.9).
 *
 * The process is started with an argv array and no shell, so nothing the
 * caller or a receipt contains is ever parsed by one. It lives for one call
 * (about 12 ms) and ends with it: a hostile input reaches nothing that
 * outlives the call. Exit status 0 is a result (verified or not), 3 the
 * module's answer to an input over the size cap (on stdout, like any
 * result), 70 a trap, an ABI fault or a load failure.
 *
 * Custom roots go to `aprv` as one owner-only temporary file per transport
 * (`--roots FILE`), written by {@see open()} and deleted with the object.
 */
final class CliTransport implements Transport
{
    private ?string $binary = null;

    private ?string $rootsFile = null;

    private bool $opened = false;

    /**
     * @param string|null $executable the `aprv` binary; null means the one
     *        `bin/aprv-install` put in this package's `php/bin/` directory
     * @param int $timeoutSeconds how long one process may run before it is killed
     */
    public function __construct(
        private readonly ?string $executable = null,
        private readonly int $timeoutSeconds = 30,
    ) {
    }

    /** Where `aprv-install` puts the binary, and where this transport looks by default. */
    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2) . '/bin/aprv' . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');
    }

    public function open(?array $roots): void
    {
        if ($this->opened) {
            throw new LogicException('a transport serves one Verifier');
        }
        $this->opened = true;
        $binary = $this->executable ?? self::defaultPath();
        if (!is_file($binary) || (PHP_OS_FAMILY !== 'Windows' && !is_executable($binary))) {
            throw new RuntimeException(
                'no aprv binary at ' . Text::printable($binary, 300) . ': run vendor/bin/aprv-install, '
                . 'pass CliTransport the path of an aprv binary, or use HttpTransport with a server URL',
            );
        }
        $this->binary = $binary;

        [$code, $out, $err] = $this->execute(['info'], '');
        if ($code !== 0) {
            throw new RuntimeException($this->describe('aprv info', $code, $err));
        }
        Info::decode($out, 'aprv info');

        if ($roots === null) {
            return;
        }
        $this->rootsFile = $this->writeRoots($roots);
        // Nothing reads the roots until a verification runs, so run one on
        // no input: a root the module refuses ends here, at create, not in
        // the first real call.
        [$code, , $err] = $this->execute(
            array_merge(Operation::SignedData->cliArguments(), $this->rootsArguments()),
            '',
        );
        if ($code === 2) {
            throw new InvalidArgumentException('the verification module refused the roots: ' . Text::printable($err));
        }
        if ($code !== 0) {
            throw new RuntimeException($this->describe('aprv', $code, $err));
        }
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        $arguments = array_merge($operation->cliArguments(), ['--now-ms', (string) $nowMs], $this->rootsArguments());
        [$code, $out, $err] = $this->execute($arguments, substr($input, 0, Input::MAX_BYTES));
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
        if ($this->rootsFile !== null) {
            @unlink($this->rootsFile);
            $this->rootsFile = null;
        }
    }

    /** @return list<string> */
    private function rootsArguments(): array
    {
        return $this->rootsFile === null ? [] : ['--roots', $this->rootsFile];
    }

    /**
     * @param list<string> $roots
     *
     * @throws RuntimeException
     */
    private function writeRoots(array $roots): string
    {
        $lines = '';
        foreach ($roots as $der) {
            $lines .= base64_encode($der) . "\n";
        }
        // tempnam() creates the file with mode 0600: owner-only.
        $path = @tempnam(sys_get_temp_dir(), 'aprv-roots-');
        if ($path === false) {
            throw new RuntimeException('cannot create the roots file in ' . Text::printable(sys_get_temp_dir(), 200));
        }
        if (@file_put_contents($path, $lines) !== strlen($lines)) {
            @unlink($path);
            throw new RuntimeException('cannot write the roots file');
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
     * @return array{int, string, string} the exit status, stdout and stderr
     *
     * @throws ServerProcessException when the process cannot be started or outlives its timeout
     */
    private function execute(array $arguments, string $stdin): array
    {
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        // An argv array and no shell: nothing is interpolated or parsed.
        $process = @proc_open(
            array_merge([(string) $this->binary], $arguments),
            $descriptors,
            $pipes,
            null,
            null,
            ['bypass_shell' => true],
        );
        if (!is_resource($process)) {
            throw new ServerProcessException('aprv could not be started');
        }

        $timedOut = false;
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows pipes cannot be polled. aprv reads its whole input
            // before it writes anything, so writing all, then reading all,
            // cannot deadlock.
            [$out, $err] = self::exchangeBlocking($pipes, $stdin);
        } else {
            [$out, $err, $timedOut] = self::exchange($pipes, $stdin, $this->timeoutSeconds);
        }
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        if ($timedOut) {
            proc_terminate($process, 9);
            proc_close($process);
            throw new ServerProcessException('aprv did not answer within ' . $this->timeoutSeconds . ' seconds');
        }

        return [proc_close($process), $out, $err];
    }

    /**
     * Writes stdin and reads stdout and stderr together without deadlocking
     * on a large body, until both outputs end or the timeout passes.
     *
     * @param array<int, resource> $pipes
     *
     * @return array{string, string, bool} stdout, stderr, whether the timeout passed
     */
    private static function exchange(array $pipes, string $stdin, int $timeoutSeconds): array
    {
        foreach ($pipes as $pipe) {
            stream_set_blocking($pipe, false);
        }
        $out = '';
        $err = '';
        $offset = 0;
        $length = strlen($stdin);
        $deadline = microtime(true) + $timeoutSeconds;
        $inputOpen = true;
        while (true) {
            if ($inputOpen && $offset >= $length) {
                fclose($pipes[0]);
                $inputOpen = false;
            }
            $read = [];
            foreach ([1, 2] as $index) {
                if (!feof($pipes[$index])) {
                    $read[] = $pipes[$index];
                }
            }
            if ($read === []) {
                return [$out, $err, false];
            }
            $write = $inputOpen ? [$pipes[0]] : [];
            $except = null;
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                return [$out, $err, true];
            }
            $ready = @stream_select($read, $write, $except, 0, min(500_000, (int) ($remaining * 1_000_000)));
            if ($ready === false || $ready === 0) {
                continue;
            }
            if (in_array($pipes[0], $write, true)) {
                // A child that ended early (the size cap) closes its end:
                // stop writing and read what it said.
                $written = @fwrite($pipes[0], substr($stdin, $offset, 65536));
                if ($written === false) {
                    fclose($pipes[0]);
                    $inputOpen = false;
                } else {
                    $offset += $written;
                }
            }
            foreach ($read as $stream) {
                $chunk = fread($stream, 65536);
                if ($chunk === false || $chunk === '') {
                    continue;
                }
                if ($stream === $pipes[1]) {
                    $out .= $chunk;
                } else {
                    $err .= $chunk;
                }
            }
        }
    }

    /**
     * @param array<int, resource> $pipes
     *
     * @return array{string, string}
     */
    private static function exchangeBlocking(array $pipes, string $stdin): array
    {
        $offset = 0;
        $length = strlen($stdin);
        while ($offset < $length) {
            $written = @fwrite($pipes[0], substr($stdin, $offset, 65536));
            if ($written === false || $written === 0) {
                break;
            }
            $offset += $written;
        }
        fclose($pipes[0]);

        return [(string) stream_get_contents($pipes[1]), (string) stream_get_contents($pipes[2])];
    }
}
