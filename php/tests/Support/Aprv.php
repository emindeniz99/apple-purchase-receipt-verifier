<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use InvalidArgumentException;
use RuntimeException;

/**
 * Finds the `aprv` binary the suite runs against, and starts servers from
 * it. The binary is never committed: `APRV_BIN` names it, and without that
 * the suite looks where `bin/aprv-install` puts it. A missing binary is a
 * hard error, not a skip.
 */
final class Aprv
{
    private static ?string $componentSha256 = null;

    public static function binary(): string
    {
        $path = getenv('APRV_BIN');
        $path = is_string($path) && $path !== '' ? $path : CliTransport::defaultPath();
        if (!is_file($path) || !is_executable($path)) {
            throw new RuntimeException(
                "no aprv binary at {$path}: set APRV_BIN to one, or run bin/aprv-install "
                . '(the suite needs the real binary; it never skips)',
            );
        }

        return $path;
    }

    /** The SHA-256 of the component the binary runs, from `aprv info`. */
    public static function componentSha256(): string
    {
        if (self::$componentSha256 === null) {
            $out = shell_exec(escapeshellarg(self::binary()) . ' info 2>/dev/null');
            $info = is_string($out) ? json_decode($out, true) : null;
            $hash = is_array($info) ? ($info['component_sha256'] ?? null) : null;
            if (!is_string($hash)) {
                throw new RuntimeException('aprv info did not report component_sha256');
            }
            self::$componentSha256 = $hash;
        }

        return self::$componentSha256;
    }

    /**
     * Starts `aprv serve` on a free loopback port.
     *
     * @param string|null $rootsFile base64 DER lines, or null for the built-in roots
     * @param list<string> $flags more flags: the revocation settings
     *
     * @throws InvalidArgumentException when the server exits 2: a configuration init refused
     */
    public static function startServer(?string $rootsFile = null, ?string $token = null, array $flags = []): ServerProcess
    {
        $tokenFile = null;
        $arguments = [self::binary(), 'serve', '--listen', '127.0.0.1:0', ...$flags];
        if ($rootsFile !== null) {
            array_push($arguments, '--roots', $rootsFile);
        }
        if ($token !== null) {
            $tokenFile = (string) tempnam(sys_get_temp_dir(), 'aprv-token-');
            file_put_contents($tokenFile, $token . "\n");
            array_push($arguments, '--token-file', $tokenFile);
        }
        $process = proc_open($arguments, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start aprv serve');
        }
        stream_set_timeout($pipes[1], 30);
        $line = fgets($pipes[1]);
        if (!is_string($line) || preg_match('/^APRV_LISTEN=(127\.0\.0\.1:\d+)$/', trim($line), $match) !== 1) {
            // A server that printed something else, or nothing within the
            // timeout, may still be running, and reading its stderr or
            // closing it would then wait for it forever: stop it first. One
            // that closed its stdout is exiting, and its exit status says
            // whether it refused its configuration.
            if (is_string($line) || stream_get_meta_data($pipes[1])['timed_out']) {
                proc_terminate($process);
            }
            $error = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $code = proc_close($process);
            if ($code === 2) {
                throw new InvalidArgumentException('aprv serve refused its configuration: ' . $error);
            }
            throw new RuntimeException('aprv serve did not start: ' . $error);
        }

        return new ServerProcess($process, $pipes, 'http://' . $match[1], $tokenFile);
    }
}
