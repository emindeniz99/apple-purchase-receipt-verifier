<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

/**
 * Runs a snippet in a fresh PHP child with an explicit `memory_limit`.
 *
 * Memory exhaustion in PHP is a **fatal error, not a `Throwable`**: no
 * `catch (Throwable)` anywhere in this library can contain it, and the process
 * simply dies. That makes it impossible to assert on in-process — a test that
 * triggered it would take PHPUnit down with it — so the vectors that probe it
 * run out of band and the parent asserts on the child's exit code and output.
 *
 * `php.ini-production` ships `memory_limit = 128M`; that is the number these
 * tests hold the library to, because it is the number a default deployment
 * actually runs under.
 */
final class Subprocess
{
    public const PRODUCTION_MEMORY_LIMIT = '128M';

    /**
     * @return array{int, string} the child's exit code and its combined output
     */
    public static function run(string $code, string $memoryLimit = self::PRODUCTION_MEMORY_LIMIT): array
    {
        $file = tempnam(sys_get_temp_dir(), 'aprv-child-') . '.php';
        $autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';
        file_put_contents($file, "<?php\nrequire " . var_export($autoload, true) . ";\n" . $code);
        try {
            $command = escapeshellarg(PHP_BINARY)
                . ' -d memory_limit=' . escapeshellarg($memoryLimit)
                . ' -d error_reporting=-1 '
                . escapeshellarg($file) . ' 2>&1';
            $output = [];
            $status = 0;
            exec($command, $output, $status);

            return [$status, implode("\n", $output)];
        } finally {
            @unlink($file);
        }
    }
}
