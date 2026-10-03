<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use RuntimeException;

/**
 * A fake `aprv` executable in a temporary directory: a shell wrapper that
 * runs `fake-aprv.php`, which logs every invocation and answers as
 * {@see behave()} says.
 */
final class FakeCli
{
    public readonly string $directory;

    public readonly string $executable;

    public function __construct(string $name = 'aprv')
    {
        $directory = tempnam(sys_get_temp_dir(), 'aprv-fake-');
        if ($directory === false) {
            throw new RuntimeException('cannot create a temporary directory');
        }
        unlink($directory);
        mkdir($directory, 0700);
        $this->directory = $directory;
        $this->executable = $directory . '/' . $name;
        $script = "#!/bin/sh\nFAKE_APRV_DIR=" . escapeshellarg($directory)
            . ' exec ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/fake-aprv.php') . " \"\$@\"\n";
        file_put_contents($this->executable, $script);
        chmod($this->executable, 0700);
        $this->behave([]);
    }

    /** @param array<string, mixed> $mode */
    public function behave(array $mode): void
    {
        file_put_contents($this->directory . '/mode.json', json_encode($mode, JSON_THROW_ON_ERROR));
    }

    /** @return list<array{argv: list<string>, stdin_length: int, stdin_sha256: string, roots_file: string|null, roots_file_mode: string|null, roots_file_content: string|null}> */
    public function log(): array
    {
        $entries = [];
        $log = $this->directory . '/log.jsonl';
        if (!is_file($log)) {
            return $entries; // the fake never ran
        }
        foreach (file($log, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            /** @var array{argv: list<string>, stdin_length: int, stdin_sha256: string, roots_file: string|null, roots_file_mode: string|null, roots_file_content: string|null} $entry */
            $entry = json_decode($line, true, 8, JSON_THROW_ON_ERROR);
            $entries[] = $entry;
        }

        return $entries;
    }

    public function remove(): void
    {
        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
        @rmdir($this->directory);
    }
}
