<?php

declare(strict_types=1);

/**
 * Pins the hashes of a release's aprv binaries in php/binaries.json, which is
 * what `bin/aprv-install` checks a download against. Run it on the release
 * branch, before the tag, with the SHA256SUMS of the binaries the release
 * will publish (docs/rust-core/MIGRATION.md, "Release artifact matrix"):
 *
 *   php php/tools/update-binaries.php --tag v0.8.0 --sums SHA256SUMS
 *
 * SHA256SUMS lines are `<64 hex>  <asset name>` (an optional `*` before the
 * name is accepted). Only the assets binaries.json lists are read; a listed
 * asset the file does not carry is reset to null with a warning, so an
 * installer on that platform answers "no binary" instead of pinning a stale
 * hash. Exit status 0 wrote the manifest, 1 wrote nothing.
 *
 * Options: --manifest FILE (default php/binaries.json).
 */

/**
 * @param array{tag: string, sums: string, manifest: string} $options
 *
 * @throws RuntimeException
 */
function updateBinaries(array $options): string
{
    $manifest = json_decode((string) @file_get_contents($options['manifest']), true);
    if (!is_array($manifest) || !is_array($manifest['assets'] ?? null)) {
        throw new RuntimeException("cannot read the manifest {$options['manifest']}");
    }
    if (preg_match('/^v[0-9A-Za-z.+-]+$/', $options['tag']) !== 1) {
        throw new RuntimeException('the tag must look like v0.8.0');
    }
    $sums = @file($options['sums'], FILE_IGNORE_NEW_LINES);
    if ($sums === false) {
        throw new RuntimeException("cannot read {$options['sums']}");
    }
    $hashes = [];
    foreach ($sums as $line) {
        if (preg_match('/^([0-9a-f]{64}) [ *](\S+)$/', $line, $match) === 1) {
            $hashes[$match[2]] = $match[1];
        }
    }
    $log = '';
    $pinned = 0;
    $assets = [];
    foreach (array_keys($manifest['assets']) as $name) {
        $name = (string) $name;
        $assets[$name] = $hashes[$name] ?? null;
        if ($assets[$name] === null) {
            $log .= "warning: {$name} is not in the SHA-256 list: no hash is pinned for it\n";
        } else {
            ++$pinned;
        }
    }
    if ($pinned === 0) {
        throw new RuntimeException('none of the assets binaries.json lists is in the SHA-256 list: nothing written');
    }
    $manifest['tag'] = $options['tag'];
    $manifest['assets'] = $assets;
    file_put_contents($options['manifest'], json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");

    return $log . "pinned {$pinned} of " . count($assets) . " assets for {$options['tag']}\n";
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $given = getopt('', ['tag:', 'sums:', 'manifest:']);
    $tag = $given['tag'] ?? null;
    $sums = $given['sums'] ?? null;
    $manifest = $given['manifest'] ?? dirname(__DIR__) . '/binaries.json';
    if (!is_string($tag) || !is_string($sums) || !is_string($manifest)) {
        fwrite(STDERR, "usage: php update-binaries.php --tag v0.8.0 --sums SHA256SUMS [--manifest FILE]\n");
        exit(1);
    }
    try {
        fwrite(STDOUT, updateBinaries(['tag' => $tag, 'sums' => $sums, 'manifest' => $manifest]));
    } catch (RuntimeException $e) {
        fwrite(STDERR, 'update-binaries: ' . $e->getMessage() . "\n");
        exit(1);
    }
}
