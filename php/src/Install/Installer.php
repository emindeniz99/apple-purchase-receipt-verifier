<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Install;

/**
 * `aprv install`: puts the `aprv` binary for this platform where
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport}
 * looks for it (docs/rust-core/DECISIONS.md R29).
 *
 * The binary comes from the GitHub Release the package was cut with and is
 * checked against the SHA-256 that `binaries.json` pins in the package. It
 * is written to a temporary owner-only file beside its destination, hashed
 * there, and made executable and renamed into place only when the hash
 * matches: a wrong hash installs nothing, and an existing binary stays as
 * it was. Nothing downloads at request time.
 *
 * This class is self-contained (no autoloader, no other package class), so
 * `bin/aprv-install` runs from a checkout, from `vendor/bin` and before
 * `composer install` has run.
 */
final class Installer
{
    /** No release binary is larger than this; a download that passes it is cut off. */
    private const MAX_BYTES = 64 * 1024 * 1024;

    /** The pinned hashes' asset names, by platform: `aprv-<target>[.exe]`. */
    private const TARGETS = [
        'Linux' => ['x86_64' => 'x86_64-unknown-linux-musl', 'aarch64' => 'aarch64-unknown-linux-musl', 'arm64' => 'aarch64-unknown-linux-musl'],
        'Darwin' => ['x86_64' => 'x86_64-apple-darwin', 'arm64' => 'aarch64-apple-darwin', 'aarch64' => 'aarch64-apple-darwin'],
        'Windows' => ['AMD64' => 'x86_64-pc-windows-msvc', 'x86_64' => 'x86_64-pc-windows-msvc', 'ARM64' => 'aarch64-pc-windows-msvc'],
    ];

    private function __construct()
    {
    }

    /** The release target of this machine, or null where no binary is published. */
    public static function detectTarget(?string $os = null, ?string $machine = null): ?string
    {
        return self::TARGETS[$os ?? PHP_OS_FAMILY][$machine ?? php_uname('m')] ?? null;
    }

    /** The name a release asset of `$target` carries. */
    public static function assetName(string $target): string
    {
        return 'aprv-' . $target . (str_contains($target, 'windows') ? '.exe' : '');
    }

    /**
     * @param string $manifestPath the package's `binaries.json`
     * @param string $directory where the binary goes, as `aprv` (`aprv.exe` on Windows)
     * @param string|null $baseUrl replaces the GitHub Release URL of the pinned tag; HTTPS, or HTTP to loopback
     * @param string|null $target replaces the detected release target
     * @param bool $force downloads even when the installed binary already has the pinned hash
     * @param array{string, string}|null $platform `[PHP_OS_FAMILY, machine]` to detect the target from, in place of this machine's
     *
     * @return string what was done, for the person running it
     *
     * @throws InstallException
     */
    public static function install(
        string $manifestPath,
        string $directory,
        ?string $baseUrl = null,
        ?string $target = null,
        bool $force = false,
        ?array $platform = null,
    ): string {
        $manifest = self::manifest($manifestPath);
        $target ??= self::detectTarget($platform[0] ?? null, $platform[1] ?? null);
        if ($target === null) {
            throw new InstallException(
                'no aprv binary is published for ' . ($platform[0] ?? PHP_OS_FAMILY) . ' ' . ($platform[1] ?? php_uname('m'))
                . '. Run an aprv server where a binary exists (Docker image or binary) and pass '
                . 'HttpTransport(\'http://host:8080\', $token) to Verifier::create().',
                InstallException::UNAVAILABLE,
            );
        }
        $asset = self::assetName($target);
        $pinned = $manifest['assets'][$asset] ?? null;
        if (!is_string($pinned) || preg_match('/^[0-9a-f]{64}$/', $pinned) !== 1) {
            throw new InstallException(
                "binaries.json pins no SHA-256 for {$asset}: this checkout has no release binaries. "
                . 'Use HttpTransport with an aprv server, or install a released version of the package.',
                InstallException::UNAVAILABLE,
            );
        }
        $url = ($baseUrl ?? self::releaseUrl($manifest)) . '/' . $asset;
        if (!self::urlAllowed($url)) {
            throw new InstallException('the download URL must be https, or http to loopback: ' . $url, InstallException::UNAVAILABLE);
        }

        $final = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . (str_contains($target, 'windows') ? 'aprv.exe' : 'aprv');
        if (!$force && is_file($final) && hash_file('sha256', $final) === $pinned) {
            return "aprv is already installed at {$final} (SHA-256 {$pinned})";
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new InstallException("cannot create {$directory}");
        }

        // tempnam() makes the file with mode 0600: owner-only until the hash matches.
        $temporary = @tempnam($directory, '.aprv-download-');
        if ($temporary === false) {
            throw new InstallException("cannot write in {$directory}");
        }
        try {
            self::download($url, $temporary);
            $actual = hash_file('sha256', $temporary);
            if ($actual === false || !hash_equals($pinned, $actual)) {
                throw new InstallException(
                    "the download of {$asset} has SHA-256 " . ($actual === false ? 'unreadable' : $actual)
                    . ", binaries.json pins {$pinned}: nothing was installed",
                );
            }
            if (PHP_OS_FAMILY !== 'Windows') {
                chmod($temporary, 0700);
            } elseif (is_file($final)) {
                @unlink($final);
            }
            if (!@rename($temporary, $final)) {
                throw new InstallException("cannot move the binary to {$final}");
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }

        return "installed {$asset} at {$final} (SHA-256 {$pinned})";
    }

    /**
     * @return array{tag: mixed, repository: mixed, assets: array<string, mixed>}
     *
     * @throws InstallException
     */
    private static function manifest(string $path): array
    {
        $text = @file_get_contents($path);
        $data = $text === false ? null : json_decode($text, true);
        if (!is_array($data) || !is_array($data['assets'] ?? null)) {
            throw new InstallException("cannot read the manifest {$path}", InstallException::UNAVAILABLE);
        }

        $assets = [];
        foreach ($data['assets'] as $name => $hash) {
            $assets[(string) $name] = $hash;
        }

        return ['tag' => $data['tag'] ?? null, 'repository' => $data['repository'] ?? null, 'assets' => $assets];
    }

    /**
     * @param array{tag: mixed, repository: mixed, assets: array<string, mixed>} $manifest
     *
     * @throws InstallException
     */
    private static function releaseUrl(array $manifest): string
    {
        $tag = $manifest['tag'];
        $repository = $manifest['repository'];
        if (!is_string($tag) || !is_string($repository)
            || preg_match('#^v[0-9A-Za-z.+-]+$#', $tag) !== 1
            || preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repository) !== 1) {
            throw new InstallException(
                'binaries.json names no release tag: this checkout has no release binaries. '
                . 'Use HttpTransport with an aprv server, or install a released version of the package.',
                InstallException::UNAVAILABLE,
            );
        }

        return "https://github.com/{$repository}/releases/download/{$tag}";
    }

    /** HTTPS anywhere; plain HTTP only to this machine, which the tests and a local mirror use. */
    private static function urlAllowed(string $url): bool
    {
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower($parts['host'] ?? '');

        return $scheme === 'https' || ($scheme === 'http' && in_array($host, ['127.0.0.1', 'localhost', '[::1]'], true));
    }

    /** @throws InstallException */
    private static function download(string $url, string $destination): void
    {
        $file = fopen($destination, 'wb');
        if ($file === false) {
            throw new InstallException("cannot write {$destination}");
        }
        try {
            if (extension_loaded('curl')) {
                self::downloadWithCurl($url, $file);
            } elseif (str_starts_with($url, 'https://') && !extension_loaded('openssl')) {
                throw new InstallException('downloading over HTTPS needs ext-curl or ext-openssl', InstallException::UNAVAILABLE);
            } else {
                self::downloadWithStreams($url, $file);
            }
        } finally {
            fclose($file);
        }
    }

    /**
     * @param resource $file
     *
     * @throws InstallException
     */
    private static function downloadWithCurl(string $url, $file): void
    {
        $written = 0;
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_FAILONERROR => true,
            CURLOPT_WRITEFUNCTION => static function ($handle, string $data) use ($file, &$written): int {
                $written += strlen($data);
                if ($written > self::MAX_BYTES) {
                    return 0;
                }

                return (int) fwrite($file, $data);
            },
        ]);
        $ok = curl_exec($curl);
        $error = curl_error($curl);
        $effective = (string) curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
        if ($written > self::MAX_BYTES) {
            throw new InstallException('the download is larger than ' . self::MAX_BYTES . ' bytes: cut off');
        }
        if ($ok !== true) {
            throw new InstallException("cannot download {$url}: {$error}");
        }
        if (!self::urlAllowed($effective)) {
            throw new InstallException("the download was redirected to a URL that is not https: {$effective}");
        }
    }

    /**
     * @param resource $file
     *
     * @throws InstallException
     */
    private static function downloadWithStreams(string $url, $file): void
    {
        $context = stream_context_create(['http' => ['timeout' => 300, 'follow_location' => 1, 'max_redirects' => 5]]);
        $source = @fopen($url, 'rb', false, $context);
        if ($source === false) {
            throw new InstallException("cannot download {$url}");
        }
        $status = 0;
        // The http wrapper's response headers, every hop's, from the stream
        // itself: PHP 8.5 deprecates the magic local variable at compile
        // time, even behind a function_exists() check.
        $headers = stream_get_meta_data($source)['wrapper_data'] ?? [];
        foreach ((array) $headers as $line) {
            if (is_string($line) && preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $match) === 1) {
                $status = (int) $match[1];
            }
        }
        if ($status !== 200) {
            fclose($source);
            throw new InstallException("cannot download {$url}: HTTP {$status}");
        }
        $written = 0;
        while (!feof($source)) {
            $chunk = fread($source, 65536);
            if ($chunk === false) {
                break;
            }
            $written += strlen($chunk);
            if ($written > self::MAX_BYTES) {
                fclose($source);
                throw new InstallException('the download is larger than ' . self::MAX_BYTES . ' bytes: cut off');
            }
            fwrite($file, $chunk);
        }
        fclose($source);
    }
}
