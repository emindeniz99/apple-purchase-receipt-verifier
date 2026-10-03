<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Install;

/**
 * `aprv install`: puts the `aprv` binary for this platform where
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport}
 * looks for it (docs/rust-core/DECISIONS.md R29).
 *
 * The binary comes from the GitHub Release the package was cut with and is
 * checked against the SHA-256 that `SHA256SUMS` pins in the package. It
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

    /** Where the releases are: `https://github.com/<repository>/releases/download/<tag>/<asset>`. */
    private const REPOSITORY = 'emindeniz99/apple-purchase-receipt-verifier';

    /**
     * A `SHA256SUMS` line as sha256sum's text mode writes it for a file laid
     * out as `<tag>/<asset>`: 64 lowercase hex digits, two spaces, the path.
     */
    private const SUMS_LINE = '#^([0-9a-f]{64})  (v[0-9A-Za-z.+-]+)/([^/\s]+)$#';

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
     * @param string $sumsPath the package's `SHA256SUMS`
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
        string $sumsPath,
        string $directory,
        ?string $baseUrl = null,
        ?string $target = null,
        bool $force = false,
        ?array $platform = null,
    ): string {
        $sums = self::pins($sumsPath);
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
        $pinned = $sums['assets'][$asset] ?? null;
        if ($pinned === null || $sums['tag'] === null) {
            throw new InstallException(
                "SHA256SUMS pins no SHA-256 for {$asset}: this checkout has no release binaries. "
                . 'Use HttpTransport with an aprv server, or install a released version of the package.',
                InstallException::UNAVAILABLE,
            );
        }
        $url = ($baseUrl ?? 'https://github.com/' . self::REPOSITORY . '/releases/download/' . $sums['tag']) . '/' . $asset;
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
                    . ", SHA256SUMS pins {$pinned}: nothing was installed",
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
     * Reads the package's `SHA256SUMS`: the release tag and the pinned
     * SHA-256 of each release asset. Every line is sha256sum's text output
     * for a file laid out as `<tag>/<asset>`, so `sha256sum -c --strict`
     * run where the release's assets sit under `<tag>/` checks the same
     * claim. An empty file pins nothing (a checkout between releases).
     * Anything else is refused: a binary-mode `*`, a tagged line, a path
     * that is not one tag and one release asset, a blank line, a CR, an
     * asset named twice, or two tags.
     *
     * @return array{tag: string|null, assets: array<string, string>}
     *
     * @throws InstallException
     */
    public static function pins(string $sumsPath): array
    {
        $text = @file_get_contents($sumsPath);
        if ($text === false) {
            throw new InstallException("cannot read {$sumsPath}", InstallException::UNAVAILABLE);
        }
        $known = [];
        foreach (self::TARGETS as $machines) {
            foreach ($machines as $target) {
                $known[self::assetName($target)] = true;
            }
        }

        $tag = null;
        $assets = [];
        $lines = $text === '' ? [] : explode("\n", str_ends_with($text, "\n") ? substr($text, 0, -1) : $text);
        foreach ($lines as $index => $line) {
            $where = $sumsPath . ' line ' . ($index + 1);
            if (preg_match(self::SUMS_LINE, $line, $match) !== 1) {
                throw new InstallException(
                    "{$where} is not `<sha256>  <tag>/<asset>` as sha256sum writes it: "
                    . (string) json_encode($line, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES),
                    InstallException::UNAVAILABLE,
                );
            }
            [, $hash, $lineTag, $asset] = $match;
            if (!isset($known[$asset])) {
                throw new InstallException("{$where} names {$asset}, which is not a release asset", InstallException::UNAVAILABLE);
            }
            if ($tag !== null && $lineTag !== $tag) {
                throw new InstallException("{$where} names the tag {$lineTag}, an earlier line {$tag}", InstallException::UNAVAILABLE);
            }
            if (isset($assets[$asset])) {
                throw new InstallException("{$where} pins {$asset} a second time", InstallException::UNAVAILABLE);
            }
            $tag = $lineTag;
            $assets[$asset] = $hash;
        }

        return ['tag' => $tag, 'assets' => $assets];
    }

    /** HTTPS anywhere; plain HTTP only to this machine, which the tests and a local mirror use. */
    private static function urlAllowed(string $url): bool
    {
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower($parts['host'] ?? '');

        return $scheme === 'https' || ($scheme === 'http' && in_array($host, ['127.0.0.1', 'localhost', '[::1]'], true));
    }

    /**
     * Fetches `$url` into `$destination` with ext-curl, following at most
     * five redirects; a download that ends anywhere but HTTPS (or HTTP to
     * loopback) is refused.
     *
     * @throws InstallException
     */
    private static function download(string $url, string $destination): void
    {
        if (!extension_loaded('curl')) {
            throw new InstallException('aprv-install needs ext-curl to download the binary', InstallException::UNAVAILABLE);
        }
        $file = fopen($destination, 'wb');
        if ($file === false) {
            throw new InstallException("cannot write {$destination}");
        }
        try {
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
        } finally {
            fclose($file);
        }
    }
}
