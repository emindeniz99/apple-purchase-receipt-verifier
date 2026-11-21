<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\RevokedCertificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\ServerProcess;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * The shared cases over HTTP against a locally started `aprv serve`. The
 * server's roots and revocation settings are fixed at its start, so one
 * server runs per distinct configuration (the case's roots, or the
 * built-in ones, and its lists, issuers and distrust entries), and
 * `Verifier::create` checks each against what `GET /v1/info` reports. A
 * configuration the module refuses stops the server at start, which the
 * harness reports as the refusal `Verifier::create` would raise.
 */
final class ConformanceHttpTest extends ConformanceBase
{
    /** @var array<string, ServerProcess> */
    private static array $servers = [];

    /** @var list<string> */
    private static array $files = [];

    protected static function verifierFor(Config $config): Verifier
    {
        $key = hash('sha256', serialize([
            $config->roots,
            $config->revocationLists,
            $config->revocationIssuers,
            array_map(static fn (RevokedCertificate $d): array => [$d->issuer, $d->serial], $config->distrust),
        ]));
        if (!isset(self::$servers[$key])) {
            $rootsFile = null;
            if ($config->roots !== null) {
                $rootsFile = self::file(implode("\n", array_map('base64_encode', $config->roots)) . "\n");
            }
            $flags = [];
            foreach ($config->revocationLists as $list) {
                array_push($flags, '--revocation-list', self::file($list));
            }
            foreach ($config->revocationIssuers as $issuer) {
                array_push($flags, '--revocation-issuer', self::file(base64_encode($issuer) . "\n"));
            }
            foreach ($config->distrust as $entry) {
                $flags[] = '--distrust=' . $entry->issuer . ':' . $entry->serial;
            }
            self::$servers[$key] = Aprv::startServer($rootsFile, null, $flags);
        }

        return Verifier::create($config, new HttpTransport(self::$servers[$key]->url));
    }

    private static function file(string $contents): string
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'aprv-config-');
        file_put_contents($file, $contents);
        self::$files[] = $file;

        return $file;
    }

    public static function tearDownAfterClass(): void
    {
        foreach (self::$servers as $server) {
            $server->stop();
        }
        foreach (self::$files as $file) {
            @unlink($file);
        }
        self::$servers = [];
        self::$files = [];
    }
}
