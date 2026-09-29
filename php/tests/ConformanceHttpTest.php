<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\ServerProcess;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/**
 * The shared cases over HTTP against a locally started `aprv serve`. The
 * server's roots are fixed at its start, so one server runs per distinct
 * root set (the case's roots, or the built-in ones), and `Verifier::create`
 * checks each against the fingerprints `GET /v1/info` reports.
 */
final class ConformanceHttpTest extends ConformanceBase
{
    /** @var array<string, ServerProcess> */
    private static array $servers = [];

    /** @var list<string> */
    private static array $rootsFiles = [];

    protected static function verifierFor(Config $config): Verifier
    {
        $key = implode("\n", array_map('base64_encode', $config->roots ?? []));
        if (!isset(self::$servers[$key])) {
            $file = null;
            if ($config->roots !== null) {
                $file = (string) tempnam(sys_get_temp_dir(), 'aprv-roots-');
                file_put_contents($file, $key . "\n");
                self::$rootsFiles[] = $file;
            }
            self::$servers[$key] = Aprv::startServer($file);
        }

        return Verifier::create($config, new HttpTransport(self::$servers[$key]->url));
    }

    public static function tearDownAfterClass(): void
    {
        foreach (self::$servers as $server) {
            $server->stop();
        }
        foreach (self::$rootsFiles as $file) {
            @unlink($file);
        }
        self::$servers = [];
        self::$rootsFiles = [];
    }
}
