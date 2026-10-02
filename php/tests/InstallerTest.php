<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Install\Installer;
use EminDeniz99\ApplePurchaseReceiptVerifier\Install\InstallException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FakeServer;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * `aprv install`, against a local HTTP server that serves the binary under
 * test (never committed: `APRV_BIN`) as the release asset. A wrong hash must
 * install nothing; the right one installs an owner-only executable that
 * runs.
 */
#[CoversNothing]
final class InstallerTest extends TestCase
{
    private const TARGET = 'x86_64-unknown-linux-musl';

    private const ASSET = 'aprv-' . self::TARGET;

    private string $work;

    private string $installDirectory;

    private string $sha256;

    private FakeServer $server;

    protected function setUp(): void
    {
        $work = tempnam(sys_get_temp_dir(), 'aprv-install-');
        self::assertNotFalse($work);
        unlink($work);
        mkdir($work . '/served', 0700, true);
        $this->work = $work;
        $this->installDirectory = $work . '/bin';
        copy(Aprv::binary(), $work . '/served/' . self::ASSET);
        $this->sha256 = (string) hash_file('sha256', $work . '/served/' . self::ASSET);
        $this->server = new FakeServer(documentRoot: $work . '/served');
    }

    protected function tearDown(): void
    {
        $this->server->stop();
        foreach (array_merge(
            glob($this->work . '/served/*') ?: [],
            glob($this->work . '/bin/{,.}*', GLOB_BRACE) ?: [],
            glob($this->work . '/*') ?: [],
        ) as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
        @rmdir($this->work . '/served');
        @rmdir($this->installDirectory);
        @rmdir($this->work);
    }

    /** @param array<string, string|null> $assets */
    private function manifest(array $assets, ?string $tag = 'v0.0.0-test'): string
    {
        $path = $this->work . '/binaries.json';
        file_put_contents($path, json_encode([
            'schema' => 1,
            'repository' => 'example/repo',
            'tag' => $tag,
            'assets' => $assets,
        ], JSON_THROW_ON_ERROR));

        return $path;
    }

    /** @return list<string> the files in the install directory, temporary ones included */
    private function installed(): array
    {
        $names = is_dir($this->installDirectory) ? scandir($this->installDirectory) : [];

        return array_values(array_diff($names === false ? [] : $names, ['.', '..']));
    }

    public function testTheRightHashInstallsAnOwnerOnlyExecutableThatRuns(): void
    {
        $message = Installer::install(
            $this->manifest([self::ASSET => $this->sha256]),
            $this->installDirectory,
            $this->server->url,
            self::TARGET,
        );

        $final = $this->installDirectory . '/aprv';
        self::assertStringContainsString('installed ' . self::ASSET, $message);
        self::assertSame(['aprv'], $this->installed(), 'no temporary file is left behind');
        self::assertSame($this->sha256, hash_file('sha256', $final));
        self::assertSame(0700, fileperms($final) & 0777, 'owner-only, and executable');
        self::assertSame(['GET /' . self::ASSET], array_column($this->server->requests(), 'key'));

        // The installed file is the working binary: a Verifier opens over it.
        Verifier::create(new Config(), new CliTransport($final));
    }

    public function testAWrongHashInstallsNothing(): void
    {
        $wrong = str_repeat('ab', 32);
        try {
            Installer::install($this->manifest([self::ASSET => $wrong]), $this->installDirectory, $this->server->url, self::TARGET);
            self::fail('a binary that does not match its pinned hash must not be installed');
        } catch (InstallException $e) {
            self::assertSame(InstallException::FAILED, $e->exitCode);
            self::assertStringContainsString('nothing was installed', $e->getMessage());
            self::assertStringContainsString($wrong, $e->getMessage());
            self::assertStringContainsString($this->sha256, $e->getMessage(), 'the message names the hash it computed');
        }

        self::assertSame([], $this->installed(), 'neither the binary nor a temporary file remains');
    }

    public function testAWrongHashLeavesAnExistingBinaryAsItWas(): void
    {
        mkdir($this->installDirectory, 0700, true);
        file_put_contents($this->installDirectory . '/aprv', 'the previous binary');

        $this->expectException(InstallException::class);
        try {
            Installer::install(
                $this->manifest([self::ASSET => str_repeat('cd', 32)]),
                $this->installDirectory,
                $this->server->url,
                self::TARGET,
            );
        } finally {
            self::assertSame('the previous binary', file_get_contents($this->installDirectory . '/aprv'));
            self::assertSame(['aprv'], $this->installed());
        }
    }

    public function testAnInstalledBinaryWithThePinnedHashIsNotDownloadedAgainUnlessForced(): void
    {
        $manifest = $this->manifest([self::ASSET => $this->sha256]);
        Installer::install($manifest, $this->installDirectory, $this->server->url, self::TARGET);
        self::assertCount(1, $this->server->requests());

        $again = Installer::install($manifest, $this->installDirectory, $this->server->url, self::TARGET);
        self::assertStringContainsString('already installed', $again);
        self::assertCount(1, $this->server->requests(), 'nothing was downloaded');

        Installer::install($manifest, $this->installDirectory, $this->server->url, self::TARGET, true);
        self::assertCount(2, $this->server->requests());
    }

    public function testAMissingReleaseAssetIsAFailureAndInstallsNothing(): void
    {
        $other = 'aprv-aarch64-unknown-linux-musl';
        try {
            Installer::install($this->manifest([$other => $this->sha256]), $this->installDirectory, $this->server->url, 'aarch64-unknown-linux-musl');
            self::fail('a 404 must not install anything');
        } catch (InstallException $e) {
            self::assertSame(InstallException::FAILED, $e->exitCode);
            self::assertStringContainsString($other, $e->getMessage());
        }
        self::assertSame([], $this->installed());
    }

    public function testAnUnsupportedPlatformNamesTheServerOption(): void
    {
        try {
            Installer::install($this->manifest([self::ASSET => $this->sha256]), $this->installDirectory, $this->server->url, null, false, ['FreeBSD', 'amd64']);
            self::fail('there is no binary for FreeBSD');
        } catch (InstallException $e) {
            self::assertSame(InstallException::UNAVAILABLE, $e->exitCode);
            self::assertStringContainsString('FreeBSD amd64', $e->getMessage());
            self::assertStringContainsString('HttpTransport', $e->getMessage());
        }
        self::assertSame([], $this->server->requests());
    }

    /** @return iterable<string, array{string, string, string|null, string|null}> */
    public static function platformProvider(): iterable
    {
        yield 'Linux x86-64' => ['Linux', 'x86_64', 'x86_64-unknown-linux-musl', 'aprv-x86_64-unknown-linux-musl'];
        yield 'Linux arm64' => ['Linux', 'aarch64', 'aarch64-unknown-linux-musl', 'aprv-aarch64-unknown-linux-musl'];
        yield 'macOS Intel' => ['Darwin', 'x86_64', 'x86_64-apple-darwin', 'aprv-x86_64-apple-darwin'];
        yield 'macOS Apple silicon' => ['Darwin', 'arm64', 'aarch64-apple-darwin', 'aprv-aarch64-apple-darwin'];
        yield 'Windows x64' => ['Windows', 'AMD64', 'x86_64-pc-windows-msvc', 'aprv-x86_64-pc-windows-msvc.exe'];
        yield 'Windows arm64' => ['Windows', 'ARM64', 'aarch64-pc-windows-msvc', 'aprv-aarch64-pc-windows-msvc.exe'];
        yield 'Linux 32-bit ARM' => ['Linux', 'armv7l', null, null];
        yield 'Linux ppc64le' => ['Linux', 'ppc64le', null, null];
        yield 'FreeBSD' => ['BSD', 'amd64', null, null];
    }

    #[DataProvider('platformProvider')]
    public function testEachPlatformMapsToTheReleaseAssetOrToNothing(string $os, string $machine, ?string $target, ?string $asset): void
    {
        self::assertSame($target, Installer::detectTarget($os, $machine));
        if ($target !== null) {
            self::assertSame($asset, Installer::assetName($target));
        }
    }

    public function testEveryAssetTheBriefNamesHasAPinSlotInTheShippedManifest(): void
    {
        /** @var array{assets: array<string, mixed>} $shipped */
        $shipped = json_decode((string) file_get_contents(__DIR__ . '/../binaries.json'), true, 8, JSON_THROW_ON_ERROR);

        self::assertSame(
            [
                'aprv-x86_64-unknown-linux-musl',
                'aprv-aarch64-unknown-linux-musl',
                'aprv-x86_64-apple-darwin',
                'aprv-aarch64-apple-darwin',
                'aprv-x86_64-pc-windows-msvc.exe',
                'aprv-aarch64-pc-windows-msvc.exe',
            ],
            array_keys($shipped['assets']),
        );
    }

    public function testAManifestWithNoPinnedHashOrNoTagInstallsNothing(): void
    {
        foreach ([
            [[self::ASSET => null], 'v1.0.0'],
            [[self::ASSET => 'not a hash'], 'v1.0.0'],
            [[], 'v1.0.0'],
            [[self::ASSET => $this->sha256], null],
            [[self::ASSET => $this->sha256], 'main'],
        ] as [$assets, $tag]) {
            try {
                // No base URL: the tag alone decides where GitHub would be asked.
                Installer::install($this->manifest($assets, $tag), $this->installDirectory, null, self::TARGET);
                self::fail('nothing is pinned, so nothing may install');
            } catch (InstallException $e) {
                self::assertSame(InstallException::UNAVAILABLE, $e->exitCode, json_encode([$assets, $tag]) ?: '');
                self::assertStringContainsString('HttpTransport', $e->getMessage());
            }
        }
        self::assertSame([], $this->installed());
        self::assertSame([], $this->server->requests());
    }

    public function testAnUnreadableManifestIsRefused(): void
    {
        file_put_contents($this->work . '/binaries.json', '{not json');
        $this->expectException(InstallException::class);
        Installer::install($this->work . '/binaries.json', $this->installDirectory, $this->server->url, self::TARGET);
    }

    public function testPlainHttpToAnotherHostIsRefusedBeforeAnyRequest(): void
    {
        foreach (['http://example.com/releases', 'ftp://127.0.0.1/x', 'file:///etc/passwd'] as $base) {
            try {
                Installer::install($this->manifest([self::ASSET => $this->sha256]), $this->installDirectory, $base, self::TARGET);
                self::fail("{$base} must be refused");
            } catch (InstallException $e) {
                self::assertSame(InstallException::UNAVAILABLE, $e->exitCode, $base);
            }
        }
        self::assertSame([], $this->installed());
    }

    /** The stream fallback is what runs where ext-curl is absent. */
    public function testTheStreamDownloaderFetchesAFileAndRefusesAnError(): void
    {
        $download = new ReflectionMethod(Installer::class, 'downloadWithStreams');
        $target = $this->work . '/streamed';
        $file = fopen($target, 'wb');
        self::assertIsResource($file);
        $download->invoke(null, $this->server->url . '/' . self::ASSET, $file);
        fclose($file);
        self::assertSame($this->sha256, hash_file('sha256', $target));

        $file = fopen($target, 'wb');
        self::assertIsResource($file);
        $this->expectException(InstallException::class);
        try {
            $download->invoke(null, $this->server->url . '/absent', $file);
        } finally {
            fclose($file);
        }
    }

    public function testTheDefaultInstallLocationIsWhereTheTransportLooks(): void
    {
        self::assertSame(realpath(__DIR__ . '/../bin'), realpath(dirname(CliTransport::defaultPath())));
        self::assertMatchesRegularExpression('/aprv(\.exe)?$/', CliTransport::defaultPath());
    }

    // --- bin/aprv-install ---------------------------------------------------------

    /**
     * @param list<string> $arguments
     *
     * @return array{int, string, string}
     */
    private function script(array $arguments): array
    {
        $process = proc_open(
            array_merge([PHP_BINARY, __DIR__ . '/../bin/aprv-install'], $arguments),
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), $out, $err];
    }

    public function testTheCommandInstallsAndExitsZero(): void
    {
        [$code, $out, $err] = $this->script([
            '--manifest', $this->manifest([self::ASSET => $this->sha256]),
            '--dir', $this->installDirectory,
            '--base-url', $this->server->url,
            '--target', self::TARGET,
        ]);

        self::assertSame(0, $code, $err);
        self::assertStringContainsString('installed ' . self::ASSET, $out);
        self::assertSame(['aprv'], $this->installed());
    }

    public function testTheCommandExitsOneOnAWrongHashAndInstallsNothing(): void
    {
        [$code, , $err] = $this->script([
            '--manifest', $this->manifest([self::ASSET => str_repeat('00', 32)]),
            '--dir', $this->installDirectory,
            '--base-url', $this->server->url,
            '--target', self::TARGET,
        ]);

        self::assertSame(1, $code);
        self::assertStringContainsString('nothing was installed', $err);
        self::assertSame([], $this->installed());
    }

    public function testTheCommandExitsTwoWhenThereIsNothingToInstall(): void
    {
        [$code, , $err] = $this->script(['--manifest', $this->manifest([self::ASSET => null]), '--dir', $this->installDirectory, '--target', self::TARGET]);
        self::assertSame(2, $code);
        self::assertStringContainsString('HttpTransport', $err);

        [$code] = $this->script(['--bogus']);
        self::assertSame(2, $code);
        [$code] = $this->script(['--help']);
        self::assertSame(0, $code);
        self::assertSame([], $this->installed());
    }
}
