<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Install\Installer;
use EminDeniz99\ApplePurchaseReceiptVerifier\Install\InstallException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function updateBinaries;

require_once __DIR__ . '/../tools/update-binaries.php';

/** The release step that pins the binaries' hashes: what `aprv-install` will later check against. */
#[CoversNothing]
final class UpdateBinariesTest extends TestCase
{
    private string $manifest;

    private string $sums;

    protected function setUp(): void
    {
        $this->manifest = (string) tempnam(sys_get_temp_dir(), 'aprv-manifest-');
        $this->sums = (string) tempnam(sys_get_temp_dir(), 'aprv-sums-');
        copy(__DIR__ . '/../binaries.json', $this->manifest);
    }

    protected function tearDown(): void
    {
        @unlink($this->manifest);
        @unlink($this->sums);
    }

    /** @return array{tag: string, sums: string, manifest: string} */
    private function options(string $tag = 'v0.8.0'): array
    {
        return ['tag' => $tag, 'sums' => $this->sums, 'manifest' => $this->manifest];
    }

    /** @return array{tag: mixed, assets: array<string, mixed>} */
    private function written(): array
    {
        /** @var array{tag: mixed, assets: array<string, mixed>} */
        return json_decode((string) file_get_contents($this->manifest), true, 8, JSON_THROW_ON_ERROR);
    }

    public function testTheTagAndTheListedHashesAreWrittenAndTheRestAreReset(): void
    {
        $linux = str_repeat('a1', 32);
        $mac = str_repeat('b2', 32);
        file_put_contents($this->sums, implode("\n", [
            "{$linux}  aprv-x86_64-unknown-linux-musl",
            "{$mac} *aprv-aarch64-apple-darwin",
            str_repeat('c3', 32) . '  aprv.wasm',
            'not a sums line',
        ]) . "\n");

        $log = updateBinaries($this->options());

        $manifest = $this->written();
        self::assertSame('v0.8.0', $manifest['tag']);
        self::assertSame($linux, $manifest['assets']['aprv-x86_64-unknown-linux-musl']);
        self::assertSame($mac, $manifest['assets']['aprv-aarch64-apple-darwin']);
        self::assertNull($manifest['assets']['aprv-x86_64-pc-windows-msvc.exe'], 'a binary the release did not build has no pin');
        self::assertArrayNotHasKey('aprv.wasm', $manifest['assets'], 'only the listed assets are read');
        self::assertStringContainsString('pinned 2 of 6 assets for v0.8.0', $log);
        self::assertStringContainsString('warning: aprv-x86_64-pc-windows-msvc.exe', $log);
    }

    public function testAnOldPinIsNeverKeptForAnAssetTheNewListLacks(): void
    {
        file_put_contents($this->sums, str_repeat('a1', 32) . "  aprv-x86_64-unknown-linux-musl\n");
        updateBinaries($this->options('v0.8.0'));
        file_put_contents($this->sums, str_repeat('d4', 32) . "  aprv-aarch64-unknown-linux-musl\n");
        updateBinaries($this->options('v0.8.1'));

        $manifest = $this->written();
        self::assertNull($manifest['assets']['aprv-x86_64-unknown-linux-musl']);
        self::assertSame(str_repeat('d4', 32), $manifest['assets']['aprv-aarch64-unknown-linux-musl']);
        self::assertSame('v0.8.1', $manifest['tag']);
    }

    public function testARunWithNothingToPinWritesNothing(): void
    {
        file_put_contents($this->sums, str_repeat('c3', 32) . "  aprv.wasm\n");
        $before = (string) file_get_contents($this->manifest);

        try {
            updateBinaries($this->options());
            self::fail('a list with none of the assets must not blank the manifest');
        } catch (RuntimeException) {
            self::assertSame($before, file_get_contents($this->manifest));
        }
    }

    public function testATagThatIsNotAReleaseTagIsRefused(): void
    {
        file_put_contents($this->sums, str_repeat('a1', 32) . "  aprv-x86_64-unknown-linux-musl\n");
        $this->expectException(RuntimeException::class);
        updateBinaries($this->options('main'));
    }

    public function testTheWrittenManifestIsWhatTheInstallerReads(): void
    {
        $hash = str_repeat('e5', 32);
        file_put_contents($this->sums, "{$hash}  aprv-x86_64-unknown-linux-musl\n");
        updateBinaries($this->options());

        $dir = sys_get_temp_dir() . '/aprv-upd-' . bin2hex(random_bytes(4));
        try {
            Installer::install($this->manifest, $dir, 'http://127.0.0.1:1', 'x86_64-unknown-linux-musl');
            self::fail('port 1 has no server');
        } catch (InstallException $e) {
            // It got as far as downloading: the manifest pins a hash for this target.
            self::assertSame(InstallException::FAILED, $e->exitCode);
        } finally {
            @rmdir($dir);
        }
    }
}
