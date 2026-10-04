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

    /** @param array<string, string> $assets asset name => SHA-256, one sha256sum line each under `$tag/` */
    private function sums(array $assets, string $tag = 'v0.0.0-test'): string
    {
        $text = '';
        foreach ($assets as $asset => $hash) {
            $text .= "{$hash}  {$tag}/{$asset}\n";
        }

        return $this->sumsFile($text);
    }

    private function sumsFile(string $text): string
    {
        $path = $this->work . '/SHA256SUMS';
        file_put_contents($path, $text);

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
            $this->sums([self::ASSET => $this->sha256]),
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
            Installer::install($this->sums([self::ASSET => $wrong]), $this->installDirectory, $this->server->url, self::TARGET);
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
                $this->sums([self::ASSET => str_repeat('cd', 32)]),
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
        $sums = $this->sums([self::ASSET => $this->sha256]);
        Installer::install($sums, $this->installDirectory, $this->server->url, self::TARGET);
        self::assertCount(1, $this->server->requests());

        $again = Installer::install($sums, $this->installDirectory, $this->server->url, self::TARGET);
        self::assertStringContainsString('already installed', $again);
        self::assertCount(1, $this->server->requests(), 'nothing was downloaded');

        Installer::install($sums, $this->installDirectory, $this->server->url, self::TARGET, true);
        self::assertCount(2, $this->server->requests());
    }

    public function testAMissingReleaseAssetIsAFailureAndInstallsNothing(): void
    {
        $other = 'aprv-aarch64-unknown-linux-musl';
        try {
            Installer::install($this->sums([$other => $this->sha256]), $this->installDirectory, $this->server->url, 'aarch64-unknown-linux-musl');
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
            Installer::install($this->sums([self::ASSET => $this->sha256]), $this->installDirectory, $this->server->url, null, false, ['FreeBSD', 'amd64']);
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

    public function testTheShippedSha256sumsIsOneTheInstallerReads(): void
    {
        // Empty until the first release writes it; from then on main
        // carries the last release's two Linux lines (the release branch
        // merges into main). Either way the installer must accept it.
        $shipped = Installer::pins(__DIR__ . '/../SHA256SUMS');
        if ((string) file_get_contents(__DIR__ . '/../SHA256SUMS') === '') {
            self::assertSame(['tag' => null, 'assets' => []], $shipped);

            return;
        }
        self::assertIsString($shipped['tag']);
        self::assertMatchesRegularExpression('/^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/', $shipped['tag'], 'a release tag');
        $assets = array_keys($shipped['assets']);
        sort($assets);
        self::assertSame(
            ['aprv-aarch64-unknown-linux-musl', 'aprv-x86_64-unknown-linux-musl'],
            $assets,
            'the two Linux binaries the release branch pins, and nothing else',
        );
    }

    public function testEveryAssetTheBriefNamesCanBePinnedAndNothingElse(): void
    {
        $assets = [
            'aprv-x86_64-unknown-linux-musl',
            'aprv-aarch64-unknown-linux-musl',
            'aprv-x86_64-apple-darwin',
            'aprv-aarch64-apple-darwin',
            'aprv-x86_64-pc-windows-msvc.exe',
            'aprv-aarch64-pc-windows-msvc.exe',
        ];
        $pins = Installer::pins($this->sums(array_fill_keys($assets, $this->sha256), 'v0.8.0'));
        self::assertSame('v0.8.0', $pins['tag']);
        self::assertSame($assets, array_keys($pins['assets']));

        $this->expectException(InstallException::class);
        Installer::pins($this->sums(['aprv.wasm' => $this->sha256]));
    }

    /**
     * The format is sha256sum's own: what the tool writes for files laid out
     * as `<tag>/<asset>` is what the installer reads, so `sha256sum -c
     * --strict` beside the release assets checks the claim the package
     * ships.
     */
    public function testSha256sumsOwnOutputIsWhatTheInstallerReads(): void
    {
        $sha256sum = trim((string) shell_exec('command -v sha256sum 2>/dev/null'));
        if ($sha256sum === '') {
            self::markTestSkipped('no sha256sum on this machine (coreutils)');
        }
        mkdir($this->work . '/release/v0.8.0', 0700, true);
        copy($this->work . '/served/' . self::ASSET, $this->work . '/release/v0.8.0/' . self::ASSET);
        $out = shell_exec('cd ' . escapeshellarg($this->work . '/release') . ' && sha256sum v0.8.0/*');
        self::assertIsString($out);
        unlink($this->work . '/release/v0.8.0/' . self::ASSET);
        rmdir($this->work . '/release/v0.8.0');
        rmdir($this->work . '/release');

        self::assertSame(['tag' => 'v0.8.0', 'assets' => [self::ASSET => $this->sha256]], Installer::pins($this->sumsFile($out)));
    }

    public function testSumsWithNoPinForThisPlatformInstallNothing(): void
    {
        foreach ([
            'an empty file, as main carries before the first release' => '',
            'another platform only' => $this->sha256 . "  v1.0.0/aprv-aarch64-unknown-linux-musl\n",
        ] as $case => $text) {
            try {
                // No base URL: the file alone decides where GitHub would be asked.
                Installer::install($this->sumsFile($text), $this->installDirectory, null, self::TARGET);
                self::fail("{$case}: nothing is pinned, so nothing may install");
            } catch (InstallException $e) {
                self::assertSame(InstallException::UNAVAILABLE, $e->exitCode, $case);
                self::assertStringContainsString('HttpTransport', $e->getMessage(), $case);
            }
        }
        self::assertSame([], $this->installed());
        self::assertSame([], $this->server->requests());
    }

    /** @return iterable<string, array{string}> */
    public static function malformedSumsProvider(): iterable
    {
        $hash = str_repeat('ab', 32);
        $line = static fn (string $path): string => "{$hash}  {$path}\n";
        yield 'binary mode' => ["{$hash} *v1.0.0/" . self::ASSET . "\n"];
        yield 'one space' => ["{$hash} v1.0.0/" . self::ASSET . "\n"];
        yield 'upper-case hex' => [strtoupper($hash) . '  v1.0.0/' . self::ASSET . "\n"];
        yield '63 digits' => [substr($hash, 1) . '  v1.0.0/' . self::ASSET . "\n"];
        yield 'BSD tagged' => ['SHA256 (v1.0.0/' . self::ASSET . ") = {$hash}\n"];
        yield 'no tag' => [$line(self::ASSET)];
        yield 'two slashes' => [$line('v1.0.0/x/' . self::ASSET)];
        yield 'absolute path' => [$line('/v1.0.0/' . self::ASSET)];
        yield 'parent directory' => [$line('../' . self::ASSET)];
        yield 'a branch, not a tag' => [$line('main/' . self::ASSET)];
        yield 'not a release asset' => [$line('v1.0.0/aprv.wasm')];
        yield 'CRLF' => ["{$hash}  v1.0.0/" . self::ASSET . "\r\n"];
        yield 'a blank line' => ["\n" . $line('v1.0.0/' . self::ASSET)];
        yield 'two tags' => [$line('v1.0.0/' . self::ASSET) . $line('v1.0.1/aprv-aarch64-unknown-linux-musl')];
        yield 'an asset twice' => [$line('v1.0.0/' . self::ASSET) . $line('v1.0.0/' . self::ASSET)];
        yield 'the old binaries.json' => ['{"schema": 1, "tag": null, "assets": {}}'];
    }

    #[DataProvider('malformedSumsProvider')]
    public function testAMalformedSumsFileIsRefusedBeforeAnyRequest(string $text): void
    {
        try {
            Installer::install($this->sumsFile($text), $this->installDirectory, $this->server->url, self::TARGET);
            self::fail('a SHA256SUMS line sha256sum would not write, or the installer cannot trust, must be refused');
        } catch (InstallException $e) {
            self::assertSame(InstallException::UNAVAILABLE, $e->exitCode);
            self::assertStringContainsString('SHA256SUMS', $e->getMessage(), 'the message names the file');
        }
        self::assertSame([], $this->installed());
        self::assertSame([], $this->server->requests());
    }

    public function testAMissingSumsFileIsRefused(): void
    {
        $this->expectException(InstallException::class);
        Installer::install($this->work . '/SHA256SUMS', $this->installDirectory, $this->server->url, self::TARGET);
    }

    /**
     * file_get_contents() reads a directory as an empty string, which would
     * pass for an empty file that pins nothing. A directory is not a sums
     * file, and the command says it cannot read it.
     */
    public function testADirectoryInPlaceOfTheSumsFileIsRefused(): void
    {
        try {
            Installer::pins($this->work);
            self::fail('a directory must not read as an empty SHA256SUMS');
        } catch (InstallException $e) {
            self::assertSame(InstallException::UNAVAILABLE, $e->exitCode);
            self::assertStringContainsString('cannot read ' . $this->work, $e->getMessage());
        }

        [$code, , $err] = $this->script(['--sums', $this->work, '--dir', $this->installDirectory, '--target', self::TARGET]);
        self::assertSame(2, $code);
        self::assertStringContainsString('cannot read', $err);
        self::assertSame([], $this->installed());
    }

    /** An asset name is the file's text, so its control bytes are escaped before they reach a terminal. */
    public function testAnUnknownAssetIsNamedEscaped(): void
    {
        try {
            Installer::pins($this->sumsFile(str_repeat('ab', 32) . "  v1.0.0/aprv-\e[2Jx\n"));
            self::fail('an asset outside the release list must be refused');
        } catch (InstallException $e) {
            self::assertStringContainsString('not a release asset', $e->getMessage());
            self::assertStringNotContainsString("\e", $e->getMessage());
            self::assertStringContainsString('"aprv-\u001b[2Jx"', $e->getMessage());
        }
    }

    public function testPlainHttpToAnotherHostIsRefusedBeforeAnyRequest(): void
    {
        foreach (['http://example.com/releases', 'ftp://127.0.0.1/x', 'file:///etc/passwd'] as $base) {
            try {
                Installer::install($this->sums([self::ASSET => $this->sha256]), $this->installDirectory, $base, self::TARGET);
                self::fail("{$base} must be refused");
            } catch (InstallException $e) {
                self::assertSame(InstallException::UNAVAILABLE, $e->exitCode, $base);
            }
        }
        self::assertSame([], $this->installed());
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
            '--sums', $this->sums([self::ASSET => $this->sha256]),
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
            '--sums', $this->sums([self::ASSET => str_repeat('00', 32)]),
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
        [$code, , $err] = $this->script(['--sums', $this->sums([]), '--dir', $this->installDirectory, '--target', self::TARGET]);
        self::assertSame(2, $code);
        self::assertStringContainsString('HttpTransport', $err);

        // An unknown option is refused before anything is read or installed:
        // getopt() alone drops it, and the script would then install from
        // the package's own SHA256SUMS into the package's bin directory.
        foreach ([['--bogus'], ['--dir', $this->installDirectory, '--bogus=1'], ['stray'], ['--sums=' . $this->sums([]), '--force', '--bogus']] as $arguments) {
            [$code, , $err] = $this->script($arguments);
            self::assertSame(2, $code, implode(' ', $arguments));
            self::assertStringContainsString('unknown argument ' . end($arguments), $err);
            self::assertStringNotContainsString('SHA256SUMS', $err);
        }
        [$code] = $this->script(['--help']);
        self::assertSame(0, $code);
        self::assertSame([], $this->installed());
    }
}
