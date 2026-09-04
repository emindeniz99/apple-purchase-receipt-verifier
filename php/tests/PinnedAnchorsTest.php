<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Trust comes from the caller's anchors and from nowhere else.
 *
 * This is the security property the whole library exists for, so it is tested
 * three ways: behaviourally (a chain nobody pinned is refused), mechanically
 * (no function that can reach a CA file or the network appears in `src/`), and
 * environmentally (a CA the PROCESS trusts, via OpenSSL's own default-path
 * environment variables, still buys an attacker nothing).
 */
#[CoversNothing]
final class PinnedAnchorsTest extends TestCase
{
    /**
     * The functions that would hand trust decisions to a CA file, a CA
     * directory, or the process's `openssl.cafile` ini setting — plus every
     * way to fetch anything. This is the test that would catch someone
     * "simplifying" the receipt path back onto the OS trust store.
     *
     * @return list<string>
     */
    private const BANNED_FUNCTIONS = [
        'openssl_cms_verify',
        'openssl_pkcs7_verify',
        'openssl_cms_read',
        'openssl_pkcs7_read',
        'openssl_x509_checkpurpose',
        'curl_init',
        'curl_exec',
        'fsockopen',
        'stream_socket_client',
        'file_get_contents',
        'fopen',
        'readfile',
        'eval',
        'unserialize',
        'exec',
        'shell_exec',
        'proc_open',
        'system',
        'passthru',
    ];

    /** @return list<string> */
    private static function sourceFiles(): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../src'));
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        sort($files);

        return $files;
    }

    public function testNoBannedFunctionAppearsInTheSourceTree(): void
    {
        $files = self::sourceFiles();
        self::assertNotEmpty($files);

        foreach ($files as $file) {
            // Comments legitimately name these functions to explain why they
            // are not used; the ban is on calling them.
            $source = self::codeOf($file);
            foreach (self::BANNED_FUNCTIONS as $banned) {
                self::assertDoesNotMatchRegularExpression(
                    '/(?<![A-Za-z0-9_$>])' . preg_quote($banned, '/') . '\s*\(/',
                    $source,
                    basename($file) . ' calls ' . $banned . '()',
                );
            }
        }
    }

    public function testNoNetworkOrDefaultTrustStoreReferenceAppearsInTheSourceTree(): void
    {
        foreach (self::sourceFiles() as $file) {
            // Prose in a docblock legitimately names these; code does not.
            $code = self::codeOf($file);
            foreach (['http://', 'https://', 'set_default_paths', 'openssl.cafile', 'openssl.capath'] as $banned) {
                self::assertStringNotContainsString($banned, $code, basename($file) . ' mentions ' . $banned);
            }
        }
    }

    /** A genuine Apple-signed receipt against the wrong anchor set is refused. */
    public function testAGenuineAppleReceiptIsRefusedUnderAnAnchorItDoesNotReach(): void
    {
        $pki = MintedPki::get();
        $legacy = Support\Fixtures::bytes('public-receipt-sandbox-legacy');

        self::assertSame(
            'com.nutcall.alert',
            (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.nutcall.alert'))->verify($legacy)->bundleId,
        );

        try {
            (new ReceiptVerifier([$pki->rootDer], 'com.nutcall.alert'))->verify($legacy);
            self::fail('a genuine receipt verified against an anchor it does not chain to');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }
    }

    /** And the mirror: our own PKI is refused under Apple's real roots. */
    public function testAMintedChainIsRefusedUnderApplesRealRoots(): void
    {
        $pki = MintedPki::get();

        try {
            (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.example.app'))->verify($pki->receipt());
            self::fail('a minted receipt verified against Apple roots');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }

        try {
            (new JwsVerifier(AppleRootCerts::jwsRoots(), 'com.example.app', [Environment::Sandbox]))
                ->verifyTransaction($pki->jws(MintedPki::transactionClaims()));
            self::fail('a minted JWS verified against Apple roots');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }
    }

    /**
     * The environmental proof. OpenSSL's default verification paths are
     * driven by `SSL_CERT_FILE` / `SSL_CERT_DIR`; a library that reached them
     * anywhere would start trusting whatever a host operator configured.
     * Here the process is pointed at a CA file that DID sign the chain, and
     * the answer must not change.
     */
    public function testACaTheProcessItselfTrustsBuysAnAttackerNothing(): void
    {
        $pki = MintedPki::get();
        $caFile = tempnam(sys_get_temp_dir(), 'aprv-ca-') . '.pem';
        file_put_contents($caFile, Certificate::parse($pki->rootDer)->pem());

        $previousFile = getenv('SSL_CERT_FILE');
        $previousDir = getenv('SSL_CERT_DIR');
        putenv('SSL_CERT_FILE=' . $caFile);
        putenv('SSL_CERT_DIR=' . dirname($caFile));

        try {
            // Apple's roots are the configured anchors. The minted chain is
            // signed by a CA this PROCESS now trusts, and that must not matter.
            (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.example.app'))->verify($pki->receipt());
            self::fail('the process trust store leaked into a verification decision');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        } finally {
            $previousFile === false ? putenv('SSL_CERT_FILE') : putenv('SSL_CERT_FILE=' . $previousFile);
            $previousDir === false ? putenv('SSL_CERT_DIR') : putenv('SSL_CERT_DIR=' . $previousDir);
            @unlink($caFile);
        }
    }

    /**
     * A real public CA root, read straight out of the host's own trust bundle
     * where there is one: it is a certificate millions of TLS clients accept,
     * and this library must give it no standing whatsoever.
     */
    public function testARealPublicCaRootIsNotAnAnchorUnlessTheCallerPassesIt(): void
    {
        $bundle = self::firstReadable([
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/cert.pem',
        ]);
        if ($bundle === null) {
            self::markTestSkipped('no host CA bundle on this machine to read a genuine public root from');
        }
        $pem = self::firstPemBlock((string) file_get_contents($bundle));
        self::assertNotNull($pem, 'the host CA bundle held no PEM block');

        $pki = MintedPki::get();

        // Anchored on a real public CA, our minted chain is still refused —
        // trust is by argument, and the argument does not certify this chain.
        try {
            (new ReceiptVerifier([$pem], 'com.example.app'))->verify($pki->receipt());
            self::fail('a chain unrelated to the anchor was accepted');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }

        // And Apple's own roots do not gain standing from the public CA
        // sitting next to them in the caller's list.
        try {
            (new ReceiptVerifier([$pem, ...AppleRootCerts::receiptRoots()], 'com.example.app'))
                ->verify($pki->receipt());
            self::fail('a chain unrelated to any anchor was accepted');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }
    }

    public function testAnEmptyOrUnparseableAnchorListIsAConfigurationErrorNotAVerdict(): void
    {
        foreach ([[], ['']] as $roots) {
            try {
                new ReceiptVerifier($roots, 'com.example.app');
                self::fail('an empty anchor list was accepted');
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString('trustedRoots', $e->getMessage());
            }
        }

        $this->expectException(InvalidArgumentException::class);
        new ReceiptVerifier(['not a certificate'], 'com.example.app');
    }

    /** A source file with its comments stripped, using PHP's own tokenizer. */
    private static function codeOf(string $file): string
    {
        $code = '';
        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (is_array($token)) {
                if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                    continue;
                }
                $code .= $token[1];
                continue;
            }
            $code .= $token;
        }

        return $code;
    }

    /** @param list<string> $paths */
    private static function firstReadable(array $paths): ?string
    {
        foreach ($paths as $path) {
            if (is_readable($path)) {
                return $path;
            }
        }

        return null;
    }

    private static function firstPemBlock(string $bundle): ?string
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $bundle, $m) !== 1) {
            return null;
        }

        return $m[0];
    }
}
