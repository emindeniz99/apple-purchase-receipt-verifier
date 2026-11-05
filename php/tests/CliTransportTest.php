<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\RevokedCertificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FakeCli;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Outcome;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ServerProcessException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The one-shot transport: what it puts on the command line and on stdin,
 * how it reads exit statuses, and what it leaves on disk. A fake `aprv`
 * logs each invocation; the real binary answers the size-cap and roots
 * questions.
 */
#[CoversNothing]
final class CliTransportTest extends TestCase
{
    private FakeCli $cli;

    protected function setUp(): void
    {
        $this->cli = new FakeCli();
    }

    protected function tearDown(): void
    {
        $this->cli->remove();
    }

    private function transport(int $timeoutSeconds = 30): CliTransport
    {
        return new CliTransport($this->cli->executable, $timeoutSeconds);
    }

    /** Opens a transport with the built-in roots and forgets the probe's log line. */
    private function opened(int $timeoutSeconds = 30): CliTransport
    {
        $transport = $this->transport($timeoutSeconds);
        $transport->open(new Config());
        file_put_contents($this->cli->directory . '/log.jsonl', '');

        return $transport;
    }

    public function testACallIsOneProcessWithAnArgvArrayAndTheInputOnStdin(): void
    {
        $transport = $this->opened();
        $bytes = "a\0b\xff\xfe;\$(touch pwned)`id`'\"\r\n";

        $transport->call(Operation::Receipt, $bytes, 1722945600123);
        $transport->call(Operation::SignedData, $bytes, 5);
        $transport->call(Operation::EndpointProduction, $bytes, 6);
        $transport->call(Operation::EndpointSandbox, '', 0);

        $log = $this->cli->log();
        self::assertSame(
            [
                ['verify-receipt', '--now-ms', '1722945600123'],
                ['verify-signed-data', '--now-ms', '5'],
                ['verify-receipt-endpoint', 'production', '--now-ms', '6'],
                ['verify-receipt-endpoint', 'sandbox', '--now-ms', '0'],
            ],
            array_column($log, 'argv'),
            'no --roots for the built-in roots, and the clock in decimal',
        );
        self::assertSame([strlen($bytes), strlen($bytes), strlen($bytes), 0], array_column($log, 'stdin_length'));
        self::assertSame(hash('sha256', $bytes), $log[0]['stdin_sha256'], 'stdin carries the bytes exactly');
        self::assertFileDoesNotExist('pwned', 'no shell parsed anything');
    }

    /**
     * An input over the cap goes to stdin cut to one byte over it, the
     * `limits.max_input_bytes` `aprv info` stated and the cut every Wasm
     * wrapper makes; one at the cap whole.
     */
    public function testAnInputOverTheCapIsSentCutToOneByteOverIt(): void
    {
        $transport = $this->opened();
        $twentyMib = str_repeat("A\xffB\0", 5 * 1024 * 1024);
        $atCap = str_repeat('A', 3145728);

        $transport->call(Operation::Receipt, $twentyMib, 1);
        $transport->call(Operation::Receipt, $atCap, 1);

        $log = $this->cli->log();
        self::assertSame([3145729, 3145728], array_column($log, 'stdin_length'));
        self::assertSame(hash('sha256', substr($twentyMib, 0, 3145729)), $log[0]['stdin_sha256'], 'the first bytes, unchanged');
    }

    public function testTheCutIsTheLengthAprvInfoStatedNotAConstant(): void
    {
        $this->cli->behave(['info' => '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":5},"revocation_urls":[],"revocation_valid_until_ms":null}']);
        $transport = $this->transport();
        $transport->open(new Config());

        $transport->call(Operation::SignedData, 'abcdefgh', 1);
        $transport->call(Operation::SignedData, 'abc', 1);

        $log = array_slice($this->cli->log(), -2);
        self::assertSame([5, 3], array_column($log, 'stdin_length'));
        self::assertSame(hash('sha256', 'abcde'), $log[0]['stdin_sha256']);
    }

    /** A binary that states no input length is older than this package: create refuses it. */
    public function testABinaryThatStatesNoInputLengthFailsCreate(): void
    {
        foreach ([
            '{"abi":"aprv:verifier@0.2.0"}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_body_bytes":3145729}}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":0}}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":"3145729"}}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":1.5}}',
        ] as $info) {
            $this->cli->behave(['info' => $info]);
            try {
                $this->transport()->open(new Config());
                self::fail("aprv info answered {$info}: create must refuse it");
            } catch (RuntimeException $e) {
                self::assertStringContainsString('max_input_bytes', $e->getMessage(), $info);
            }
        }
    }

    public function testTheCallReturnsTheJsonOnStdoutUnchanged(): void
    {
        $answer = "{\"verified\":false, \"x\":\"\u{e9}\"}\n  ";
        $this->cli->behave(['stdout' => $answer]);

        self::assertSame($answer, $this->opened()->call(Operation::Receipt, 'x', 1));
    }

    public function testAnInputThatMakesTheBinaryStopReadingStillGetsItsAnswer(): void
    {
        $answer = '{"verified":false,"reason":"TOO_LARGE","message":"said by the module"}';
        $this->cli->behave(['exit' => 3, 'read_stdin' => false, 'stdout' => $answer]);
        $transport = $this->opened();

        // Far more than a pipe buffer: the write fails or is cut off, and neither hangs nor raises a notice.
        self::assertSame($answer, $transport->call(Operation::Receipt, str_repeat('A', 6 * 1024 * 1024), 1));
    }

    public function testALargeAnswerIsReadInFull(): void
    {
        $answer = '{"status":0,"pad":"' . str_repeat('x', 3 * 1024 * 1024) . '"}';
        $this->cli->behave(['stdout' => $answer]);

        self::assertSame($answer, $this->opened()->call(Operation::EndpointSandbox, '{}', 1));
    }

    public function testExitStatusesAreMappedToTheirOutcomes(): void
    {
        $transport = $this->opened();

        // Exit 3: the input was over the cap, and stdout is the module's answer to it.
        $this->cli->behave(['exit' => 3, 'stdout' => '{"status":21002}']);
        self::assertSame('{"status":21002}', $transport->call(Operation::EndpointSandbox, 'x', 1));

        $this->cli->behave(['exit' => 70, 'stderr' => "wasm trap: unreachable\x1b[31m"]);
        try {
            $transport->call(Operation::Receipt, 'x', 1);
            self::fail('exit 70 is a trap');
        } catch (ModuleFaultException $e) {
            self::assertSame('EXIT_70', $e->category);
            self::assertStringContainsString('wasm trap: unreachable?[31m', $e->getMessage(), 'stderr is reduced to printable ASCII');
        }

        foreach ([2, 1, 64, 127, 255] as $code) {
            $this->cli->behave(['exit' => $code, 'stderr' => 'nope']);
            try {
                $transport->call(Operation::SignedData, 'x', 1);
                self::fail("exit {$code} is a process failure");
            } catch (ServerProcessException $e) {
                self::assertStringContainsString("status {$code}", $e->getMessage());
                self::assertStringContainsString('nope', $e->getMessage());
            }
        }
    }

    public function testAProcessKilledBySignalIsAProcessFailure(): void
    {
        $this->cli->behave(['signal' => 9]);
        $transport = $this->opened();

        $this->expectException(ServerProcessException::class);
        $transport->call(Operation::Receipt, 'x', 1);
    }

    public function testAProcessThatOutlivesTheTimeoutIsKilled(): void
    {
        $this->cli->behave(['sleep' => 20]);
        $transport = $this->opened(1);

        $started = microtime(true);
        try {
            $transport->call(Operation::Receipt, 'x', 1);
            self::fail('a hung process must be given up on');
        } catch (ServerProcessException $e) {
            self::assertStringContainsString('within 1 seconds', $e->getMessage());
        }
        self::assertLessThan(10, microtime(true) - $started);
    }

    // --- open ------------------------------------------------------------

    public function testOpenRunsInfoOnceWithARootsFileOnlyWhenRootsAreGiven(): void
    {
        $this->transport()->open(new Config());
        self::assertSame([['info']], array_column($this->cli->log(), 'argv'));

        $this->cli->remove();
        $this->cli = new FakeCli();
        $roots = ["\x30\x03\x02\x01\x01", "\xff\x00binary"];
        $transport = $this->transport();
        $transport->open(new Config(roots: $roots));

        $log = $this->cli->log();
        self::assertCount(1, $log, 'aprv info runs init on the roots: no probe call');
        self::assertSame(['info', '--roots'], array_slice($log[0]['argv'], 0, 2));
        self::assertSame(0, $log[0]['stdin_length']);
        self::assertSame(base64_encode($roots[0]) . "\n" . base64_encode($roots[1]) . "\n", $log[0]['roots_file_content']);
    }

    /**
     * Each list goes to aprv as a file of its bytes, the issuers as one
     * file of base64 lines like the roots, and each distrust entry as one
     * `--distrust=` argument, as written; `aprv info` gets them at open and
     * every call gets them again, and the revocation state open() returns
     * is what `aprv info` stated.
     */
    public function testRevocationSettingsReachEveryProcessAndTheStateIsAprvInfos(): void
    {
        $this->cli->behave(['info' => '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":3145729},'
            . '"revocation_urls":["http://crl.example.test/a.crl"],"revocation_valid_until_ms":1796083200000}']);
        $lists = ["\x30\x01\x00", "\x30\x01\xff"];
        $issuer = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        $transport = $this->transport();
        $state = $transport->open(new Config(
            revocationLists: $lists,
            revocationIssuers: [$issuer],
            distrust: [new RevokedCertificate('AB', '-1'), new RevokedCertificate('cd', '0080')],
        ));
        $transport->call(Operation::SignedData, 'x', 7);

        self::assertSame(['http://crl.example.test/a.crl'], $state->revocationUrls);
        self::assertSame(1796083200000, $state->revocationValidUntilMs);
        $log = $this->cli->log();
        self::assertCount(2, $log);
        foreach ($log as $entry) {
            self::assertSame(array_map('base64_encode', $lists), $entry['lists'], 'each list as its bytes, in order');
            self::assertSame(base64_encode($issuer) . "\n", $entry['issuers_file_content']);
            self::assertSame(['--distrust=AB:-1', '--distrust=cd:0080'], array_slice($entry['argv'], -2), 'with =, so a dash stays a value');
            self::assertNotContains('--roots', $entry['argv'], 'no roots given, no roots file');
        }
        self::assertSame(['verify-signed-data', '--now-ms', '7', '--revocation-list'], array_slice($log[1]['argv'], 0, 4));

        $files = array_values(array_filter($log[0]['argv'], static fn (string $a): bool => is_file($a)));
        self::assertCount(3, $files, 'two lists and one issuers file');
        unset($transport);
        foreach ($files as $file) {
            self::assertFileDoesNotExist($file, 'deleted with the transport');
        }
    }

    public function testADistrustEntryWithANulByteIsAnArgumentError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('distrust[1] holds a NUL byte');
        $this->transport()->open(new Config(distrust: [new RevokedCertificate('a', 'b'), new RevokedCertificate("a\0", 'b')]));
    }

    /** A binary that states no revocation state is older than this package: create refuses it. */
    public function testABinaryThatStatesNoRevocationStateFailsCreate(): void
    {
        foreach ([
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":3145729}}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":3145729},"revocation_urls":[]}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":3145729},"revocation_urls":[1],"revocation_valid_until_ms":null}',
            '{"abi":"aprv:verifier@0.2.0","limits":{"max_input_bytes":3145729},"revocation_urls":[],"revocation_valid_until_ms":"1"}',
        ] as $info) {
            $this->cli->behave(['info' => $info]);
            try {
                $this->transport()->open(new Config());
                self::fail("aprv info answered {$info}: create must refuse it");
            } catch (RuntimeException $e) {
                self::assertStringContainsString('revocation_urls', $e->getMessage(), $info);
            }
        }
    }

    public function testTheRootsFileIsOwnerOnlyOnEveryCallAndDeletedWithTheTransport(): void
    {
        $transport = $this->transport();
        $transport->open(new Config(roots: ["\x30\x00"]));
        $transport->call(Operation::Receipt, 'x', 1);
        $transport->call(Operation::EndpointProduction, 'x', 1);

        $log = $this->cli->log();
        $files = array_values(array_unique(array_filter(array_column($log, 'roots_file'))));
        self::assertCount(1, $files, 'one file per transport, however many calls');
        self::assertSame(['0600'], array_values(array_unique(array_filter(array_column($log, 'roots_file_mode')))));
        $file = (string) $files[0];
        self::assertFileExists($file);
        self::assertSame(['--roots', $file], array_slice($log[2]['argv'], -2), 'every call passes it');

        unset($transport);
        self::assertFileDoesNotExist($file, 'deleted when the transport is destroyed');
    }

    public function testADestroyedVerifierLeavesNoRootsFile(): void
    {
        $verifier = Verifier::create(
            new Config(roots: ["\x30\x00"]),
            $this->transport(),
        );
        $file = (string) $this->cli->log()[0]['roots_file'];
        self::assertFileExists($file);

        unset($verifier);
        self::assertFileDoesNotExist($file);
    }

    public function testAFailedOpenStillCleansUpTheRootsFile(): void
    {
        $this->cli->behave(['info_exit' => 2, 'info_stderr' => 'aprv: the component refused the configuration']);
        $transport = $this->transport();
        try {
            $transport->open(new Config(roots: ["\x30\x00"]));
            self::fail('a refused root must fail open');
        } catch (InvalidArgumentException) {
            $file = (string) $this->cli->log()[0]['roots_file'];
        }
        unset($transport);
        self::assertFileDoesNotExist($file);
    }

    public function testARootTheModuleRefusesIsAnArgumentErrorAtCreate(): void
    {
        $this->cli->behave(['info_exit' => 2, 'info_stderr' => "aprv: the component refused the configuration: roots[0]: trust anchor is not a certificate\n"]);

        try {
            Verifier::create(new Config(roots: ['not a certificate']), $this->transport());
            self::fail('create must refuse it');
        } catch (InvalidArgumentException $e) {
            self::assertStringContainsString('refused the configuration', $e->getMessage());
            self::assertStringContainsString('trust anchor is not a certificate', $e->getMessage());
        }
    }

    public function testAMissingOrNonExecutableBinaryFailsCreateWithTheWayOut(): void
    {
        foreach ([
            new CliTransport(sys_get_temp_dir() . '/there-is-no-aprv-here'),
            new CliTransport($this->cli->directory . '/mode.json'),
        ] as $transport) {
            try {
                $transport->open(new Config());
                self::fail('no binary, no verifier');
            } catch (RuntimeException $e) {
                self::assertStringContainsString('aprv-install', $e->getMessage());
                self::assertStringContainsString('HttpTransport', $e->getMessage());
            }
        }
    }

    public function testABinaryOfAnotherAbiFailsCreateNamingBothVersions(): void
    {
        $this->cli->behave(['info' => '{"abi":"aprv:verifier@2.0.0"}']);

        try {
            $this->transport()->open(new Config());
            self::fail('an ABI mismatch is a hard failure');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('aprv:verifier@2.0.0', $e->getMessage());
            self::assertStringContainsString('aprv:verifier@0.2.0', $e->getMessage());
        }
    }

    public function testABinaryThatAnswersNoInfoFailsCreate(): void
    {
        foreach (['not json', '{"abi":42}', '[]'] as $info) {
            $this->cli->behave(['info' => $info]);
            try {
                $this->transport()->open(new Config());
                self::fail("aprv info answered {$info}: create must refuse it");
            } catch (RuntimeException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testATransportServesOneVerifier(): void
    {
        $transport = $this->transport();
        $transport->open(new Config());

        $this->expectException(LogicException::class);
        $transport->open(new Config());
    }

    /**
     * The input length comes from `aprv info` in open(): a call before it
     * would cut every input to nothing and get the module's MALFORMED back
     * as if the caller had sent an empty receipt.
     */
    public function testACallBeforeOpenIsALogicErrorAndStartsNoProcess(): void
    {
        $transport = $this->transport();
        try {
            $transport->call(Operation::Receipt, 'MIIT', 1);
            self::fail('call() before open() must throw');
        } catch (LogicException $e) {
            self::assertStringContainsString('open()', $e->getMessage());
        }
        self::assertSame([], $this->cli->log());
    }

    /**
     * aprv's one-shot commands read no variable, and symfony/process would
     * otherwise hand the child getenv() and $_ENV, where Dotenv puts an
     * application's secrets. Only PATH goes through (the wrapper script
     * adds its own FAKE_APRV_DIR).
     */
    public function testTheBinaryGetsNoneOfTheCallersEnvironment(): void
    {
        $_ENV['APRV_TEST_LEAK'] = 'from $_ENV';
        putenv('APRV_TEST_LEAK_GETENV=from getenv()');
        try {
            $this->opened()->call(Operation::Receipt, 'x', 1);
        } finally {
            unset($_ENV['APRV_TEST_LEAK']);
            putenv('APRV_TEST_LEAK_GETENV');
        }

        $names = $this->cli->log()[0]['env_names'];
        self::assertNotContains('APRV_TEST_LEAK', $names);
        self::assertNotContains('APRV_TEST_LEAK_GETENV', $names);
        self::assertContains('PATH', $names, 'what the OS needs to start a binary stays');
        self::assertNotContains('HOME', $names);
    }

    public function testATimeoutUnderOneSecondIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('timeoutSeconds must be at least 1');
        new CliTransport($this->cli->executable, 0);
    }

    /** A relative path names the file it names, not a binary of that name on PATH. */
    public function testARelativePathRunsThatFile(): void
    {
        $cwd = (string) getcwd();
        chdir($this->cli->directory);
        try {
            $transport = new CliTransport('aprv');
            $transport->open(new Config());
            $transport->call(Operation::Receipt, 'x', 1);
        } finally {
            chdir($cwd);
        }

        self::assertSame([['info'], ['verify-receipt', '--now-ms', '1']], array_column($this->cli->log(), 'argv'));
    }

    public function testWhatTheBinaryPrintsOnStderrNeverReachesTheCallersOutput(): void
    {
        $this->cli->behave(['stderr' => 'a warning', 'stdout' => '{"status":0}']);

        self::assertSame('{"status":0}', $this->opened()->call(Operation::EndpointSandbox, '{}', 1));
    }

    // --- against the real binary --------------------------------------------------

    /** Over the 3 MiB cap, aprv exits 3 with the module's own answer, which the façade reads as any other. */
    public function testAnInputOverTheCapIsTooLargeOnEveryOperationThroughTheRealBinary(): void
    {
        $verifier = Verifier::create(new Config(), new CliTransport(Aprv::binary()));
        $over = str_repeat('A', 3145728 + 1);
        $receipt = Outcome::failure($verifier->verifyReceipt(str_repeat('A', 20 * 1024 * 1024)));
        self::assertSame(Reason::TooLarge, $receipt->reason);
        self::assertNull($receipt->cause, 'the module\'s verdict, not a transport failure');
        self::assertStringContainsString('3145728', $receipt->message, 'the module\'s own message');

        self::assertSame(Reason::TooLarge, Outcome::failure($verifier->verifyReceipt($over))->reason);
        self::assertSame(Reason::TooLarge, Outcome::failure($verifier->verifySignedData($over))->reason);
        self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Production, $over));
        self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, $over));
    }

    public function testARootTheRealModuleRefusesIsAnArgumentErrorAtCreate(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/refused the configuration/');
        Verifier::create(new Config(roots: ['not a certificate']), new CliTransport(Aprv::binary()));
    }

    /** A root is DER or PEM bytes: Apple's own root opens both ways. */
    public function testARealRootIsAcceptedAsDerAndAsPem(): void
    {
        $der = (string) file_get_contents(__DIR__ . '/../../certs/AppleRootCA-G3.cer');
        Verifier::create(new Config(roots: [$der]), new CliTransport(Aprv::binary()));
        $this->addToAssertionCount(1);

        // The module reads a PEM root itself (DECISIONS.md R39, amended); the façade passes the bytes on.
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
        Verifier::create(new Config(roots: [$pem]), new CliTransport(Aprv::binary()));
        $this->addToAssertionCount(1);
    }

    public function testTheRealBinaryOpensWithTheBuiltInRoots(): void
    {
        $verifier = Verifier::create(
            new Config(clock: new FrozenClock(new DateTimeImmutable('2026-01-01T00:00:00Z'))),
            new CliTransport(Aprv::binary()),
        );
        // Not a receipt, so a verdict of the module's, and a JSON object with an integer status at the endpoint.
        self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, 'not json'));
        // The built-in roots expect Apple's four lists, and none is held.
        self::assertSame(
            [
                'http://crl.apple.com/root.crl',
                'http://crl.apple.com/applerootcag3.crl',
                'http://crl.apple.com/wwdrg5.crl',
                'http://crl.apple.com/wwdrg6.crl',
            ],
            $verifier->revocationUrls(),
        );
        self::assertNull($verifier->revocationValidUntil());
    }

    public function testADistrustEntryTheRealModuleRefusesIsAnArgumentErrorAtCreate(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/refused the configuration.*distrust\[0\]/');
        Verifier::create(new Config(distrust: [new RevokedCertificate('ab', '01')]), new CliTransport(Aprv::binary()));
    }
}
