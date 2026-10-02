<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\CountingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FakeServer;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Outcome;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ServerProcessException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;

/**
 * The server transport: the headers and body it sends, how each problem
 * response of the wire contract maps onto the six outcomes, and the roots
 * check at create. A fake server answers the contract's shapes; the real
 * `aprv serve` answers the token and roots questions.
 */
#[CoversNothing]
final class HttpTransportTest extends TestCase
{
    private const INFO_PATH = 'GET /v1/info';

    private ?FakeServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->stop();
    }

    /** @param array<string, array<string, mixed>> $responses */
    private function server(array $responses): FakeServer
    {
        return $this->server = new FakeServer($responses);
    }

    /**
     * @param list<string> $fingerprints
     *
     * @return array<string, mixed>
     */
    private static function info(string $source = 'defaults', array $fingerprints = [], string $abi = 'aprv:verifier@0.1.0'): array
    {
        return [
            'status' => 200,
            'body' => json_encode(['abi' => $abi, 'roots' => ['source' => $source, 'sha256' => $fingerprints]], JSON_THROW_ON_ERROR),
        ];
    }

    /**
     * @param array<string, mixed> $problem
     *
     * @return array<string, mixed>
     */
    private static function problem(int $status, array $problem): array
    {
        return ['status' => $status, 'headers' => ['Content-Type' => 'application/problem+json'], 'body' => json_encode($problem, JSON_THROW_ON_ERROR)];
    }

    public function testACallSendsTheBytesTheClockAndTheTokenAndReturnsTheBodyUnchanged(): void
    {
        $answer = "{\"verified\":false,\"x\":\"\u{e9}\"}\n";
        $server = $this->server([
            self::INFO_PATH => self::info(),
            'default' => ['status' => 200, 'body' => $answer],
        ]);
        $transport = new HttpTransport($server->url . '/', 'sekret');
        $transport->open(null);
        $bytes = "a\0b\xff\xfe\r\n";

        foreach ([
            [Operation::Receipt, '/v1/receipt/verify'],
            [Operation::SignedData, '/v1/signed-data/verify'],
            [Operation::EndpointProduction, '/v1/verify-receipt/production'],
            [Operation::EndpointSandbox, '/v1/verify-receipt/sandbox'],
        ] as [$operation, $path]) {
            self::assertSame($answer, $transport->call($operation, $bytes, 1722945600123));
            $request = $server->requests()[count($server->requests()) - 1];
            self::assertSame('POST ' . $path, $request['key']);
            self::assertSame(hash('sha256', $bytes), $request['body_sha256'], 'the body is the input, byte for byte');
            self::assertSame('application/octet-stream', $request['content_type']);
            /** @var array<string, string> $headers */
            $headers = $request['headers'];
            self::assertSame('1722945600123', $headers['x-aprv-now-ms']);
            self::assertSame('sekret', $headers['x-aprv-token']);
            self::assertArrayNotHasKey('expect', $headers);
        }
        self::assertSame(self::INFO_PATH, $server->requests()[0]['key']);
        /** @var array<string, string> $infoHeaders */
        $infoHeaders = $server->requests()[0]['headers'];
        self::assertSame('sekret', $infoHeaders['x-aprv-token'], 'the info request carries the token too');
    }

    /**
     * An input over the cap is sent cut to one byte over it, the cut every
     * Wasm wrapper makes: the server reads no more of a body announced past
     * its drain limit and closes after its answer. An input at the cap is
     * sent whole.
     */
    public function testAnInputOverTheCapIsSentCutToOneByteOverIt(): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 200, 'body' => '{}']]);
        $transport = new HttpTransport($server->url);
        $transport->open(null);
        $twentyMib = str_repeat("A\xffB\0", 5 * 1024 * 1024);

        $transport->call(Operation::Receipt, $twentyMib, 1);
        $request = $server->requests()[count($server->requests()) - 1];
        self::assertSame(3145729, $request['body_length']);
        self::assertSame(hash('sha256', substr($twentyMib, 0, 3145729)), $request['body_sha256'], 'the first bytes, unchanged');

        $atCap = str_repeat('A', 3145728);
        $transport->call(Operation::Receipt, $atCap, 1);
        $request = $server->requests()[count($server->requests()) - 1];
        self::assertSame(hash('sha256', $atCap), $request['body_sha256'], 'an input at the cap is sent whole');
    }

    public function testNoTokenHeaderIsSentWithoutAToken(): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 200, 'body' => '{}']]);
        $transport = new HttpTransport($server->url);
        $transport->open(null);
        $transport->call(Operation::Receipt, 'x', 1);

        foreach ($server->requests() as $request) {
            /** @var array<string, string> $headers */
            $headers = $request['headers'];
            self::assertArrayNotHasKey('x-aprv-token', $headers);
        }
    }

    public function testOneCurlHandleServesEveryCall(): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 200, 'body' => '{}']]);
        $transport = new HttpTransport($server->url);
        $transport->open(null);
        $handle = new ReflectionProperty($transport, 'curl');

        $first = $handle->getValue($transport);
        $transport->call(Operation::Receipt, 'x', 1);
        $transport->call(Operation::Receipt, 'x', 2);
        self::assertSame($first, $handle->getValue($transport), 'one handle, so curl keeps the connection alive');
    }

    // --- problems ------------------------------------------------------------------

    /** @return iterable<string, array{array<string, mixed>, class-string<\Throwable>}> */
    public static function problemProvider(): iterable
    {
        // A 413 problem is an older server's, not the module's answer.
        yield '413 PAYLOAD_TOO_LARGE problem' => [self::problem(413, ['code' => 'PAYLOAD_TOO_LARGE', 'status' => 413]), ServerProcessException::class];
        yield '413 with no body at all' => [['status' => 413, 'body' => ''], ServerProcessException::class];
        yield '500 WASM_TRAP' => [self::problem(500, ['code' => 'WASM_TRAP', 'detail' => 'trap: unreachable']), ModuleFaultException::class];
        yield '500 ABI_ERROR' => [self::problem(500, ['code' => 'ABI_ERROR', 'detail' => 'not utf-8']), ModuleFaultException::class];
        yield '500 INTERNAL_ERROR' => [self::problem(500, ['code' => 'INTERNAL_ERROR']), ServerProcessException::class];
        yield '401 UNAUTHORIZED' => [self::problem(401, ['code' => 'UNAUTHORIZED']), ServerProcessException::class];
        yield '400 BAD_REQUEST' => [self::problem(400, ['code' => 'BAD_REQUEST']), ServerProcessException::class];
        yield '404 NOT_FOUND' => [self::problem(404, ['code' => 'NOT_FOUND']), ServerProcessException::class];
        yield '405 METHOD_NOT_ALLOWED' => [self::problem(405, ['code' => 'METHOD_NOT_ALLOWED']), ServerProcessException::class];
        yield '502 from a proxy, HTML' => [['status' => 502, 'body' => '<html>Bad gateway</html>'], ServerProcessException::class];
        yield '500 with a body that is not a problem' => [['status' => 500, 'body' => 'oops'], ServerProcessException::class];
        yield '503 with an unknown code' => [self::problem(503, ['code' => 'SOMETHING_NEW']), ServerProcessException::class];
    }

    /**
     * @param array<string, mixed> $response
     * @param class-string<\Throwable> $exception
     */
    #[DataProvider('problemProvider')]
    public function testEachProblemOfTheContractMapsToItsOutcome(array $response, string $exception): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => $response]);
        $transport = new HttpTransport($server->url);
        $transport->open(null);

        $this->expectException($exception);
        $transport->call(Operation::Receipt, 'x', 1);
    }

    public function testTheFaçadeAnswersEachProblemAsItsOutcome(): void
    {
        // A 413 carries the module's own answer to an input over the cap, read as a 200 is.
        $tooLarge = '{"verified":false,"reason":"TOO_LARGE","message":"said by the module"}';
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 413, 'headers' => ['Content-Type' => 'application/json'], 'body' => $tooLarge]]);
        $verifier = Verifier::create(new Config(), new HttpTransport($server->url));
        $receipt = Outcome::failure($verifier->verifyReceipt('x'));
        self::assertSame(Reason::TooLarge, $receipt->reason);
        self::assertSame('said by the module', $receipt->message);
        $server->respond([self::INFO_PATH => self::info(), 'default' => ['status' => 413, 'headers' => ['Content-Type' => 'application/json'], 'body' => '{"status":21002}']]);
        self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Production, '{}'));

        $server->respond([self::INFO_PATH => self::info(), 'default' => self::problem(500, ['code' => 'WASM_TRAP', 'detail' => 'unreachable'])]);
        $trap = Outcome::failure($verifier->verifySignedData('x'));
        self::assertSame(Reason::InternalError, $trap->reason);
        self::assertInstanceOf(ModuleFaultException::class, $trap->cause);
        self::assertSame('WASM_TRAP', $trap->cause->category);
        self::assertSame('{"status":21009}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, '{}'));

        $server->respond([self::INFO_PATH => self::info(), 'default' => self::problem(500, ['code' => 'INTERNAL_ERROR'])]);
        $down = Outcome::failure($verifier->verifyReceipt('x'));
        self::assertSame(Reason::InternalError, $down->reason);
        self::assertInstanceOf(ServerProcessException::class, $down->cause);
    }

    public function testAServerThatIsGoneIsAProcessFailureNotAVerdict(): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 200, 'body' => '{"status":0}']]);
        $verifier = Verifier::create(new Config(), new HttpTransport($server->url, timeoutSeconds: 3));
        $server->stop();

        $result = $verifier->verifyReceipt('x');
        self::assertSame(Reason::InternalError, Outcome::failure($result)->reason);
        self::assertInstanceOf(ServerProcessException::class, Outcome::failure($result)->cause);
        self::assertSame('{"status":21009}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, '{}'));
    }

    // --- create --------------------------------------------------------------------

    public function testAnUnreachableServerFailsCreate(): void
    {
        $server = $this->server([]);
        $url = $server->url;
        $server->stop();

        $this->expectException(ServerProcessException::class);
        (new HttpTransport($url, timeoutSeconds: 3))->open(null);
    }

    public function testARefusedTokenIsAnArgumentErrorAtCreate(): void
    {
        $server = $this->server([self::INFO_PATH => self::problem(401, ['code' => 'UNAUTHORIZED'])]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('token');
        (new HttpTransport($server->url, 'wrong'))->open(null);
    }

    public function testAServerThatIsNotAprvFailsCreate(): void
    {
        foreach ([
            [['status' => 404, 'body' => 'no']],
            [['status' => 200, 'body' => 'hello']],
            [['status' => 200, 'body' => '{"abi":"other"}']],
            [self::info('defaults', [], 'aprv:verifier@2.0.0')],
        ] as [$info]) {
            $server = $this->server([self::INFO_PATH => $info]);
            try {
                (new HttpTransport($server->url))->open(null);
                self::fail('create must refuse ' . json_encode($info));
            } catch (RuntimeException $e) {
                // An ABI or shape problem is a RuntimeException, not caller misuse.
                $this->addToAssertionCount(1);
            }
            $server->stop();
        }
    }

    public function testAnAbiMismatchNamesBothVersions(): void
    {
        $server = $this->server([self::INFO_PATH => self::info('defaults', [], 'aprv:verifier@2.0.0')]);

        try {
            (new HttpTransport($server->url))->open(null);
            self::fail('an ABI mismatch is a hard failure');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('aprv:verifier@2.0.0', $e->getMessage());
            self::assertStringContainsString('aprv:verifier@0.1.0', $e->getMessage());
        }
    }

    /** @return iterable<string, array{list<string>|null, array<string, mixed>, bool}> */
    public static function rootsProvider(): iterable
    {
        $a = "\x30\x01\x0a";
        $b = "\x30\x01\x0b";
        $fa = hash('sha256', $a);
        $fb = hash('sha256', $b);

        yield 'built-in roots on a server with the built-in roots' => [null, self::info('defaults'), true];
        yield 'built-in roots on a server with custom roots' => [null, self::info('configured', [$fa]), false];
        yield 'custom roots on a server with the built-in roots' => [[$a], self::info('defaults'), false];
        yield 'the same roots' => [[$a, $b], self::info('configured', [$fa, $fb]), true];
        yield 'the same roots in another order' => [[$b, $a], self::info('configured', [$fa, $fb]), true];
        yield 'a duplicate in the Config' => [[$a, $a, $b], self::info('configured', [$fa, $fb]), true];
        yield 'one root fewer on the server' => [[$a, $b], self::info('configured', [$fa]), false];
        yield 'one root more on the server' => [[$a], self::info('configured', [$fa, $fb]), false];
        yield 'another root' => [[$a], self::info('configured', [$fb]), false];
        yield 'a server that reports no roots' => [[$a], ['status' => 200, 'body' => '{"abi":"aprv:verifier@0.1.0"}'], false];
    }

    /**
     * @param list<string>|null $roots
     * @param array<string, mixed> $info
     */
    #[DataProvider('rootsProvider')]
    public function testTheServersRootsMustBeExactlyTheConfigsRoots(?array $roots, array $info, bool $accepted): void
    {
        $server = $this->server([self::INFO_PATH => $info]);
        $transport = new HttpTransport($server->url);

        if ($accepted) {
            $transport->open($roots);
            $this->addToAssertionCount(1);

            return;
        }
        try {
            $transport->open($roots);
            self::fail('a server that trusts other roots than the Config names must be refused');
        } catch (InvalidArgumentException | RuntimeException $e) {
            // Refusing a mismatch is caller misuse where the server said what it trusts, a shape fault where it did not.
            self::assertTrue($e instanceof InvalidArgumentException || str_contains($e->getMessage(), 'roots'));
        }
    }

    public function testATransportServesOneVerifier(): void
    {
        $server = $this->server([self::INFO_PATH => self::info()]);
        $transport = new HttpTransport($server->url);
        $transport->open(null);

        $this->expectException(LogicException::class);
        $transport->open(null);
    }

    /** @return iterable<string, array{string, string|null}> */
    public static function badConstructionProvider(): iterable
    {
        yield 'no scheme' => ['127.0.0.1:8080', null];
        yield 'a path' => ['http://127.0.0.1:8080/v1', null];
        yield 'a query' => ['http://127.0.0.1:8080?x=1', null];
        yield 'a scheme that is not http' => ['file:///etc/passwd', null];
        yield 'a space' => ['http://127.0.0.1 :8080', null];
        yield 'a token with a header break' => ['http://127.0.0.1:8080', "abc\r\nX-Evil: 1"];
        yield 'a token with a newline' => ['http://127.0.0.1:8080', "abc\n"];
    }

    #[DataProvider('badConstructionProvider')]
    public function testAnUrlOrTokenThatCouldSteerTheRequestIsRefused(string $url, ?string $token): void
    {
        $this->expectException(InvalidArgumentException::class);
        new HttpTransport($url, $token);
    }

    public function testTheClockIsSentAsTheHeaderOncePerCall(): void
    {
        $server = $this->server([self::INFO_PATH => self::info(), 'default' => ['status' => 200, 'body' => '{"status":0}']]);
        $clock = new CountingClock();
        $verifier = Verifier::create(new Config(clock: $clock), new HttpTransport($server->url));

        $verifier->verifyReceiptEndpoint(Environment::Production, '{}');
        $verifier->verifyReceiptEndpoint(Environment::Production, '{}');

        $sent = [];
        foreach ($server->requests() as $request) {
            /** @var array<string, string> $headers */
            $headers = $request['headers'];
            if (isset($headers['x-aprv-now-ms'])) {
                $sent[] = $headers['x-aprv-now-ms'];
            }
        }
        $first = (int) $clock->first()->format('Uv');
        self::assertSame([(string) $first, (string) ($first + 1000)], $sent);
        self::assertSame(2, $clock->reads);
    }

    // --- the real server ---------------------------------------------------------------

    public function testTheTokenGatesTheRealServer(): void
    {
        $token = bin2hex(random_bytes(16));
        $server = Aprv::startServer(null, $token);
        try {
            // The right token: create and a call both work.
            $verifier = Verifier::create(new Config(), new HttpTransport($server->url, $token));
            self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, 'not json'));

            foreach ([null, 'wrong'] as $bad) {
                try {
                    Verifier::create(new Config(), new HttpTransport($server->url, $bad));
                    self::fail('a server with a token must refuse a client without it');
                } catch (InvalidArgumentException $e) {
                    self::assertStringContainsString('token', $e->getMessage());
                }
            }
        } finally {
            $server->stop();
        }
    }

    public function testAnInputOverTheCapIsTooLargeOnEveryOperationThroughTheRealServer(): void
    {
        $server = Aprv::startServer();
        try {
            $verifier = Verifier::create(new Config(), new HttpTransport($server->url));
            // One byte over, and past the server's 16 MiB drain limit, where
            // the server reads only what the module needs and then closes.
            foreach ([str_repeat('A', 3145728 + 1), str_repeat('A', 20 * 1024 * 1024)] as $over) {
                $receipt = Outcome::failure($verifier->verifyReceipt($over));
                self::assertSame(Reason::TooLarge, $receipt->reason, $receipt->message);
                self::assertNull($receipt->cause, 'the module\'s verdict, not a transport failure');
                self::assertSame(Reason::TooLarge, Outcome::failure($verifier->verifySignedData($over))->reason);
                self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Production, $over));
                self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Sandbox, $over));
            }
        } finally {
            $server->stop();
        }
    }

    public function testARealServerWithCustomRootsRefusesADefaultConfigAndAcceptsItsOwn(): void
    {
        // A server refuses roots that are not certificates at its own start, so the root is a real one.
        $certificate = (string) file_get_contents(__DIR__ . '/../../certs/AppleRootCA-G3.cer');
        $file = (string) tempnam(sys_get_temp_dir(), 'aprv-roots-');
        file_put_contents($file, base64_encode($certificate) . "\n");
        $server = Aprv::startServer($file);
        try {
            try {
                Verifier::create(new Config(), new HttpTransport($server->url));
                self::fail('the server runs one custom root, the Config asks for the built-in ones');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
            Verifier::create(new Config(roots: [$certificate]), new HttpTransport($server->url));
            $this->addToAssertionCount(1);
        } finally {
            $server->stop();
            @unlink($file);
        }
    }
}
