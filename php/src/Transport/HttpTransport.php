<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use CurlHandle;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Info;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Input;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Text;
use InvalidArgumentException;
use LogicException;
use RuntimeException;

/**
 * A server the caller runs: `aprv serve`, as a sidecar, a Docker service or
 * a private-network service (docs/rust-core/ARCHITECTURE.md §7.7, §7.9).
 * One keep-alive curl handle carries every call, so a call costs about
 * 3.5 ms instead of a process's 12 ms.
 *
 * The roots live in the server (`aprv serve --roots FILE`, or the built-in
 * ones), not in the call. {@see open()} therefore compares the SHA-256 of
 * each root of the `Config` with what `GET /v1/info` says the server runs,
 * and refuses a server that trusts anything else. The server speaks plain
 * HTTP and is meant for loopback or a private network; terminate TLS in
 * front of it when the path is not one. No proxy is used.
 *
 * Needs `ext-curl`.
 */
final class HttpTransport implements Transport
{
    private const TOKEN_HEADER = 'X-Aprv-Token';

    private const NOW_HEADER = 'X-Aprv-Now-Ms';

    private ?CurlHandle $curl = null;

    private bool $opened = false;

    private readonly string $baseUrl;

    /**
     * @param string $baseUrl for example `http://127.0.0.1:8080`
     * @param string|null $token the server's `X-Aprv-Token`, when it has one
     * @param int $timeoutSeconds how long one request may take
     */
    public function __construct(
        string $baseUrl,
        private readonly ?string $token = null,
        private readonly int $timeoutSeconds = 30,
    ) {
        if (!extension_loaded('curl')) {
            throw new RuntimeException('HttpTransport needs ext-curl');
        }
        if (preg_match('#^https?://[^/?\#\s]+$#i', rtrim($baseUrl, '/')) !== 1) {
            throw new InvalidArgumentException('the server URL must be http(s)://host[:port], without a path');
        }
        if ($token !== null && preg_match('/[\x00-\x1f\x7f]/', $token) === 1) {
            throw new InvalidArgumentException('the token must not contain control characters');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public function open(?array $roots): void
    {
        if ($this->opened) {
            throw new LogicException('a transport serves one Verifier');
        }
        $this->opened = true;
        [$status, $body] = $this->request('GET', '/v1/info', null, null);
        if ($status === 401) {
            throw new InvalidArgumentException('the server refused the token');
        }
        if ($status !== 200) {
            throw new RuntimeException("GET /v1/info answered HTTP {$status}: is this an aprv server?");
        }
        $info = Info::decode($body, 'the server');
        $this->checkRoots($info, $roots);
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        [$status, $body, $type] = $this->request('POST', $operation->httpPath(), substr($input, 0, Input::MAX_BYTES), $nowMs);
        // A 413 carries the module's own answer to an input over the cap, as
        // JSON; a 413 problem document (an older server) falls through.
        if ($status === 200 || ($status === 413 && str_starts_with(strtolower($type), 'application/json'))) {
            return $body;
        }
        $problem = json_decode($body, true);
        $code = is_array($problem) && is_string($problem['code'] ?? null) ? $problem['code'] : null;
        $detail = is_array($problem) && is_string($problem['detail'] ?? null) ? Text::printable($problem['detail']) : '';
        if ($code === 'WASM_TRAP' || $code === 'ABI_ERROR') {
            throw new ModuleFaultException($code, "the server reported {$code}: {$detail}");
        }

        throw new ServerProcessException(
            "the server answered HTTP {$status}" . ($code === null ? '' : " {$code}") . ($detail === '' ? '' : ": {$detail}"),
        );
    }

    /**
     * @param array<array-key, mixed> $info
     * @param list<string>|null $roots
     */
    private function checkRoots(array $info, ?array $roots): void
    {
        $served = $info['roots'] ?? null;
        $source = is_array($served) ? ($served['source'] ?? null) : null;
        $fingerprints = is_array($served) ? ($served['sha256'] ?? null) : null;
        if (!is_string($source) || !is_array($fingerprints)) {
            throw new RuntimeException('the server did not report its roots');
        }
        if ($roots === null) {
            if ($source !== 'defaults') {
                throw new InvalidArgumentException(
                    'the server runs custom roots; give the Config those roots, or start the server without --roots',
                );
            }

            return;
        }
        $expected = array_map(static fn (string $der): string => hash('sha256', $der), $roots);
        $actual = array_map(static fn (mixed $one): string => is_string($one) ? $one : '', $fingerprints);
        $expected = array_values(array_unique($expected));
        $actual = array_values(array_unique($actual));
        sort($expected);
        sort($actual);
        if ($source !== 'configured' || $expected !== $actual) {
            throw new InvalidArgumentException(
                'the server trusts other roots than the Config names: start it with --roots for exactly these roots',
            );
        }
    }

    /**
     * @return array{int, string, string} the HTTP status, the body and its content type
     *
     * @throws ServerProcessException when no HTTP answer came back
     */
    private function request(string $method, string $path, ?string $body, ?int $nowMs): array
    {
        $headers = ['Expect:'];
        if ($this->token !== null) {
            $headers[] = self::TOKEN_HEADER . ': ' . $this->token;
        }
        $options = [
            CURLOPT_URL => $this->baseUrl . $path,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TCP_NODELAY => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROXY => '',
        ];
        if ($method === 'POST') {
            $options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/octet-stream';
            if ($nowMs !== null) {
                $options[CURLOPT_HTTPHEADER][] = self::NOW_HEADER . ': ' . $nowMs;
            }
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $body ?? '';
        } else {
            $options[CURLOPT_HTTPGET] = true;
        }
        // One handle for the transport's life: curl keeps the connection alive between calls.
        $this->curl ??= curl_init();
        curl_setopt_array($this->curl, $options);
        $answer = curl_exec($this->curl);
        if (!is_string($answer)) {
            throw new ServerProcessException('the server did not answer: ' . Text::printable(curl_error($this->curl)));
        }

        $type = curl_getinfo($this->curl, CURLINFO_CONTENT_TYPE);

        return [(int) curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE), $answer, is_string($type) ? $type : ''];
    }
}
