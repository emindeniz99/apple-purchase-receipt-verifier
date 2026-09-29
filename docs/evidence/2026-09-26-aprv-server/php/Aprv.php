<?php
// Spike only (2026-09-26). A minimal PHP client for aprv: one façade, two
// transports. No Composer package. The three calls return the module's JSON
// text unchanged (json_decode it as needed). Verification failures are
// values in that JSON; only transport, server or Wasm failures throw.
declare(strict_types=1);

namespace Aprv;

final class AprvException extends \RuntimeException {}

interface Transport {
    /** @param int $op 1 receipt, 2 signed data, 3 endpoint production, 4 endpoint sandbox */
    public function invoke(int $op, string $body): string;
}

/** One process per call: `aprv <subcommand>` reading stdin, JSON on stdout. */
final class CliTransport implements Transport {
    private const ARGS = [1 => ['verify-receipt'], 2 => ['verify-signed-data'],
        3 => ['verify-receipt-endpoint', 'production'], 4 => ['verify-receipt-endpoint', 'sandbox']];

    public function __construct(private string $executable) {}

    public function invoke(int $op, string $body): string {
        // An argv array: no shell is involved, nothing is interpolated.
        $p = proc_open(array_merge([$this->executable], self::ARGS[$op]),
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($p)) throw new AprvException('cannot start ' . $this->executable);
        // Write stdin and read stdout without deadlocking on large bodies.
        stream_set_blocking($pipes[0], false);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = ''; $err = ''; $off = 0; $len = strlen($body);
        while (true) {
            $r = [$pipes[1], $pipes[2]]; $w = $off < $len ? [$pipes[0]] : null; $x = null;
            if ($off >= $len && is_resource($pipes[0])) { fclose($pipes[0]); }
            if (stream_select($r, $w, $x, 30) === false) break;
            if ($w) { $n = fwrite($pipes[0], substr($body, $off, 65536)); if ($n === false) break; $off += $n; }
            foreach ($r as $s) {
                $chunk = fread($s, 65536);
                if ($s === $pipes[1]) $out .= $chunk; else $err .= $chunk;
            }
            if (feof($pipes[1]) && feof($pipes[2])) break;
        }
        foreach ($pipes as $s) if (is_resource($s)) fclose($s);
        $code = proc_close($p);
        if ($code === 3) throw new AprvException('request too large', 413);
        if ($code !== 0) throw new AprvException("aprv exited $code: " . trim($err));
        return $out;
    }
}

/** HTTP to a running aprv server (a sidecar, a container, a service). */
final class HttpTransport implements Transport {
    private const PATHS = [1 => '/v1/receipt/verify', 2 => '/v1/signed-data/verify',
        3 => '/v1/verify-receipt/production', 4 => '/v1/verify-receipt/sandbox'];
    private \CurlHandle $curl; // reused: keep-alive

    public function __construct(private string $baseUrl, private ?string $token = null) {
        $this->curl = curl_init();
    }

    public function invoke(int $op, string $body): string {
        $headers = ['Content-Type: application/octet-stream', 'Expect:'];
        if ($this->token !== null) $headers[] = 'X-Aprv-Token: ' . $this->token;
        curl_setopt_array($this->curl, [
            CURLOPT_URL => rtrim($this->baseUrl, '/') . self::PATHS[$op],
            CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_TCP_NODELAY => true,
            CURLOPT_PROXY => '', CURLOPT_NOPROXY => '*',
        ]);
        $out = curl_exec($this->curl);
        if ($out === false) throw new AprvException('aprv-server: ' . curl_error($this->curl));
        $status = curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE);
        if ($status !== 200) throw new AprvException("aprv-server HTTP $status: $out", $status);
        return $out;
    }
}

final class Verifier {
    public function __construct(private Transport $t) {}
    public static function cli(string $executable): self { return new self(new CliTransport($executable)); }
    public static function http(string $baseUrl, ?string $token = null): self { return new self(new HttpTransport($baseUrl, $token)); }

    public function verifyReceipt(string $receiptDataBase64): string { return $this->t->invoke(1, $receiptDataBase64); }
    public function verifySignedData(string $jws): string { return $this->t->invoke(2, $jws); }
    public function verifyReceiptEndpoint(string $environment, string $appleRequestJson): string {
        return $this->t->invoke(match ($environment) { 'production' => 3, 'sandbox' => 4 }, $appleRequestJson);
    }
    /** Spike only: the raw operation number, for the corpus slice. */
    public function invoke(int $op, string $body): string { return $this->t->invoke($op, $body); }
}
