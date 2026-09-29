<?php
// Spike only. php run.php EXE URL TOKEN G5_B64 JWS CALLS_DIR NODE_DIR SLICE
// Both transports: g5 and the JWS, a corpus slice compared with the Node rows
// (public operations 1-4 only; request_date* masked on endpoint answers), timings.
declare(strict_types=1);
require __DIR__ . '/Aprv.php';
[$_, $exe, $url, $token, $g5f, $jwsf, $calls, $node, $slice] = $argv;
$g5 = trim(file_get_contents($g5f)); $jws = trim(file_get_contents($jwsf));
echo '# PHP ' . PHP_VERSION . ', curl ' . curl_version()['version'] . "\n";
$mask = fn(string $s) => preg_replace('/"(request_date(?:_ms|_pst)?)":"[^"]*"/', '"$1":"*"', $s);
$rows = [];
foreach (['cases', 'hostile'] as $c) {
    $ref = [];
    foreach (file("$node/node-$c.jsonl") as $l) { $r = json_decode($l, true); $ref[$r['id']] = $r; }
    foreach (file("$calls/$c.jsonl") as $l) {
        $call = json_decode($l, true);
        if (!isset($call['op']) || $call['op'] > 4) continue;
        $body = base64_decode($call['input']);
        if (strlen($body) > 3145728) continue; // refused by the server before the module (413)
        $rows[] = [$call['op'], $body, $ref[$call['id']]['out'] ?? null];
        if (count($rows) >= (int)$slice) break 2;
    }
}
foreach (['cli' => Aprv\Verifier::cli($exe), 'http' => Aprv\Verifier::http($url, $token)] as $name => $v) {
    $r = $v->verifyReceipt($g5);
    printf("%s: verifyReceipt(g5) %s\n", $name, str_starts_with($r, '{"verified":true') ? 'PASS verified' : 'FAIL ' . substr($r, 0, 80));
    $j = $v->verifySignedData($jws);
    printf("%s: verifySignedData(shared-sandbox JWS) %s\n", $name, str_contains($j, 'INVALID_CHAIN') ? 'PASS result value (not anchored by Apple roots)' : 'FAIL ' . substr($j, 0, 80));
    $e = $v->verifyReceiptEndpoint('sandbox', json_encode(['receipt-data' => $g5]));
    printf("%s: verifyReceiptEndpoint(sandbox) %s\n", $name, str_contains($e, '"status":0') ? 'PASS status 0' : 'FAIL ' . substr($e, 0, 80));
    $n = $name === 'cli' ? 50 : 300;
    $t = hrtime(true);
    for ($i = 0; $i < $n; $i++) $v->verifyReceipt($g5);
    printf("%s: g5 %.2f ms per call (%d calls)\n", $name, (hrtime(true) - $t) / 1e6 / $n, $n);
    $same = 0; $diff = 0; $t = hrtime(true);
    foreach ($rows as [$op, $body, $want]) {
        $got = $v->invoke($op, $body);
        if ($op >= 3) { $got = $mask($got); $want = $want === null ? null : $mask($want); }
        $got === $want ? $same++ : $diff++;
    }
    printf("%s: corpus slice %d rows (public ops, cases then hostile): %d identical to Node, %d different; %.2f ms per row\n",
        $name, count($rows), $same, $diff, (hrtime(true) - $t) / 1e6 / max(1, count($rows)));
}
