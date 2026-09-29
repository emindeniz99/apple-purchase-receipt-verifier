<?php

declare(strict_types=1);

// Router for `php -S`: a stand-in for `aprv serve`. It logs each request to
// requests.jsonl and answers from responses.json, both in FAKE_SERVER_DIR:
// {"GET /v1/info": {"status": 200, "body": "...", "headers": {}}, ...}, and
// "default" for every other route.

$dir = (string) getenv('FAKE_SERVER_DIR');
$body = (string) file_get_contents('php://input');
$headers = [];
foreach ($_SERVER as $name => $value) {
    if (str_starts_with((string) $name, 'HTTP_')) {
        $headers[strtolower(str_replace('_', '-', substr((string) $name, 5)))] = $value;
    }
}
$key = $_SERVER['REQUEST_METHOD'] . ' ' . parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
file_put_contents($dir . '/requests.jsonl', json_encode([
    'key' => $key,
    'headers' => $headers,
    'body_length' => strlen($body),
    'body_sha256' => hash('sha256', $body),
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
]) . "\n", FILE_APPEND);

$responses = json_decode((string) file_get_contents($dir . '/responses.json'), true);
$response = $responses[$key] ?? $responses['default'] ?? ['status' => 404, 'body' => ''];
http_response_code((int) $response['status']);
foreach ($response['headers'] ?? [] as $name => $value) {
    header($name . ': ' . $value);
}
echo $response['body'] ?? '';
