<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use RuntimeException;

/**
 * A PHP built-in web server standing in for `aprv serve`, or serving files:
 * answers from a responses table, logs every request.
 */
final class FakeServer
{
    public readonly string $directory;

    public readonly string $url;

    /** @var resource */
    private $process;

    /**
     * @param array<string, array<string, mixed>> $responses "METHOD /path" => {status, body, headers}
     * @param string|null $documentRoot serve this directory's files instead of the router
     */
    public function __construct(array $responses = [], ?string $documentRoot = null)
    {
        $directory = tempnam(sys_get_temp_dir(), 'aprv-server-');
        if ($directory === false) {
            throw new RuntimeException('cannot create a temporary directory');
        }
        unlink($directory);
        mkdir($directory, 0700);
        $this->directory = $directory;
        $this->respond($responses);

        $probe = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        if ($probe === false) {
            throw new RuntimeException("cannot find a free port: {$error}");
        }
        $port = (int) substr((string) stream_socket_get_name($probe, false), strlen('127.0.0.1:'));
        fclose($probe);

        $arguments = [PHP_BINARY, '-S', "127.0.0.1:{$port}"];
        if ($documentRoot !== null) {
            // A router that logs the request and then lets the server serve the file.
            file_put_contents($directory . '/router.php', '<?php file_put_contents(' . var_export($directory . '/requests.jsonl', true)
                . ', json_encode(["key" => $_SERVER["REQUEST_METHOD"] . " " . parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH)]) . "\n", FILE_APPEND); return false;');
            array_push($arguments, '-t', $documentRoot, $directory . '/router.php');
        } else {
            array_push($arguments, __DIR__ . '/fake-server.php');
        }
        $process = proc_open(
            $arguments,
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            ['FAKE_SERVER_DIR' => $directory, 'PATH' => (string) getenv('PATH')],
        );
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start php -S');
        }
        $this->process = $process;
        $this->url = "http://127.0.0.1:{$port}";
        for ($attempt = 0; $attempt < 100; ++$attempt) {
            $socket = @stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $error, 0.2);
            if ($socket !== false) {
                fclose($socket);

                return;
            }
            usleep(50_000);
        }
        $this->stop();
        throw new RuntimeException('php -S did not come up');
    }

    /** @param array<string, array<string, mixed>> $responses */
    public function respond(array $responses): void
    {
        file_put_contents($this->directory . '/responses.json', json_encode($responses, JSON_THROW_ON_ERROR));
    }

    /** @return list<array<string, mixed>> */
    public function requests(): array
    {
        $entries = [];
        foreach (@file($this->directory . '/requests.jsonl', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            /** @var array<string, mixed> $entry */
            $entry = json_decode($line, true, 8, JSON_THROW_ON_ERROR);
            $entries[] = $entry;
        }

        return $entries;
    }

    public function stop(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
        foreach (glob($this->directory . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->directory);
    }
}
