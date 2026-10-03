<?php

declare(strict_types=1);

// A stand-in for the `aprv` CLI, run through a generated shell wrapper (see
// FakeCli). It logs what it was given and behaves as the directory's
// `mode.json` says: {"exit": 0, "stdout": "...", "stderr": "...", "sleep": 0,
// "read_stdin": true, "info": "<json>"}.
//
// `info` answers the ABI line and the module's input length; every other
// subcommand follows the mode.

$dir = (string) getenv('FAKE_APRV_DIR');
$mode = json_decode((string) @file_get_contents($dir . '/mode.json'), true);
$mode = is_array($mode) ? $mode : [];
$arguments = array_slice($argv, 1);

$rootsFile = null;
foreach ($arguments as $index => $argument) {
    if ($argument === '--roots' && isset($arguments[$index + 1])) {
        $rootsFile = $arguments[$index + 1];
    }
}
$stdin = ($mode['read_stdin'] ?? true) ? (string) stream_get_contents(STDIN) : '';
$entry = [
    'argv' => $arguments,
    'stdin_length' => strlen($stdin),
    'stdin_sha256' => hash('sha256', $stdin),
    'roots_file' => $rootsFile,
    'roots_file_mode' => $rootsFile !== null && is_file($rootsFile) ? substr(sprintf('%o', fileperms($rootsFile)), -4) : null,
    'roots_file_content' => $rootsFile !== null && is_file($rootsFile) ? file_get_contents($rootsFile) : null,
];
file_put_contents($dir . '/log.jsonl', json_encode($entry, JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND);

if (($arguments[0] ?? '') === 'info') {
    echo $mode['info'] ?? '{"abi":"aprv:verifier@0.1.0","limits":{"max_input_bytes":3145729}}';
    exit(0);
}
if (isset($mode['sleep'])) {
    sleep((int) $mode['sleep']);
}
if (isset($mode['signal'])) {
    posix_kill(posix_getpid(), (int) $mode['signal']);
    sleep(2);
}
fwrite(STDOUT, (string) ($mode['stdout'] ?? '{"status":21002}'));
fwrite(STDERR, (string) ($mode['stderr'] ?? ''));
exit((int) ($mode['exit'] ?? 0));
