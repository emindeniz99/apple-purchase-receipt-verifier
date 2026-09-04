<?php

declare(strict_types=1);

/**
 * Test bootstrap: Composer's autoloader, plus a PSR-4 fallback for the test
 * namespace.
 *
 * The fallback exists because the test namespace lives in `autoload-dev`,
 * which a `--no-dev` install omits — and running the suite against a
 * production-shaped install is exactly the thing worth being able to do.
 */

require __DIR__ . '/../vendor/autoload.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'EminDeniz99\\ApplePurchaseReceiptVerifier\\Tests\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = __DIR__ . '/' . $relative . '.php';
    if (is_file($file)) {
        require $file;
    }
});
