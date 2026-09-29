<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Install;

use RuntimeException;

/** Why {@see Installer} installed nothing. `$exitCode` is what `bin/aprv-install` exits with. */
final class InstallException extends RuntimeException
{
    /** The download or the pinned hash failed. */
    public const FAILED = 1;

    /** Nothing to install: an unsupported platform, no pinned release, or a bad option. */
    public const UNAVAILABLE = 2;

    public function __construct(string $message, public readonly int $exitCode = self::FAILED)
    {
        parent::__construct($message);
    }
}
