<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use RuntimeException;

/**
 * Internal ASN.1 / X.509 decoding failure. Never escapes the library: every
 * public entry point converts it into a
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException}.
 *
 * @internal
 */
final class ParseException extends RuntimeException
{
}
