<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Aprv;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

/** The 311 cases through the default transport: one `aprv` process per call. */
final class ConformanceCasesTest extends ConformanceBase
{
    protected static function verifierFor(Config $config): Verifier
    {
        return Verifier::create($config, new CliTransport(Aprv::binary()));
    }
}
