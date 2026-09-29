<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

/**
 * The four operations `aprv` runs, each with the two spellings the wire
 * contract gives it: the one-shot CLI's arguments and the server's route.
 */
enum Operation
{
    case Receipt;
    case SignedData;
    case EndpointProduction;
    case EndpointSandbox;

    /** @return list<string> the subcommand and its positional argument */
    public function cliArguments(): array
    {
        return match ($this) {
            self::Receipt => ['verify-receipt'],
            self::SignedData => ['verify-signed-data'],
            self::EndpointProduction => ['verify-receipt-endpoint', 'production'],
            self::EndpointSandbox => ['verify-receipt-endpoint', 'sandbox'],
        };
    }

    public function httpPath(): string
    {
        return match ($this) {
            self::Receipt => '/v1/receipt/verify',
            self::SignedData => '/v1/signed-data/verify',
            self::EndpointProduction => '/v1/verify-receipt/production',
            self::EndpointSandbox => '/v1/verify-receipt/sandbox',
        };
    }
}
