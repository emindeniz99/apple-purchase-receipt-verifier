<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * The App Store environment a payload was issued in, spelled exactly as the
 * JWS claim spells it (`environment` on a transaction, `receiptType` on an
 * AppTransaction).
 *
 * Verification takes an accept-*set* rather than a single value: App Review
 * runs production builds against sandbox, so an endpoint that hard-failed on
 * anything but Production would reject purchases during review (PLAN.md D3).
 */
enum Environment: string
{
    case Production = 'Production';
    case Sandbox = 'Sandbox';
    case Xcode = 'Xcode';
    case LocalTesting = 'LocalTesting';
}
