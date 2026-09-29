<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use EminDeniz99\ApplePurchaseReceiptVerifier\Failure;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationResult;
use PHPUnit\Framework\Assert;

/** Narrows a {@see VerificationResult} to the side a test is about to read, failing the test when it is the other. */
final class Outcome
{
    /** @param VerificationResult<mixed> $result */
    public static function failure(VerificationResult $result): Failure
    {
        $failure = $result->failure;
        if ($failure === null) {
            Assert::fail('expected a failure, the input verified');
        }

        return $failure;
    }

    /**
     * @template T
     *
     * @param VerificationResult<T> $result
     *
     * @return T
     */
    public static function payload(VerificationResult $result): mixed
    {
        if (!$result->verified()) {
            Assert::fail('expected a payload, got ' . self::failure($result)->reason->value);
        }

        return $result->payload;
    }
}
