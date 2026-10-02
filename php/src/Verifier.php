<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Wire;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\CliTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\InputTooLargeException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ServerProcessException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Transport;
use InvalidArgumentException;
use RangeException;
use RuntimeException;
use Throwable;

/**
 * The library's one entry point (docs/design/0.7-api.md, "Setup"). Every
 * method here answers one question — did Apple sign this data, under a
 * pinned Apple root? — and no method ever throws for any input it is asked
 * to verify.
 *
 * The verification itself runs in `aprv`, one binary that hosts the shared
 * verification module (docs/rust-core/ARCHITECTURE.md §7.9). This class
 * holds no verification logic: it reads the {@see Config} clock once per
 * call, hands the input to a {@see Transport} and maps the JSON that comes
 * back onto the 0.7 types. The default transport starts `aprv` once per
 * call; {@see Transport\HttpTransport} talks to a server the caller runs.
 *
 * ```php
 * $verifier = Verifier::create(Config::defaults());
 * $result = $verifier->verifyReceipt($base64FromTheClient);
 * if ($result->verified()) {
 *     $receipt = $result->payload;
 * }
 * ```
 *
 * The six outcomes of a call, kept distinct: a verified payload, a
 * verification failure (a {@see Reason} from the module), caller misuse
 * (thrown by {@see create()}), an ABI mismatch (thrown by {@see create()}),
 * a module trap or unreadable answer ({@see Reason::InternalError} with a
 * {@see ModuleFaultException} cause) and a server process failure
 * ({@see Reason::InternalError} with a {@see ServerProcessException} cause).
 */
final class Verifier
{
    private const TOO_LARGE_MESSAGE = 'the input is over the size cap aprv accepts';

    private function __construct(
        private readonly Transport $transport,
        private readonly Config $config,
    ) {
    }

    /**
     * @param Transport|null $transport how to reach `aprv`; null starts the binary
     *        `bin/aprv-install` installed, once per call
     *
     * @throws RuntimeException on a 32-bit build: Apple's epoch-millisecond
     *         timestamps (~1.7x10^12) do not fit a 32-bit `int`, and letting
     *         one through would mean `json_decode` silently degrading every
     *         date to a float rather than refusing to run at all; when the
     *         `aprv` binary or server cannot be used or speaks another ABI
     * @throws InvalidArgumentException when the root set is an empty list
     *         (leave the roots out for the built-in ones), when a root is
     *         not a string or the module refuses it (for example a value that is not a
     *         certificate), or when the server refuses the token or trusts
     *         other roots than `$config` names
     */
    public static function create(Config $config, ?Transport $transport = null): self
    {
        if (PHP_INT_SIZE < 8) {
            throw new RuntimeException(
                'this library requires a 64-bit PHP build: Apple\'s epoch-millisecond '
                . 'timestamps do not fit a 32-bit int',
            );
        }
        if ($config->roots === []) {
            throw new InvalidArgumentException(
                'the root set is empty: leave the roots out (Config::defaults()) for the built-in Apple roots, or give at least one',
            );
        }
        foreach ($config->roots ?? [] as $root) {
            self::requireDer($root);
        }
        $transport ??= new CliTransport();
        $transport->open($config->roots);

        return new self($transport, $config);
    }

    /** @throws InvalidArgumentException */
    private static function requireDer(mixed $root): void
    {
        if (!is_string($root) || $root === '') {
            throw new InvalidArgumentException('every root must be a non-empty string of DER or PEM bytes');
        }
    }

    /**
     * Verifies a legacy PKCS#7 app receipt and decodes it
     * (docs/design/0.7-api.md §1). Never throws.
     *
     * @return VerificationResult<ReceiptPayload>
     */
    public function verifyReceipt(?string $base64): VerificationResult
    {
        try {
            $nowMs = $this->clockMillis();
        } catch (Throwable $e) {
            return self::failed(self::clockFailure($e));
        }
        try {
            return Wire::receiptResult($this->transport->call(Operation::Receipt, $base64 ?? '', $nowMs));
        } catch (InputTooLargeException) {
            return self::failed(new Failure(Reason::TooLarge, self::TOO_LARGE_MESSAGE));
        } catch (Throwable $e) {
            return self::failed(self::internalError($e));
        }
    }

    /**
     * Verifies an Apple-signed compact JWS and returns its payload
     * (docs/design/0.7-api.md §2). Never throws.
     *
     * @return VerificationResult<JsonPayload>
     */
    public function verifySignedData(?string $jws): VerificationResult
    {
        try {
            $nowMs = $this->clockMillis();
        } catch (Throwable $e) {
            return self::failed(self::clockFailure($e));
        }
        try {
            return Wire::signedDataResult($this->transport->call(Operation::SignedData, $jws ?? '', $nowMs));
        } catch (InputTooLargeException) {
            return self::failed(new Failure(Reason::TooLarge, self::TOO_LARGE_MESSAGE));
        } catch (Throwable $e) {
            return self::failed(self::internalError($e));
        }
    }

    /**
     * A local stand-in for Apple's deprecated `verifyReceipt` endpoint:
     * same request body, same response body shape, same status codes, but
     * verified offline against the pinned roots instead of by calling
     * Apple (docs/design/0.7-api.md §3). Like Apple's endpoint, this checks
     * no bundle id: the caller compares `receipt.bundle_id`. Never throws:
     * a failure of this library is status 21009.
     */
    public function verifyReceiptEndpoint(Environment $environment, ?string $requestJson): string
    {
        try {
            $nowMs = $this->clockMillis();
        } catch (Throwable) {
            return self::status(AppleStatus::InternalDataAccessError);
        }
        $operation = match ($environment) {
            Environment::Production => Operation::EndpointProduction,
            Environment::Sandbox => Operation::EndpointSandbox,
        };
        try {
            return Wire::endpointAnswer($this->transport->call($operation, $requestJson ?? '', $nowMs));
        } catch (InputTooLargeException) {
            return self::status(AppleStatus::MalformedReceiptData);
        } catch (Throwable) {
            return self::status(AppleStatus::InternalDataAccessError);
        }
    }

    /**
     * The `Config` clock in epoch milliseconds, read once per call before
     * the input is looked at.
     *
     * @throws RangeException when the clock is before 1970: `now-ms` is unsigned
     */
    private function clockMillis(): int
    {
        $now = $this->config->clock->now();
        $ms = $now->getTimestamp() * 1000 + intdiv((int) $now->format('u'), 1000);
        if ($ms < 0) {
            throw new RangeException('the configured clock is before 1970');
        }

        return $ms;
    }

    /**
     * A result that carries no payload, typed as fitting any payload type.
     *
     * @return VerificationResult<never>
     */
    private static function failed(Failure $failure): VerificationResult
    {
        // PHPStan infers T from the payload argument, and a failure has
        // none, so it falls back to mixed. never is exact: no payload value
        // exists, and T is covariant, so this result is a
        // VerificationResult<ReceiptPayload> and a
        // VerificationResult<JsonPayload> alike.
        /** @var VerificationResult<never> $result */
        $result = new VerificationResult(failure: $failure);

        return $result;
    }

    private static function clockFailure(Throwable $e): Failure
    {
        return new Failure(Reason::InternalError, 'the configured clock failed', $e);
    }

    /** A failure of this library, never a verdict of the module: the cause says which. */
    private static function internalError(Throwable $e): Failure
    {
        $message = match (true) {
            $e instanceof ModuleFaultException => 'the verification module trapped or answered unreadably',
            $e instanceof ServerProcessException => 'aprv did not answer',
            default => 'unexpected ' . $e::class,
        };

        return new Failure(Reason::InternalError, $message, $e);
    }

    private static function status(int $status): string
    {
        return json_encode(['status' => $status], JSON_THROW_ON_ERROR);
    }
}
