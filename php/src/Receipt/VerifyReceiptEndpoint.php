<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use Closure;
use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ChainValidator;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Drop-in local replacement for Apple's deprecated `verifyReceipt` endpoint:
 * same request body, same response body shape, same status codes — but
 * verified offline against pinned Apple roots instead of by calling Apple
 * (PLAN.md D9). Field-by-field fidelity and the unavoidable gaps (fields that
 * only exist in Apple's server-side subscription database, such as
 * `latest_receipt_info` and `pending_renewal_info`) are documented in
 * COMPARISON.md.
 *
 * Like Apple's endpoint, this does **not** check the bundle id — the caller
 * compares `receipt.bundle_id`, exactly as with the real endpoint.
 *
 * No method ever throws on a request: a failure is a status and a
 * {@see Reason} on the returned {@see VerifyReceiptResult}.
 *
 * ```php
 * $endpoint = new VerifyReceiptEndpoint(AppleRootCerts::receiptRoots(), Environment::Production);
 * $result = $endpoint->verifyReceiptResult((string) $request->getBody());
 * $response->getBody()->write($result->toJson());
 * ```
 */
final class VerifyReceiptEndpoint
{
    public const STATUS_OK = 0;

    /** Malformed request, or a malformed `receipt-data` property. */
    public const STATUS_MALFORMED = 21002;

    /** The receipt could not be authenticated. */
    public const STATUS_NOT_AUTHENTICATED = 21003;

    /** A sandbox receipt was sent to the production environment. */
    public const STATUS_SANDBOX_RECEIPT_ON_PRODUCTION = 21007;

    /** A production receipt was sent to the sandbox environment. */
    public const STATUS_PRODUCTION_RECEIPT_ON_SANDBOX = 21008;

    /** Internal error. */
    public const STATUS_INTERNAL = 21009;

    /**
     * Ceiling on the raw request body {@see verifyReceiptResult()} and
     * {@see verifyReceiptJson()} will parse, in bytes. A PHP string is bytes,
     * so `strlen()` is the UTF-8 byte count Apple measures.
     *
     * 3 MiB, Apple's own limit: measured on 2026-09-23 against both of
     * Apple's verifyReceipt endpoints, a body of 3,145,728 bytes is answered
     * and one of 3,145,729 bytes gets HTTP 413, and the count is bytes, not
     * characters. A larger body fails with {@see Reason::RequestTooLarge},
     * status 21002, before it is parsed. A fixed constant, the same in every
     * port.
     *
     * "No method ever throws" is a promise about `Throwable`s, and a
     * `memory_limit` exhaustion is not one: it is a fatal error, so the worker
     * dies with no body at all. `json_decode` expands a JSON bomb, millions of
     * tiny arrays, by roughly 50 to 105 times its size (measured on PHP 8.4),
     * and `JSON_MAX_DEPTH` bounds nesting, not breadth, so a body at this cap
     * can need more than the `php.ini-production` default `memory_limit` of
     * 128M. The README's
     * "Defensive bounds" section gives the figure.
     */
    public const MAX_REQUEST_BYTES = 3145728;

    /** @var (Closure(Environment, ?AppReceipt, ?Reason, ?Throwable, DateTimeImmutable): VerifyReceiptResult)|null */
    private static ?Closure $newResult = null;

    /** @var list<string> */
    private readonly array $trustedRoots;

    private readonly ClockInterface $clock;

    /**
     * @param array<string> $trustedRoots DER bytes or PEM text of the pinned
     *        anchors. In production: {@see \EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts::receiptRoots()}.
     *        Keys are ignored: the anchors are reindexed into a list, so a
     *        caller may pass any string-keyed array.
     * @param Environment $environment which environment this endpoint
     *        instance emulates; it drives the 21007/21008 routing. Only
     *        {@see Environment::Production} and {@see Environment::Sandbox}
     *        are meaningful — Apple's endpoint has no third mode.
     * @param ClockInterface|null $clock source of "now" for the
     *        `request_date` triple, the only wall-clock-dependent output
     *        here; null installs {@see SystemClock}. It cannot move a
     *        certificate-validity verdict.
     *
     * @throws InvalidArgumentException on misconfiguration
     */
    public function __construct(
        array $trustedRoots,
        private readonly Environment $environment,
        ?ClockInterface $clock = null,
    ) {
        ReceiptVerifier::requireSixtyFourBit();
        ChainValidator::normalizeRoots($trustedRoots); // validate eagerly
        if ($environment !== Environment::Production && $environment !== Environment::Sandbox) {
            throw new InvalidArgumentException(
                'environment must be Environment::Production or Environment::Sandbox',
            );
        }
        $this->trustedRoots = array_values($trustedRoots);
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * Handles one verifyReceipt request: the decoded JSON body as an array,
     * or the raw JSON text an HTTP framework hands over as a string. Never
     * throws; a failure is the result's status and
     * {@see VerifyReceiptResult::failureReason()}.
     *
     * A raw body over {@see MAX_REQUEST_BYTES} bytes fails with
     * {@see Reason::RequestTooLarge}, status 21002, where Apple answers HTTP
     * 413; it is checked before the body is parsed. Anything else that is not
     * an array with a usable `receipt-data` fails with
     * {@see Reason::MalformedRequest}, status 21002: a body that is not a
     * JSON object (unparseable, `null`, a list, a scalar) or nests deeper than
     * 64 levels, or a `receipt-data` that is missing, empty or not a string.
     * A `receipt-data` over
     * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier::MAX_RECEIPT_BYTES}
     * bytes fails with {@see Reason::InvalidReceiptFormat}, also 21002,
     * before it is decoded. Apple has no status code for "that wasn't JSON";
     * 21002 is the closest, and it is what a JSON object without usable
     * `receipt-data` gets anyway.
     *
     * `password` and `exclude-old-transactions` are accepted for wire
     * compatibility and never read: the first cannot be validated offline,
     * and the second only affects `latest_receipt_info`, which this endpoint
     * never produces (COMPARISON.md).
     *
     * @param mixed $request the decoded body, or the raw JSON body as a string
     * @param DateTimeImmutable|null $now becomes `request_date` in place of
     *        the endpoint's clock. It reaches `request_date` and nothing else:
     *        certificate validity never sees it.
     */
    public function verifyReceiptResult(mixed $request, ?DateTimeImmutable $now = null): VerifyReceiptResult
    {
        try {
            $at = $now ?? $this->clock->now();
        } catch (Throwable $e) {
            return $this->clockFailed($e);
        }
        if (is_string($request)) {
            return $this->fromJson($request, $at);
        }
        if (!is_array($request)) {
            return $this->failed(Reason::MalformedRequest, $at);
        }
        $receiptData = $request['receipt-data'] ?? null;

        return $this->verify(is_string($receiptData) ? $receiptData : null, $at);
    }

    /**
     * Verifies a bare base64 receipt, the value a request body carries as
     * `receipt-data`, with no envelope around it. Never throws; null or an
     * empty string fails with {@see Reason::MalformedRequest}, as a missing
     * `receipt-data` does.
     *
     * @param DateTimeImmutable|null $now as for {@see verifyReceiptResult()}
     */
    public function verifyReceiptData(?string $receiptData, ?DateTimeImmutable $now = null): VerifyReceiptResult
    {
        try {
            $at = $now ?? $this->clock->now();
        } catch (Throwable $e) {
            return $this->clockFailed($e);
        }

        return $this->verify($receiptData, $at);
    }

    /**
     * Handles one verifyReceipt request in its raw wire form: the JSON
     * request body in, the JSON response body out, so a PSR-7 handler can
     * pipe a body straight through without a DTO in between. The same as
     * `verifyReceiptResult($requestJson)->toJson()`, and like it, never
     * throws.
     */
    public function verifyReceiptJson(string $requestJson): string
    {
        return $this->verifyReceiptResult($requestJson)->toJson();
    }

    /**
     * The clock is read once per call, before anything else. One that throws
     * would break "never throws", so it becomes an internal error instead,
     * stamped with the system clock since the injected one has no answer.
     */
    private function clockFailed(Throwable $e): VerifyReceiptResult
    {
        return self::newResult($this->environment, null, Reason::InternalError, $e, (new SystemClock())->now());
    }

    private function fromJson(string $requestJson, DateTimeImmutable $at): VerifyReceiptResult
    {
        // Before the parse and its depth limit, so a huge body is
        // REQUEST_TOO_LARGE however malformed it is.
        if (strlen($requestJson) > self::MAX_REQUEST_BYTES) {
            return $this->failed(Reason::RequestTooLarge, $at);
        }
        try {
            // json_decode's depth is one more than the nesting levels (`[]`
            // needs 2), so 65 admits 64 levels and refuses 65, the limit
            // every port shares.
            $parsed = json_decode($requestJson, true, 65, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return $this->failed(Reason::MalformedRequest, $at);
        }
        if (!is_array($parsed) || ($parsed !== [] && array_is_list($parsed))) {
            return $this->failed(Reason::MalformedRequest, $at);
        }
        $receiptData = $parsed['receipt-data'] ?? null;

        return $this->verify(is_string($receiptData) ? $receiptData : null, $at);
    }

    /**
     * The one verification path every entry point ends in. `$at` only
     * becomes `request_date`: certificate validity is judged inside
     * {@see ReceiptVerifier::verifyReceiptCore()}, which takes no time input.
     */
    private function verify(?string $receiptData, DateTimeImmutable $at): VerifyReceiptResult
    {
        try {
            if ($receiptData === null || $receiptData === '') {
                return $this->failed(Reason::MalformedRequest, $at);
            }
            // Decoding happens before `verifyReceiptCore` could apply its own
            // cap, so the cap is applied to the transport string here: the
            // same string, the same limit and the same reason that
            // `ReceiptVerifier::toDer()` would have used, and nothing is
            // allocated first.
            if (strlen($receiptData) > ReceiptVerifier::MAX_RECEIPT_BYTES) {
                return $this->failed(Reason::InvalidReceiptFormat, $at);
            }
            $der = Base64::decodeReceipt($receiptData);
            if ($der === null) {
                return $this->failed(Reason::InvalidReceiptFormat, $at);
            }
            // The primitive itself, not a ReceiptVerifier built around a
            // wildcard bundle id: like Apple's endpoint, no bundle-id claim
            // is checked here (callers compare receipt.bundle_id).
            $receipt = ReceiptVerifier::verifyReceiptCore($der, $this->trustedRoots);

            return self::newResult($this->environment, $receipt, null, null, $at);
        } catch (VerificationException $e) {
            return $this->failed($e->reason, $at);
        } catch (Throwable $e) {
            // "Never throws" is the contract, so it holds for a bug or an
            // exhausted resource inside verification just as it does for a
            // hostile receipt.
            return self::newResult($this->environment, null, Reason::InternalError, $e, $at);
        }
    }

    private function failed(Reason $reason, DateTimeImmutable $at): VerifyReceiptResult
    {
        return self::newResult($this->environment, null, $reason, null, $at);
    }

    /**
     * VerifyReceiptResult's constructor is private so that no caller can
     * build a result carrying status 0; this closure, bound to that class's
     * scope, is the endpoint's only way in.
     */
    private static function newResult(
        Environment $environment,
        ?AppReceipt $receipt,
        ?Reason $failureReason,
        ?Throwable $failureCause,
        DateTimeImmutable $requestDate,
    ): VerifyReceiptResult {
        $factory = self::$newResult ??= Closure::bind(
            static fn (
                Environment $environment,
                ?AppReceipt $receipt,
                ?Reason $failureReason,
                ?Throwable $failureCause,
                DateTimeImmutable $requestDate,
            ): VerifyReceiptResult => new VerifyReceiptResult(
                $environment,
                $receipt,
                $failureReason,
                $failureCause,
                $requestDate,
            ),
            null,
            VerifyReceiptResult::class,
        );

        return $factory($environment, $receipt, $failureReason, $failureCause, $requestDate);
    }
}
