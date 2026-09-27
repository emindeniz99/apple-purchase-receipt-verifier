<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use DateTimeImmutable;
use DateTimeZone;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\AppleMarkers;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\BoundedJson;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ChainValidator;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Cms;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\CmsSignature;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\CmsSignerInfo;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\JwsPayloadReader;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ReceiptPayloadDecoder;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\SafeText;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\VerificationException;
use InvalidArgumentException;
use JsonException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Throwable;

/**
 * The library's one entry point (docs/design/0.7-api.md, "Setup"):
 * immutable, thread-safe once constructed. Every method here answers one
 * question — did Apple sign this data, under a pinned Apple root? — and no
 * method ever throws for any input it is asked to verify.
 *
 * ```php
 * $verifier = Verifier::create(Config::defaults());
 * $result = $verifier->verifyReceipt($base64FromTheClient);
 * if ($result->verified()) {
 *     $receipt = $result->payload;
 * }
 * ```
 */
final class Verifier
{
    /**
     * Ceiling on the receipt base64 string, in UTF-8 bytes: 0.7 takes only
     * base64, so the receipt cap is the base64 string's, not the DER's.
     */
    private const MAX_RECEIPT_BYTES = 3145728;

    /** Ceiling on the compact JWS, in UTF-8 bytes. */
    private const MAX_JWS_BYTES = 262144;

    /** Ceiling on the verifyReceipt endpoint request body, in UTF-8 bytes. */
    private const MAX_REQUEST_BYTES = 3145728;

    /** @var list<Certificate> */
    private readonly array $roots;

    private readonly ClockInterface $clock;

    private function __construct(array $roots, ClockInterface $clock)
    {
        $this->roots = $roots;
        $this->clock = $clock;
    }

    /**
     * @throws RuntimeException on a 32-bit build: Apple's epoch-millisecond
     *         timestamps (~1.7x10^12) do not fit a 32-bit `int`, and letting
     *         one through would mean `json_decode` silently degrading every
     *         date to a float rather than refusing to run at all
     * @throws InvalidArgumentException when `$config->roots` is empty or
     *         does not parse — a verifier with no roots would answer
     *         `UNTRUSTED_CHAIN` to everything and nobody would notice until
     *         production
     */
    public static function create(Config $config): self
    {
        if (PHP_INT_SIZE < 8) {
            throw new RuntimeException(
                'this library requires a 64-bit PHP build: Apple\'s epoch-millisecond '
                . 'timestamps do not fit a 32-bit int',
            );
        }

        return new self(ChainValidator::normalizeRoots($config->roots), $config->clock);
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
            return new VerificationResult(payload: $this->verifyReceiptInner($base64));
        } catch (VerificationException $e) {
            return new VerificationResult(failure: self::toFailure($e));
        } catch (Throwable $e) {
            return new VerificationResult(failure: self::internalError($e));
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
            return new VerificationResult(payload: $this->verifySignedDataInner($jws));
        } catch (VerificationException $e) {
            return new VerificationResult(failure: self::toFailure($e));
        } catch (Throwable $e) {
            return new VerificationResult(failure: self::internalError($e));
        }
    }

    /**
     * A local stand-in for Apple's deprecated `verifyReceipt` endpoint:
     * same request body, same response body shape, same status codes, but
     * verified offline against the pinned roots instead of by calling
     * Apple (docs/design/0.7-api.md §3). Like Apple's endpoint, this checks
     * no bundle id: the caller compares `receipt.bundle_id`. Never throws.
     */
    public function verifyReceiptEndpoint(Environment $environment, ?string $requestJson): string
    {
        // The clock is read before anything else, so a misbehaving
        // caller-supplied clock must be caught here too: nothing below this
        // line may let it escape the "never throws" contract.
        try {
            $requestDateMs = $this->clockMillis();
        } catch (Throwable) {
            return self::renderStatus(AppleStatus::InternalDataAccessError);
        }
        try {
            $receiptData = $this->extractReceiptData($requestJson);
        } catch (VerificationException $e) {
            return self::renderStatus(self::statusForReason($e->reason));
        } catch (Throwable) {
            return self::renderStatus(AppleStatus::InternalDataAccessError);
        }

        $result = $this->verifyReceipt($receiptData);
        if (!$result->verified()) {
            /** @var Failure $failure */
            $failure = $result->failure;

            return self::renderStatus(self::statusForReason($failure->reason));
        }
        /** @var ReceiptPayload $receipt */
        $receipt = $result->payload;
        $status = self::statusForEnvironment($environment, $receipt);
        if ($status !== AppleStatus::Ok) {
            return self::renderStatus($status);
        }

        return self::renderOk($environment, $receipt, $requestDateMs);
    }

    // --- shared plumbing --------------------------------------------------

    private function clockMillis(): int
    {
        $now = $this->clock->now();

        return $now->getTimestamp() * 1000 + intdiv((int) $now->format('u'), 1000);
    }

    /**
     * The cause is kept only behind {@see Reason::UnreadablePayload} and
     * {@see Reason::InternalError}: behind any other reason it would be a
     * parser or provider exception about unverified input, whose message
     * could quote raw certificate text a logged stack trace would print.
     */
    private static function toFailure(VerificationException $e): Failure
    {
        $keepCause = $e->reason === Reason::UnreadablePayload || $e->reason === Reason::InternalError;

        return new Failure($e->reason, $e->getMessage(), $keepCause ? $e->getPrevious() : null);
    }

    private static function internalError(Throwable $e): Failure
    {
        return new Failure(Reason::InternalError, 'unexpected ' . SafeText::quote($e::class), $e);
    }

    // --- verifyReceipt ------------------------------------------------------

    /** @throws VerificationException */
    private function verifyReceiptInner(?string $base64): ReceiptPayload
    {
        if ($base64 === null || $base64 === '') {
            throw new VerificationException(Reason::Malformed, 'receipt is empty');
        }
        // Checked before the transport form is decoded, so an oversized
        // base64 blob is rejected without allocating its decoding.
        if (strlen($base64) > self::MAX_RECEIPT_BYTES) {
            throw new VerificationException(
                Reason::TooLarge,
                'receipt exceeds the maximum accepted size of ' . self::MAX_RECEIPT_BYTES . ' bytes',
            );
        }
        $der = Base64::decodeCanonical($base64);
        if ($der === null) {
            throw new VerificationException(Reason::Malformed, 'receipt is not canonically padded standard base64');
        }
        if ($der === '') {
            throw new VerificationException(Reason::Malformed, 'receipt is empty');
        }

        // Everything up to a verified signature runs on input nobody has
        // vouched for yet: an unexpected error there is MALFORMED, never
        // INTERNAL_ERROR (hardening parity change #4) — the input nobody
        // vouched for must not be able to raise the internal-error alarm at
        // will.
        try {
            $content = $this->verifyReceiptSignature($der);
        } catch (VerificationException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new VerificationException(Reason::Malformed, 'unexpected ' . SafeText::quote($e::class), $e);
        }

        // A trusted signer signed these bytes, so anything that stops the
        // parse now is the library's failure or a format Apple added, not
        // the client's: UNREADABLE_PAYLOAD, never MALFORMED.
        try {
            return ReceiptPayloadDecoder::parse($content, Der::DEFAULT_NODE_BUDGET);
        } catch (Throwable $e) {
            throw new VerificationException(
                Reason::UnreadablePayload,
                'signed receipt content could not be read: unexpected ' . SafeText::quote($e::class),
                $e,
            );
        }
    }

    /**
     * Checks, in order: the CMS envelope, the chain to a pinned root walked
     * top-down together with certificate validity at the receipt's
     * creation date, then Apple's marker OIDs on the leaf and the
     * intermediate, and last the signature. Returns the encapsulated
     * content on the first SignerInfo/candidate pairing that verifies.
     *
     * @throws VerificationException
     */
    private function verifyReceiptSignature(string $der): string
    {
        $cms = Cms::parse($der, Der::DEFAULT_NODE_BUDGET);

        // Only the creation date is read before trust is established,
        // because it is the instant the chain's validity is judged at.
        $creationDateMs = ReceiptPayloadDecoder::readCreationDateMs($cms->content, Der::DEFAULT_NODE_BUDGET);
        $atMs = $creationDateMs ?? $this->clockMillis();

        // The embedded certificates are attacker-supplied and would each be
        // decoded and RSA-checked as a candidate issuer; an entry that will
        // not parse is held rather than thrown, because WHICH entry it is
        // changes the verdict (hardening parity change #5).
        $readable = [];
        $unreadable = [];
        foreach ($cms->certificates as $raw) {
            try {
                $readable[] = Certificate::parse($raw);
            } catch (ParseException) {
                $unreadable[] = $raw;
            }
        }

        $firstFailure = null;
        foreach ($cms->signerInfos as $signer) {
            // An unreadable entry naming THIS signer is a defect of a
            // certificate; any other unreadable entry (a stranger the
            // receipt merely carries) is a defect of the receipt itself,
            // and a broken signer outranks a broken stranger (hardening
            // parity change #5).
            $namesThisSigner = false;
            foreach ($unreadable as $raw) {
                if (Cms::namesSigner($raw, $signer)) {
                    $namesThisSigner = true;
                    break;
                }
            }
            if ($namesThisSigner) {
                $firstFailure ??= new VerificationException(
                    Reason::InvalidCertificate,
                    'receipt signer certificate is not a valid certificate',
                );
                continue;
            }
            if ($unreadable !== []) {
                $firstFailure ??= new VerificationException(Reason::Malformed, 'unparseable embedded certificate');
                continue;
            }

            $candidateIndices = Cms::findSignerIndices($signer, $readable);
            if ($candidateIndices === []) {
                $firstFailure ??= new VerificationException(Reason::Malformed, 'signer certificate not embedded');
                continue;
            }

            // More than one embedded certificate can carry this signer's
            // issuer and serial (a "twin", carrying its own key): each is
            // tried in bag order, a key is used only once ITS chain and
            // markers pass, one passing is enough, and otherwise the first
            // match's failure is what this signer reports.
            foreach ($candidateIndices as $index) {
                try {
                    return $this->attemptSigner($signer, $readable[$index], $readable, $cms, $atMs);
                } catch (VerificationException $e) {
                    $firstFailure ??= $e;
                }
            }
        }

        throw $firstFailure ?? new VerificationException(Reason::Malformed, 'no signer info');
    }

    /**
     * @param list<Certificate> $readable every embedded certificate that parsed
     *
     * @throws VerificationException
     */
    private function attemptSigner(
        CmsSignerInfo $signer,
        Certificate $candidate,
        array $readable,
        Cms $cms,
        int $atMs,
    ): string {
        $path = ChainValidator::buildPathTopDown($candidate, $readable, $this->roots);
        foreach ($path as $cert) {
            if (!$cert->isValidAt($atMs)) {
                throw new VerificationException(
                    Reason::InvalidCertificate,
                    'receipt certificate is not valid at the checked instant',
                );
            }
        }
        if (!$path[0]->hasExtension(AppleMarkers::LEAF_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'receipt signer certificate lacks Apple receipt-signing marker OID ' . AppleMarkers::LEAF_OID,
            );
        }
        if (!isset($path[1]) || !$path[1]->hasExtension(AppleMarkers::INTERMEDIATE_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'receipt intermediate certificate lacks Apple WWDR marker OID ' . AppleMarkers::INTERMEDIATE_OID,
            );
        }
        $this->verifyCmsSignature($cms, $signer, $candidate);

        return $cms->content;
    }

    /** @throws VerificationException */
    private function verifyCmsSignature(Cms $cms, CmsSignerInfo $signer, Certificate $candidate): void
    {
        $digestName = CmsSignature::resolveDigestName($signer->digestAlgorithmOid);
        if ($digestName === null) {
            throw new VerificationException(Reason::InvalidSignature, 'unsupported digest algorithm');
        }
        if ($signer->signedAttrs !== null) {
            $contentDigest = hash($digestName, $cms->content, true);
            $messageDigest = $cms->messageDigestAttribute($signer);
            if ($messageDigest === null || !hash_equals($contentDigest, $messageDigest)) {
                throw new VerificationException(
                    Reason::InvalidSignature,
                    'messageDigest attribute does not match content',
                );
            }
            $data = Cms::signedAttrsSignedBytes($signer);
        } else {
            $data = $cms->content;
        }
        CmsSignature::verify($data, $signer->signature, $candidate, $signer);
    }

    // --- verifySignedData -----------------------------------------------

    /** @throws VerificationException */
    private function verifySignedDataInner(?string $jws): JsonPayload
    {
        if ($jws === null || $jws === '') {
            throw new VerificationException(Reason::Malformed, 'jws is empty');
        }
        if (strlen($jws) > self::MAX_JWS_BYTES) {
            throw new VerificationException(
                Reason::TooLarge,
                'jws exceeds the maximum accepted size of ' . self::MAX_JWS_BYTES . ' bytes',
            );
        }
        try {
            return $this->verifySignedDataUnguarded($jws);
        } catch (VerificationException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new VerificationException(Reason::Malformed, 'unexpected ' . SafeText::quote($e::class), $e);
        }
    }

    /**
     * Checks, in order: the compact JWS structure, `alg` equal to `ES256`,
     * the `x5c` chain to a pinned root walked top-down together with
     * certificate validity at the payload's `signedDate`, then Apple's
     * marker OIDs on the leaf and the intermediate, and last the signature.
     *
     * @throws VerificationException
     */
    private function verifySignedDataUnguarded(string $jws): JsonPayload
    {
        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            throw new VerificationException(
                Reason::Malformed,
                'expected 3 dot-separated segments, got ' . count($parts),
            );
        }
        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $headerBytes = Base64::decodeStrict($headerB64);
        if ($headerBytes === null) {
            throw new VerificationException(Reason::Malformed, 'header is not valid base64url');
        }
        $payloadBytes = Base64::decodeStrict($payloadB64);
        if ($payloadBytes === null) {
            throw new VerificationException(Reason::Malformed, 'payload is not valid base64url');
        }
        $signatureBytes = Base64::decodeStrict($signatureB64);
        if ($signatureBytes === null) {
            throw new VerificationException(Reason::Malformed, 'signature is not valid base64url');
        }

        [$alg, $x5c] = JwsPayloadReader::readHeader($headerBytes);
        if ($alg !== 'ES256') {
            throw new VerificationException(Reason::Malformed, 'alg must be ES256, got ' . SafeText::quote($alg));
        }
        if ($x5c === null || count($x5c) !== 3) {
            throw new VerificationException(Reason::Malformed, 'x5c must contain exactly 3 certificates');
        }

        // Structural decode only: no certificate's public key is read here.
        // x5c[2] is decoded and then dropped — never compared to an
        // anchor, never trusted — but an entry that is not a certificate
        // is INVALID_CERTIFICATE at every index.
        $certs = [];
        foreach ($x5c as $index => $entry) {
            $certDer = Base64::decodeCanonical($entry);
            if ($certDer === null) {
                throw new VerificationException(Reason::InvalidCertificate, "x5c[{$index}] is not a valid certificate");
            }
            try {
                $certs[] = Certificate::parse($certDer);
            } catch (ParseException $e) {
                throw new VerificationException(
                    Reason::InvalidCertificate,
                    "x5c[{$index}] is not a valid certificate",
                    $e,
                );
            }
        }
        [$leaf, $intermediate] = $certs;

        [$payloadJson, $signedDateMs, ] = JwsPayloadReader::readPayload($payloadBytes);

        ChainValidator::authenticatePairTopDown($leaf, $intermediate, $this->roots);

        $atMs = $signedDateMs ?? $this->clockMillis();
        if (!$leaf->isValidAt($atMs)) {
            throw new VerificationException(Reason::InvalidCertificate, 'leaf certificate is not valid at the checked instant');
        }
        if (!$intermediate->isValidAt($atMs)) {
            throw new VerificationException(Reason::InvalidCertificate, 'intermediate certificate is not valid at the checked instant');
        }
        if (!$leaf->hasExtension(AppleMarkers::LEAF_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'leaf certificate lacks Apple marker OID ' . AppleMarkers::LEAF_OID,
            );
        }
        if (!$intermediate->hasExtension(AppleMarkers::INTERMEDIATE_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'intermediate certificate lacks Apple marker OID ' . AppleMarkers::INTERMEDIATE_OID,
            );
        }

        $this->verifyEs256($leaf, $headerB64 . '.' . $payloadB64, $signatureBytes);

        if ($payloadJson === null) {
            throw new VerificationException(Reason::UnreadablePayload, 'signed payload is not a JSON object');
        }

        return new JsonPayload($payloadJson);
    }

    /** @throws VerificationException */
    private function verifyEs256(Certificate $leaf, string $signingInput, string $signature): void
    {
        if (strlen($signature) !== 64) {
            throw new VerificationException(
                Reason::InvalidSignature,
                'ES256 signature must be 64 bytes, got ' . strlen($signature),
            );
        }
        // Safe to decode now: leaf is used only here, after the chain,
        // validity and marker checks above have all passed.
        $key = $leaf->publicKey();
        if ($key === null) {
            throw new VerificationException(Reason::InvalidCertificate, 'leaf certificate key does not decode');
        }
        if ($leaf->publicKeyType() !== OPENSSL_KEYTYPE_EC) {
            throw new VerificationException(Reason::InvalidSignature, 'leaf key is not EC');
        }
        $result = openssl_verify($signingInput, self::p1363ToDer($signature), $key, OPENSSL_ALGO_SHA256);
        Certificate::drainOpenSslErrors();
        if ($result !== 1) {
            throw new VerificationException(Reason::InvalidSignature, 'ES256 signature check failed');
        }
    }

    /**
     * JWS ships an ES256 signature as raw `r ‖ s` (RFC 7515); OpenSSL wants
     * the ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
     */
    private static function p1363ToDer(string $signature): string
    {
        $encode = static function (string $half): string {
            $half = ltrim($half, "\x00");
            if ($half === '') {
                $half = "\x00";
            }
            if ((ord($half[0]) & 0x80) !== 0) {
                $half = "\x00" . $half;
            }

            return "\x02" . chr(strlen($half)) . $half;
        };
        $body = $encode(substr($signature, 0, 32)) . $encode(substr($signature, 32, 32));

        return "\x30" . chr(strlen($body)) . $body;
    }

    // --- verifyReceiptEndpoint --------------------------------------------

    /** @throws VerificationException */
    private function extractReceiptData(?string $requestJson): string
    {
        if ($requestJson === null) {
            throw new VerificationException(Reason::Malformed, 'request body is empty');
        }
        if (strlen($requestJson) > self::MAX_REQUEST_BYTES) {
            throw new VerificationException(
                Reason::TooLarge,
                'request body exceeds the maximum of ' . self::MAX_REQUEST_BYTES . ' bytes',
            );
        }
        if (BoundedJson::exceedsBounds($requestJson)) {
            throw new VerificationException(Reason::Malformed, 'request body is nested too deeply');
        }
        try {
            $parsed = json_decode($requestJson, true, 65, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new VerificationException(Reason::Malformed, 'request body is not valid JSON', $e);
        }
        if (!is_array($parsed) || ($parsed !== [] && array_is_list($parsed))) {
            throw new VerificationException(Reason::Malformed, 'request body is not a JSON object');
        }
        // password and exclude-old-transactions are accepted for wire
        // compatibility and never read.
        $receiptData = $parsed['receipt-data'] ?? null;
        if (!is_string($receiptData) || $receiptData === '') {
            throw new VerificationException(Reason::Malformed, 'receipt-data is missing or not a string');
        }

        return $receiptData;
    }

    private static function statusForReason(Reason $reason): int
    {
        return match ($reason) {
            Reason::Malformed, Reason::TooLarge => AppleStatus::MalformedReceiptData,
            Reason::InvalidSignature, Reason::UntrustedChain,
            Reason::InvalidCertificate, Reason::InvalidCertificatePurpose => AppleStatus::NotAuthenticated,
            Reason::UnreadablePayload, Reason::InternalError => AppleStatus::InternalDataAccessError,
        };
    }

    /**
     * A receipt whose `receipt_type` is missing or unknown counts as
     * non-production, as in 0.6: 21007 on Production, status 0 on Sandbox.
     */
    private static function statusForEnvironment(Environment $environment, ReceiptPayload $receipt): int
    {
        $isProduction = Environment::fromReceiptType($receipt->receiptType) === Environment::Production;
        if ($environment === Environment::Production && !$isProduction) {
            return AppleStatus::SandboxReceiptOnProduction;
        }
        if ($environment === Environment::Sandbox && $isProduction) {
            return AppleStatus::ProductionReceiptOnSandbox;
        }

        return AppleStatus::Ok;
    }

    private static function renderStatus(int $status): string
    {
        return json_encode(['status' => $status], JSON_THROW_ON_ERROR);
    }

    private static function renderOk(Environment $environment, ReceiptPayload $receipt, int $requestDateMs): string
    {
        $body = [
            'status' => AppleStatus::Ok,
            'environment' => $environment->value,
            'receipt' => self::receiptJson($receipt, $requestDateMs),
        ];
        try {
            return json_encode($body, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            // What the endpoint has always answered when the rendering
            // itself fails, for example a timezone database without
            // America/Los_Angeles.
            return self::renderStatus(AppleStatus::InternalDataAccessError);
        }
    }

    /** @return array<string, mixed> */
    private static function receiptJson(ReceiptPayload $r, int $requestDateMs): array
    {
        $out = [];
        self::put($out, 'receipt_type', $r->receiptType);
        // Apple echoes attribute 1 under both names — its response
        // reference defines adam_id as "See app_item_id" — and as JSON
        // numbers, not as the strings the in-app integers are rendered with.
        self::put($out, 'adam_id', $r->appItemId);
        self::put($out, 'app_item_id', $r->appItemId);
        self::put($out, 'bundle_id', $r->bundleId);
        self::put($out, 'application_version', $r->applicationVersion);
        self::put($out, 'download_id', $r->downloadId);
        self::put($out, 'version_external_identifier', $r->versionExternalIdentifier);
        self::put($out, 'original_application_version', $r->originalApplicationVersion);
        self::putAppleDates($out, 'receipt_creation_date', $r->receiptCreationDateMs);
        self::putAppleDates($out, 'request_date', $requestDateMs);
        self::putAppleDates($out, 'original_purchase_date', $r->originalPurchaseDateMs);
        self::putAppleDates($out, 'expiration_date', $r->expirationDateMs);
        $out['in_app'] = array_map(self::inAppJson(...), $r->inApp);

        return $out;
    }

    /** @return array<string, mixed> */
    private static function inAppJson(InAppPurchase $p): array
    {
        $entry = [];
        self::put($entry, 'quantity', $p->quantity === null ? null : (string) $p->quantity);
        self::put($entry, 'product_id', $p->productId);
        self::put($entry, 'transaction_id', $p->transactionId);
        self::put($entry, 'original_transaction_id', $p->originalTransactionId);
        self::putAppleDates($entry, 'purchase_date', $p->purchaseDateMs);
        self::putAppleDates($entry, 'original_purchase_date', $p->originalPurchaseDateMs);
        self::putAppleDates($entry, 'expires_date', $p->expiresDateMs);
        self::putAppleDates($entry, 'cancellation_date', $p->cancellationDateMs);
        // Apple omits the key when attribute 1711 is 0, as it does for consumables.
        if (!empty($p->webOrderLineItemId)) {
            $entry['web_order_line_item_id'] = (string) $p->webOrderLineItemId;
        }
        if ($p->isTrialPeriod !== null) {
            $entry['is_trial_period'] = $p->isTrialPeriod ? 'true' : 'false';
        }
        if ($p->isInIntroOfferPeriod !== null) {
            $entry['is_in_intro_offer_period'] = $p->isInIntroOfferPeriod ? 'true' : 'false';
        }

        return $entry;
    }

    /** @param array<string, mixed> $target */
    private static function put(array &$target, string $key, mixed $value): void
    {
        if ($value !== null) {
            $target[$key] = $value;
        }
    }

    /**
     * Apple's three date renderings: `x` (GMT), `x_ms` (epoch millis as a
     * string), `x_pst` (US Pacific, which is what Apple's endpoint emits).
     *
     * @param array<string, mixed> $target
     */
    private static function putAppleDates(array &$target, string $prefix, ?int $epochMs): void
    {
        if ($epochMs === null) {
            return;
        }
        $utc = (new DateTimeImmutable('@' . intdiv($epochMs, 1000)))->setTimezone(new DateTimeZone('UTC'));
        $target[$prefix] = $utc->format('Y-m-d H:i:s') . ' Etc/GMT';
        $target[$prefix . '_ms'] = (string) $epochMs;
        $pacific = $utc->setTimezone(new DateTimeZone('America/Los_Angeles'));
        $target[$prefix . '_pst'] = $pacific->format('Y-m-d H:i:s') . ' America/Los_Angeles';
    }
}
