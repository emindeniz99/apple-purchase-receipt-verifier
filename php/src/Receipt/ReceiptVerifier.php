<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Base64;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ChainValidator;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Cms;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use Throwable;

/**
 * Verifies legacy PKCS#7 app receipts completely offline against pinned Apple
 * roots — the server-side port of Apple's "Validating receipts on the device"
 * procedure (PLAN.md §2.2).
 *
 * This class takes **no clock**. Its only notion of "now" is the fallback
 * instant a receipt without a creation date has its certificate chain judged
 * at, and that reads the system clock directly and deliberately: a caller
 * injecting a clock — to test staleness, or to work around skew — must not
 * thereby be able to accept an expired chain, or to expire a live one.
 *
 * ```php
 * $verifier = new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.example.app');
 * $receipt  = $verifier->verify($base64FromTheClient);
 * ```
 */
final class ReceiptVerifier
{
    /**
     * Apple marker OID on the receipt-signing leaf. Without this purpose
     * check, ANY certificate chaining to the same pinned root — including any
     * Apple developer's own distribution leaf, which goes through the same
     * WWDR intermediate — could sign a fully forged receipt. Checked AFTER
     * chain validation so a foreign chain still reports INVALID_CHAIN first
     * (PLAN.md D13).
     */
    private const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';

    /**
     * Genuine receipts embed a leaf, an intermediate and (for the legacy
     * SHA-1 chain) a root: the public fixtures carry 1, 3 and 3. Ten leaves
     * room for a longer Apple chain while bounding what rejecting a receipt
     * costs. The bound is enforced BEFORE any embedded certificate is decoded
     * or RSA-checked, because decoding is the expensive half: the Node port
     * measured a 722 KB receipt carrying 1,057 certificates at 26–45× the
     * cost of verifying the genuine 79 KB legacy receipt.
     */
    public const MAX_EMBEDDED_CERTIFICATES = 10;

    /** Apple receipts are tens of KB; the largest public fixture is 79 KB. */
    public const DEFAULT_MAX_RECEIPT_BYTES = 2097152;

    /** @var list<string> */
    private readonly array $trustedRoots;

    /**
     * @param array<string> $trustedRoots DER bytes or PEM text of the pinned
     *        anchors. In production: {@see \EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts::receiptRoots()}.
     *        Never the operating system's trust store — this library has no
     *        code path to it. Keys are ignored: the anchors are reindexed
     *        into a list, so a caller may pass any string-keyed array.
     * @param string $bundleId the bundle id the receipt must carry
     * @param int $maxReceiptBytes input larger than this is rejected before
     *        parsing; raise it only for a genuinely unusual corpus
     * @param int $nodeBudget ceiling on ASN.1 nodes one receipt may decode to
     *
     * @throws InvalidArgumentException on misconfiguration — which is a
     *         programming error, never a verdict about a payload
     */
    public function __construct(
        array $trustedRoots,
        private readonly string $bundleId,
        private readonly int $maxReceiptBytes = self::DEFAULT_MAX_RECEIPT_BYTES,
        private readonly int $nodeBudget = Der::DEFAULT_NODE_BUDGET,
    ) {
        self::requireSixtyFourBit();
        ChainValidator::normalizeRoots($trustedRoots); // validate eagerly
        if ($bundleId === '') {
            throw new InvalidArgumentException('bundleId is required');
        }
        if ($maxReceiptBytes < 1) {
            throw new InvalidArgumentException('maxReceiptBytes must be positive');
        }
        if ($nodeBudget < 1) {
            throw new InvalidArgumentException('nodeBudget must be positive');
        }
        $this->trustedRoots = array_values($trustedRoots);
    }

    /**
     * Verifies a receipt and enforces the configured bundle id.
     *
     * @param string $receipt the DER bytes, or their base64 — the form a
     *        client normally transports. A value starting with the DER
     *        SEQUENCE tag (0x30) is taken as DER; anything else is base64
     *        decoded first.
     * @param string|null $deviceGuid RAW GUID bytes (not hex, not base64).
     *        Non-null additionally enforces the device binding
     *        `SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) == attribute 5`
     *        (optional — PLAN.md D4). Passing a hex string here is the most
     *        likely misuse and produces a plain DEVICE_HASH_MISMATCH:
     *        use `hex2bin($guidHex)`.
     *
     * @throws VerificationException
     */
    public function verify(string $receipt, ?string $deviceGuid = null): AppReceipt
    {
        $fields = self::verifyReceiptCore(
            $receipt,
            $this->trustedRoots,
            $this->maxReceiptBytes,
            $this->nodeBudget,
        );
        if ($fields->bundleId !== $this->bundleId) {
            throw new VerificationException(
                Reason::WrongBundleId,
                'receipt bundle id is not the configured one',
            );
        }
        if ($deviceGuid !== null) {
            self::verifyDeviceHash($fields, $deviceGuid);
        }

        return $fields;
    }

    /**
     * Chain and signature verification WITHOUT the bundle-id claim check —
     * the primitive under both {@see verify()} and
     * {@see VerifyReceiptEndpoint}, which (like Apple's endpoint) accepts any
     * bundle.
     *
     * **You must check `$receipt->bundleId` yourself.** A caller that unlocks
     * products from the result of this method and skips that comparison will
     * honour any app's genuine receipt. Use {@see verify()} unless you have a
     * reason not to.
     *
     * @param list<string> $trustedRoots DER bytes or PEM text of the pinned anchors
     *
     * @throws InvalidArgumentException when `$trustedRoots` is empty or unparseable
     * @throws VerificationException
     */
    public static function verifyReceiptCore(
        string $receipt,
        array $trustedRoots,
        int $maxReceiptBytes = self::DEFAULT_MAX_RECEIPT_BYTES,
        int $nodeBudget = Der::DEFAULT_NODE_BUDGET,
    ): AppReceipt {
        self::requireSixtyFourBit();
        $anchors = ChainValidator::normalizeRoots($trustedRoots);

        // Everything below walks attacker-supplied DER through our parser and
        // through OpenSSL. Callers discriminate on VerificationException;
        // nothing else may escape, including a TypeError from an unexpected
        // node shape or an Error from a core function. A programming error
        // deep in a parser is indistinguishable, from here, from a hostile
        // input that found one — and must not reach the caller as a 500.
        try {
            return self::verifyDecoded(self::toDer($receipt, $maxReceiptBytes), $anchors, $nodeBudget);
        } catch (VerificationException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'malformed receipt', $e);
        }
    }

    /**
     * @param list<Certificate> $anchors
     *
     * @throws VerificationException
     */
    private static function verifyDecoded(string $der, array $anchors, int $nodeBudget): AppReceipt
    {
        $cms = Cms::parse($der, $nodeBudget);

        // Parsed before the signature is checked only to learn the creation
        // date, which is the instant the chain's validity is judged at.
        // NOTHING from it is trusted, returned or acted on until the chain
        // and signature checks below have passed.
        $fields = ReceiptPayload::parse($cms->content, $nodeBudget);
        $at = $fields->creationDate === null
            // A receipt with no creation date falls back to the SYSTEM clock,
            // never to an injected one. This is the whole reason this class
            // takes no clock parameter.
            ? (int) (microtime(true) * 1000)
            : $fields->creationDate->getTimestamp() * 1000;

        // The embedded certificates are attacker-supplied and would each be
        // decoded and RSA-checked as a candidate issuer, so a receipt
        // carrying more than a chain can hold is rejected here — before a
        // single one is parsed.
        if (count($cms->certificates) > self::MAX_EMBEDDED_CERTIFICATES) {
            throw new VerificationException(
                Reason::InvalidChain,
                'receipt embeds more than ' . self::MAX_EMBEDDED_CERTIFICATES . ' certificates',
            );
        }
        // An entry that will not parse is held rather than thrown, because
        // WHICH entry it is changes the verdict: a stranger the receipt
        // merely carries is a defect of the receipt, while the SIGNER being
        // unreadable is a defect of a certificate and gets the verdict an
        // unreadable x5c entry gets on the JWS path (receipt/reject-signer-*).
        // Naming the signer needs the readable entries matched against the
        // SignerInfo first.
        $embedded = [];
        $unreadable = null;
        foreach ($cms->certificates as $raw) {
            try {
                $embedded[] = Certificate::parse($raw);
            } catch (ParseException $e) {
                $unreadable ??= $e;
            }
        }
        $signerIndex = $cms->findSignerIndex($embedded);
        if ($signerIndex < 0) {
            if ($unreadable !== null) {
                throw new VerificationException(
                    Reason::InvalidCertificate,
                    "the receipt's signer certificate is not among the embedded certificates that could be read",
                    $unreadable,
                );
            }

            throw new VerificationException(Reason::InvalidReceiptFormat, 'signer certificate not embedded');
        }
        if ($unreadable !== null) {
            throw new VerificationException(
                Reason::InvalidReceiptFormat,
                'unparseable embedded certificate',
                $unreadable,
            );
        }
        $signer = $embedded[$signerIndex];
        // A SubjectPublicKeyInfo OpenSSL refuses — a namedCurve it does not
        // implement is enough — is a defect of the certificate, not of the
        // signature it carries: there is no key to check that signature with.
        // Left to verifyCmsSignature it reads as INVALID_SIGNATURE, which is
        // the answer a READABLE key of the wrong kind deserves. The JWS path
        // draws the same line for an x5c entry.
        if ($signer->publicKey() === null) {
            throw new VerificationException(
                Reason::InvalidCertificate,
                'receipt signer certificate has an unreadable public key',
            );
        }

        ChainValidator::buildAndValidatePath($signer, $embedded, $anchors, $at);

        if (!$signer->hasExtension(self::RECEIPT_SIGNER_OID)) {
            throw new VerificationException(
                Reason::InvalidCertificatePurpose,
                'receipt signer certificate lacks Apple receipt-signing marker OID ' . self::RECEIPT_SIGNER_OID,
            );
        }

        self::verifyCmsSignature($cms, $signer);

        return $fields;
    }

    /** @throws VerificationException */
    private static function verifyCmsSignature(Cms $cms, Certificate $signer): void
    {
        if ($signer->publicKeyType() !== OPENSSL_KEYTYPE_RSA) {
            throw new VerificationException(Reason::InvalidSignature, 'receipt signer key is not RSA');
        }
        $key = $signer->publicKey();
        if ($key === null) {
            throw new VerificationException(Reason::InvalidSignature, 'receipt signer public key is unreadable');
        }

        if ($cms->signedAttrs !== null) {
            $contentDigest = hash($cms->digest, $cms->content, true);
            $messageDigest = $cms->messageDigestAttribute();
            if ($messageDigest === null || !hash_equals($contentDigest, $messageDigest)) {
                throw new VerificationException(
                    Reason::InvalidSignature,
                    'messageDigest attribute does not match content',
                );
            }
            $signedBytes = $cms->signedAttrsSignedBytes();
        } else {
            $signedBytes = $cms->content;
        }

        // openssl_verify() answers 1 valid, 0 invalid and -1 on error, and -1
        // is truthy in PHP. `=== 1` is the only acceptable comparison here.
        $result = openssl_verify($signedBytes, $cms->signature, $key, self::opensslAlgorithm($cms->digest));
        Certificate::drainOpenSslErrors();
        if ($result !== 1) {
            throw new VerificationException(Reason::InvalidSignature, 'CMS signature check failed');
        }
    }

    /** @param 'sha1'|'sha256' $digest the digest {@see Cms} accepted */
    private static function opensslAlgorithm(string $digest): int
    {
        return match ($digest) {
            'sha1' => OPENSSL_ALGO_SHA1,
            'sha256' => OPENSSL_ALGO_SHA256,
        };
    }

    /** @throws VerificationException */
    private static function verifyDeviceHash(AppReceipt $fields, string $deviceGuid): void
    {
        if ($fields->opaqueValue === null || $fields->sha1Hash === null || $fields->bundleIdBytes === null) {
            throw new VerificationException(
                Reason::DeviceHashMismatch,
                'receipt lacks the attributes needed for the device-hash check',
            );
        }
        $computed = sha1($deviceGuid . $fields->opaqueValue . $fields->bundleIdBytes, true);
        if (!hash_equals($computed, $fields->sha1Hash)) {
            throw new VerificationException(
                Reason::DeviceHashMismatch,
                'computed device hash does not match attribute 5',
            );
        }
    }

    /** @throws VerificationException */
    private static function toDer(string $receipt, int $maxReceiptBytes): string
    {
        if ($receipt === '') {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'receipt is empty');
        }
        // Checked before the transport form is decided so an oversized base64
        // blob is rejected without allocating its decoding.
        if (strlen($receipt) > $maxReceiptBytes) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'receipt exceeds the configured size limit');
        }
        $der = $receipt[0] === "\x30" ? $receipt : Base64::decodeReceipt($receipt);
        if ($der === null) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'receipt is not valid base64');
        }
        if ($der === '') {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'receipt is empty');
        }
        if (strlen($der) > $maxReceiptBytes) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'receipt exceeds the configured size limit');
        }

        return $der;
    }

    /**
     * `signedDate` and friends arrive as epoch MILLISECONDS (~1.7×10^12),
     * which exceeds `PHP_INT_MAX` on a 32-bit build: `json_decode` would hand
     * back floats and every date comparison would silently drift. Refuse the
     * platform instead of drifting.
     */
    public static function requireSixtyFourBit(): void
    {
        if (PHP_INT_SIZE < 8) {
            throw new \RuntimeException(
                'apple-purchase-receipt-verifier requires a 64-bit PHP build: '
                . 'Apple ships epoch-millisecond timestamps that a 32-bit int cannot hold',
            );
        }
    }
}
