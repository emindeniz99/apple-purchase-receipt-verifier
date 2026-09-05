<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use OpenSSLAsymmetricKey;

/**
 * X.509 field extraction on top of {@see Der}.
 *
 * Everything the chain walk and the marker-OID checks need is read here
 * rather than from `openssl_x509_parse()`, for three reasons that are all
 * security-relevant:
 *
 * 1. **Marker OIDs.** `openssl_x509_parse()` keys extensions by whatever
 *    `OBJ_obj2txt()` produced, so if a future OpenSSL learns a short name for
 *    an Apple OID the key silently changes and the presence check starts
 *    failing on genuine certificates. This class compares encoded OID bytes,
 *    which cannot drift.
 * 2. **Validity at an arbitrary instant, with a well-defined "never valid".**
 *    RFC 5280 `UTCTime` (2-digit year, 1950–2049 pivot) and `GeneralizedTime`
 *    are decoded here. Contents matching neither shape yield
 *    `notBefore = PHP_INT_MAX`, `notAfter = PHP_INT_MIN`: valid at no
 *    instant, which is the fail-closed spelling of the Node port's `NaN`.
 * 3. **RFC 5280 §4.1.1.2 algorithm agreement.** `tbsCertificate.signature`
 *    must byte-equal the outer `signatureAlgorithm`; otherwise the algorithm
 *    the signature is checked under comes from a field the signature does not
 *    cover.
 *
 * The signature *check* on a chain link is delegated to OpenSSL
 * (`openssl_x509_verify`), which reads the algorithm from the certificate
 * itself — so RSA-PSS, SHA-512 and anything Apple adopts later work without a
 * hand-written OID-to-algorithm table for us to get wrong.
 *
 * @internal
 */
final class Certificate
{
    /** keyUsage bit 5 (RFC 5280 §4.2.1.3) — the bit `X509_check_ca` insists on. */
    private const KEY_CERT_SIGN_BIT = 5;

    private const OID_BASIC_CONSTRAINTS = '2.5.29.19';
    private const OID_KEY_USAGE = '2.5.29.15';

    /** Times in epoch MILLISECONDS, matching the instant every caller passes around. */
    public const NEVER_VALID_FROM = PHP_INT_MAX;
    public const NEVER_VALID_TO = PHP_INT_MIN;

    /**
     * @param list<bool>|null $keyUsage
     * @param array<string, bool> $extensionOids encoded-OID-bytes => present
     */
    private function __construct(
        public readonly string $der,
        public readonly string $tbsBytes,
        public readonly string $serialNumber,
        public readonly string $issuerDer,
        public readonly string $subjectDer,
        public readonly int $notBefore,
        public readonly int $notAfter,
        public readonly string $spki,
        public readonly string $publicKeyAlgorithmOid,
        public readonly ?string $publicKeyCurveOid,
        public readonly string $signatureAlgorithmOid,
        public readonly string $signatureValue,
        public readonly bool $isCa,
        public readonly ?array $keyUsage,
        private readonly array $extensionOids,
    ) {
    }

    /** @throws ParseException */
    public static function parse(string $der): self
    {
        $cert = Der::parse($der);
        $top = $cert->children();
        if ($cert->tag !== Der::TAG_SEQUENCE || count($top) < 3) {
            throw new ParseException('not an X.509 certificate');
        }
        $tbs = $top[0];
        if ($tbs->tag !== Der::TAG_SEQUENCE) {
            throw new ParseException('unexpected TBSCertificate layout');
        }
        $fields = $tbs->children();
        $index = 0;
        if (($fields[0] ?? null)?->tag === Der::TAG_CONTEXT_0) {
            // version [0] EXPLICIT INTEGER. RFC 5280 defines 0, 1 and 2 (v1,
            // v2, v3) and nothing else, and nothing downstream reads the
            // field — which is why it is checked here rather than skipped: a
            // certificate claiming version 11 would otherwise parse like any
            // other and verify on its signature and extensions alone.
            $version = $fields[0]->child(0);
            if ($version?->tag !== Der::TAG_INTEGER || strlen($version->contents) !== 1
                || ord($version->contents) > 2) {
                throw new ParseException('unknown X.509 certificate version');
            }
            $index = 1;
        }
        $serial = $fields[$index] ?? null;
        $innerSignature = $fields[$index + 1] ?? null;
        $issuer = $fields[$index + 2] ?? null;
        $validity = $fields[$index + 3] ?? null;
        $subject = $fields[$index + 4] ?? null;
        $spki = $fields[$index + 5] ?? null;
        if ($serial?->tag !== Der::TAG_INTEGER || $issuer?->tag !== Der::TAG_SEQUENCE
            || $validity?->tag !== Der::TAG_SEQUENCE || $subject?->tag !== Der::TAG_SEQUENCE
            || $spki?->tag !== Der::TAG_SEQUENCE) {
            throw new ParseException('unexpected TBSCertificate layout');
        }
        $validityFields = $validity->children();
        if (count($validityFields) < 2) {
            throw new ParseException('unexpected Validity layout');
        }
        $spkiAlgorithm = $spki->child(0);
        if ($spkiAlgorithm?->tag !== Der::TAG_SEQUENCE
            || $spkiAlgorithm->child(0)?->tag !== Der::TAG_OID) {
            throw new ParseException('unexpected SubjectPublicKeyInfo layout');
        }
        $curveNode = $spkiAlgorithm->child(1);
        $curveOid = $curveNode?->tag === Der::TAG_OID ? Der::decodeOid($curveNode->contents) : null;

        $outerAlgorithm = $top[1]->child(0);
        if ($top[1]->tag !== Der::TAG_SEQUENCE || $outerAlgorithm?->tag !== Der::TAG_OID) {
            throw new ParseException('unexpected signatureAlgorithm layout');
        }
        $innerAlgorithm = $innerSignature?->child(0);
        if ($innerSignature?->tag !== Der::TAG_SEQUENCE || $innerAlgorithm?->tag !== Der::TAG_OID
            || !hash_equals($outerAlgorithm->contents, $innerAlgorithm->contents)) {
            throw new ParseException('signatureAlgorithm disagrees with tbsCertificate.signature');
        }
        if ($top[2]->tag !== Der::TAG_BIT_STRING || strlen($top[2]->contents) < 2) {
            throw new ParseException('unexpected signatureValue layout');
        }

        $extensions = null;
        foreach ($fields as $field) {
            if ($field->tag === Der::TAG_CONTEXT_3) {
                $extensions = $field->child(0);
            }
        }
        /** @var array<string, string> $byOid decoded-OID => extension value bytes */
        $byOid = [];
        /** @var array<string, bool> $extensionOids raw encoded OID contents => present */
        $extensionOids = [];
        foreach ($extensions === null ? [] : $extensions->children() as $extension) {
            $parts = $extension->children();
            $oidNode = $parts[0] ?? null;
            $valueNode = $parts === [] ? null : $parts[count($parts) - 1];
            if ($oidNode?->tag !== Der::TAG_OID || $valueNode === null || !Der::isOctetString($valueNode)) {
                throw new ParseException('malformed certificate extension');
            }
            $extensionOids[$oidNode->contents] = true;
            $oid = Der::decodeOid($oidNode->contents);
            // RFC 5280 4.2: a certificate MUST NOT include more than one
            // instance of a particular extension. Keeping the first copy and
            // ignoring the rest is what this used to do, and it makes the
            // parser pick which copy the certificate means — a choice another
            // implementation can make differently, so "is this a CA", "what
            // may it be used for" and "does it carry the marker OID" stop
            // being questions about one certificate.
            if (isset($byOid[$oid])) {
                throw new ParseException('duplicate X.509 extension');
            }
            $byOid[$oid] = Der::octets($valueNode);
        }

        $keyUsage = isset($byOid[self::OID_KEY_USAGE])
            ? self::bitStringBits(Der::parse($byOid[self::OID_KEY_USAGE])->contents)
            : null;

        // X509_check_ca() === 1: basicConstraints present with cA TRUE, and a
        // keyUsage extension (if any) that permits keyCertSign.
        $basicConstraintsCa = false;
        if (isset($byOid[self::OID_BASIC_CONSTRAINTS])) {
            $first = Der::parse($byOid[self::OID_BASIC_CONSTRAINTS])->child(0);
            $basicConstraintsCa = $first?->tag === Der::TAG_BOOLEAN
                && $first->contents !== '' && $first->contents[0] !== "\x00";
        }
        $certSignAllowed = $keyUsage === null || ($keyUsage[self::KEY_CERT_SIGN_BIT] ?? false) === true;

        return new self(
            der: $der,
            tbsBytes: $tbs->raw,
            serialNumber: $serial->contents,
            issuerDer: $issuer->raw,
            subjectDer: $subject->raw,
            notBefore: self::decodeTime($validityFields[0], self::NEVER_VALID_FROM),
            notAfter: self::decodeTime($validityFields[1], self::NEVER_VALID_TO),
            spki: $spki->raw,
            publicKeyAlgorithmOid: Der::decodeOid($spkiAlgorithm->child(0)->contents),
            publicKeyCurveOid: $curveOid,
            signatureAlgorithmOid: Der::decodeOid($outerAlgorithm->contents),
            signatureValue: substr($top[2]->contents, 1),
            isCa: $basicConstraintsCa && $certSignAllowed,
            keyUsage: $keyUsage,
            extensionOids: $extensionOids,
        );
    }

    /** Whether the certificate carries an extension with the given dotted OID. */
    public function hasExtension(string $oid): bool
    {
        return isset($this->extensionOids[Der::encodeOidContents($oid)]);
    }

    public function isValidAt(int $atEpochMillis): bool
    {
        return $this->notBefore <= $atEpochMillis && $atEpochMillis <= $this->notAfter;
    }

    /** PEM armour, for the OpenSSL entry points that only speak PEM. */
    public function pem(): string
    {
        return self::derToPem($this->der, 'CERTIFICATE');
    }

    /**
     * The subject public key as an OpenSSL key handle, or null when OpenSSL
     * refuses the SubjectPublicKeyInfo.
     */
    public function publicKey(): ?OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public(self::derToPem($this->spki, 'PUBLIC KEY'));
        if ($key === false) {
            self::drainOpenSslErrors();

            return null;
        }

        return $key;
    }

    /**
     * OPENSSL_KEYTYPE_* of the subject public key, or null when unreadable.
     *
     * `openssl_pkey_get_details()` is documented to carry an int `type`, but
     * its return is an untyped array: a build that omits the key, or answers
     * something other than an int, reads as unreadable rather than being
     * handed on as an OPENSSL_KEYTYPE_* a caller would compare against.
     */
    public function publicKeyType(): ?int
    {
        $key = $this->publicKey();
        if ($key === null) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            self::drainOpenSslErrors();

            return null;
        }
        $type = $details['type'] ?? null;

        return is_int($type) ? $type : null;
    }

    /**
     * Whether this certificate's signature verifies under `$issuer`'s public
     * key AND its issuer name byte-equals the issuer's subject name.
     *
     * `openssl_x509_verify()` answers 1 valid, 0 invalid and **-1 on error**,
     * and -1 is truthy in PHP. The comparison is `=== 1` and nothing else; a
     * native test pins that a garbage certificate really does produce -1, so
     * a refactor to `if (openssl_x509_verify(...))` fails loudly.
     */
    public function isIssuedBy(self $issuer): bool
    {
        if (!hash_equals($issuer->subjectDer, $this->issuerDer)) {
            return false;
        }
        $issuerKey = $issuer->publicKey();
        if ($issuerKey === null) {
            return false;
        }
        $result = openssl_x509_verify($this->pem(), $issuerKey);
        self::drainOpenSslErrors();

        return $result === 1;
    }

    public static function derToPem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$label}-----\n";
    }

    /**
     * Empties the OpenSSL error queue.
     *
     * Without this, a caller's later unrelated `openssl_*` call inherits the
     * error strings our failed probes left behind — a real cross-library bug,
     * and one a library that verifies hostile input triggers constantly.
     */
    public static function drainOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }

    /** @return list<bool> */
    private static function bitStringBits(string $contents): array
    {
        if ($contents === '') {
            throw new ParseException('empty BIT STRING');
        }
        $unused = ord($contents[0]);
        if ($unused > 7) {
            throw new ParseException('invalid BIT STRING unused-bit count');
        }
        $bits = [];
        $length = strlen($contents);
        for ($i = 1; $i < $length; ++$i) {
            $byte = ord($contents[$i]);
            $count = $i === $length - 1 ? 8 - $unused : 8;
            for ($bit = 0; $bit < $count; ++$bit) {
                $bits[] = ($byte & (0x80 >> $bit)) !== 0;
            }
        }

        return $bits;
    }

    /**
     * RFC 5280 times, in epoch milliseconds.
     *
     * A wrong *tag* throws — OpenSSL's decoder rejects that shape too. Wrong
     * *contents* return the caller's "never valid" sentinel rather than
     * throwing, matching the Node port: OpenSSL stores an ASN1_TIME as an
     * unchecked string, so such a certificate parses happily there and only
     * fails at the validity comparison. Fail-closed either way.
     */
    private static function decodeTime(Asn1Node $node, int $sentinel): int
    {
        if ($node->tag !== Der::TAG_UTC_TIME && $node->tag !== Der::TAG_GENERALIZED_TIME) {
            throw new ParseException('unexpected Validity time type');
        }
        if (preg_match('/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $node->contents, $m) !== 1) {
            return $sentinel;
        }
        $year = (int) $m[1];
        if ($node->tag === Der::TAG_UTC_TIME) {
            $year += $year >= 50 ? 1900 : 2000;
        }
        $month = (int) $m[2];
        $day = (int) $m[3];
        $hour = (int) $m[4];
        $minute = (int) $m[5];
        $second = (int) $m[6];
        if ($month < 1 || $month > 12 || $day < 1 || $day > 31
            || $hour > 23 || $minute > 59 || $second > 59
            || !checkdate($month, $day, $year)) {
            return $sentinel;
        }

        return (int) (gmmktime($hour, $minute, $second, $month, $day, $year) * 1000);
    }
}
