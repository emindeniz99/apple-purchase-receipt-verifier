<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A generated fake "Apple" PKI plus the CMS/JWS assembly the negative tests
 * need — the same technique Apple's own libraries use for their fixtures, so
 * the tests need no real Apple secrets and can prove that anchor pinning
 * works by minting a chain the library must refuse.
 *
 * The shared `fixtures/` corpus stays the cross-language contract; this exists
 * only for the shapes no shared fixture can express (a certificate whose inner
 * and outer signature algorithms disagree, a 200-certificate flood, a
 * cross-signed mesh), and for negative cases that must be built rather than
 * stored.
 */
final class TestPki
{
    public const LEAF_OID_HEX = '2a864886f76364060b01';        // 1.2.840.113635.100.6.11.1
    public const INTERMEDIATE_OID_HEX = '2a864886f76364060201';   // 1.2.840.113635.100.6.2.1

    private const OID_SHA256_RSA = '2a864886f70d01010b';
    private const OID_SHA1_RSA = '2a864886f70d010105';
    private const OID_ECDSA_SHA256 = '2a8648ce3d040302';
    private const OID_COMMON_NAME = '550403';
    private const OID_BASIC_CONSTRAINTS = '551d13';

    public const OID_SIGNED_DATA_HEX = '2a864886f70d010702';
    public const OID_DATA_HEX = '2a864886f70d010701';
    public const OID_MESSAGE_DIGEST_HEX = '2a864886f70d010904';
    public const OID_SHA256_HEX = '608648016503040201';
    public const OID_SHA1_HEX = '2b0e03021a';
    public const OID_MD5_HEX = '2a864886f70d0202';

    private static int $nextSerial = 1;

    public static function rsaKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new RuntimeException('cannot generate an RSA key');
        }

        return $key;
    }

    public static function ecKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false) {
            throw new RuntimeException('cannot generate an EC key');
        }

        return $key;
    }

    /** SubjectPublicKeyInfo DER for a key handle. */
    public static function spki(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new RuntimeException('cannot read key details');
        }
        $pem = $details['key'];
        $body = preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem) ?? '';
        $der = base64_decode($body, true);
        if ($der === false) {
            throw new RuntimeException('cannot decode SPKI');
        }

        return $der;
    }

    public static function name(string $commonName): string
    {
        return DerWriter::tlv(
            DerWriter::SEQUENCE,
            DerWriter::tlv(DerWriter::SET, DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid(self::OID_COMMON_NAME),
                DerWriter::tlv(DerWriter::UTF8_STRING, $commonName),
            )),
        );
    }

    /** UTCTime validity window; `YYMMDDHHMMSSZ`. */
    public static function validity(string $notBefore = '200101000000Z', string $notAfter = '350101000000Z'): string
    {
        return DerWriter::tlv(
            DerWriter::SEQUENCE,
            DerWriter::tlv(DerWriter::UTC_TIME, $notBefore),
            DerWriter::tlv(DerWriter::UTC_TIME, $notAfter),
        );
    }

    /**
     * A v3 certificate, signed for real so the path walk actually runs the
     * signature check on it.
     *
     * @param list<string> $markerOidsHex extension OIDs to stamp on, empty-valued
     *
     * @return array{der: string, sid: string}
     */
    public static function certificate(
        string $subject,
        string $issuer,
        OpenSSLAsymmetricKey $subjectKey,
        OpenSSLAsymmetricKey $issuerKey,
        bool $ca = false,
        array $markerOidsHex = [],
        ?string $validity = null,
        ?string $innerAlgorithmHex = null,
    ): array {
        $isEcIssuer = (openssl_pkey_get_details($issuerKey)['type'] ?? null) === OPENSSL_KEYTYPE_EC;
        $outerAlgorithm = $isEcIssuer
            ? DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::oid(self::OID_ECDSA_SHA256))
            : self::rsaSha256Algorithm();
        $innerAlgorithm = $innerAlgorithmHex === null
            ? $outerAlgorithm
            : DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid($innerAlgorithmHex),
                DerWriter::tlv(DerWriter::NULL_TAG),
            );

        $serial = chr(self::$nextSerial++);
        $extensions = [];
        if ($ca) {
            $extensions[] = DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid(self::OID_BASIC_CONSTRAINTS),
                DerWriter::tlv(DerWriter::BOOLEAN, "\xff"),
                DerWriter::tlv(DerWriter::OCTET_STRING, DerWriter::tlv(
                    DerWriter::SEQUENCE,
                    DerWriter::tlv(DerWriter::BOOLEAN, "\xff"),
                )),
            );
        }
        foreach ($markerOidsHex as $oidHex) {
            $extensions[] = DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::oid($oidHex),
                DerWriter::tlv(DerWriter::OCTET_STRING, DerWriter::tlv(DerWriter::NULL_TAG)),
            );
        }

        $tbsParts = [
            DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::int(2)),
            DerWriter::tlv(DerWriter::INTEGER, $serial),
            $innerAlgorithm,
            self::name($issuer),
            $validity ?? self::validity(),
            self::name($subject),
            self::spki($subjectKey),
        ];
        if ($extensions !== []) {
            $tbsParts[] = DerWriter::tlv(
                DerWriter::CONTEXT_3,
                DerWriter::tlv(DerWriter::SEQUENCE, ...$extensions),
            );
        }
        $tbs = DerWriter::tlv(DerWriter::SEQUENCE, ...$tbsParts);

        if (!openssl_sign($tbs, $signature, $issuerKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('cannot sign the test certificate');
        }

        return [
            'der' => DerWriter::tlv(
                DerWriter::SEQUENCE,
                $tbs,
                $outerAlgorithm,
                DerWriter::tlv(DerWriter::BIT_STRING, "\x00" . $signature),
            ),
            // issuerAndSerialNumber, which is how a SignerInfo names its signer.
            'sid' => DerWriter::tlv(
                DerWriter::SEQUENCE,
                self::name($issuer),
                DerWriter::tlv(DerWriter::INTEGER, $serial),
            ),
        ];
    }

    /**
     * A CMS SignedData wrapping `$payload`, embedding `$certificates`, signed
     * by `$signerKey` — a genuinely valid receipt when the caller's anchors
     * include the chain's root.
     *
     * @param list<string> $certificates DER
     */
    public static function receipt(
        string $payload,
        array $certificates,
        string $sid,
        ?OpenSSLAsymmetricKey $signerKey,
        string $digestOidHex = self::OID_SHA1_HEX,
        ?string $signatureOverride = null,
        ?string $signedAttrs = null,
    ): string {
        $signedBytes = $signedAttrs === null
            ? $payload
            : chr(DerWriter::SET) . substr($signedAttrs, 1);
        if ($signatureOverride !== null) {
            $signature = $signatureOverride;
        } else {
            $algorithm = match ($digestOidHex) {
                self::OID_SHA1_HEX => OPENSSL_ALGO_SHA1,
                self::OID_SHA256_HEX => OPENSSL_ALGO_SHA256,
                default => OPENSSL_ALGO_SHA256,
            };
            if ($signerKey === null || !openssl_sign($signedBytes, $signature, $signerKey, $algorithm)) {
                throw new RuntimeException('cannot sign the test receipt');
            }
        }

        $signerFields = [
            DerWriter::int(1),
            $sid,
            DerWriter::tlv(DerWriter::SEQUENCE, DerWriter::oid($digestOidHex), DerWriter::tlv(DerWriter::NULL_TAG)),
        ];
        if ($signedAttrs !== null) {
            $signerFields[] = $signedAttrs;
        }
        $signerFields[] = self::rsaSha256Algorithm();
        $signerFields[] = DerWriter::tlv(DerWriter::OCTET_STRING, $signature);

        return DerWriter::tlv(
            DerWriter::SEQUENCE,
            DerWriter::oid(self::OID_SIGNED_DATA_HEX),
            DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::tlv(
                DerWriter::SEQUENCE,
                DerWriter::int(1),
                DerWriter::tlv(DerWriter::SET),
                DerWriter::tlv(
                    DerWriter::SEQUENCE,
                    DerWriter::oid(self::OID_DATA_HEX),
                    DerWriter::tlv(DerWriter::CONTEXT_0, DerWriter::tlv(DerWriter::OCTET_STRING, $payload)),
                ),
                DerWriter::tlv(DerWriter::CONTEXT_0, implode('', $certificates)),
                DerWriter::tlv(DerWriter::SET, DerWriter::tlv(DerWriter::SEQUENCE, ...$signerFields)),
            )),
        );
    }

    private static function rsaSha256Algorithm(): string
    {
        return DerWriter::tlv(
            DerWriter::SEQUENCE,
            DerWriter::oid(self::OID_SHA256_RSA),
            DerWriter::tlv(DerWriter::NULL_TAG),
        );
    }

    /** One receipt attribute: SEQUENCE { type, version, value }. */
    public static function attribute(int $type, string $value): string
    {
        return DerWriter::tlv(
            DerWriter::SEQUENCE,
            self::encodeInteger($type),
            DerWriter::int(1),
            DerWriter::tlv(DerWriter::OCTET_STRING, $value),
        );
    }

    /** A receipt payload SET carrying the given attributes. */
    public static function payload(string ...$attributes): string
    {
        return DerWriter::tlv(DerWriter::SET, ...$attributes);
    }

    public static function utf8Attribute(int $type, string $text): string
    {
        return self::attribute($type, DerWriter::tlv(DerWriter::UTF8_STRING, $text));
    }

    public static function dateAttribute(int $type, string $text): string
    {
        return self::attribute($type, DerWriter::tlv(DerWriter::IA5_STRING, $text));
    }

    public static function encodeInteger(int $value): string
    {
        if ($value === 0) {
            return DerWriter::int(0);
        }
        $bytes = '';
        $v = $value;
        while ($v > 0) {
            $bytes = chr($v & 0xff) . $bytes;
            $v >>= 8;
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return DerWriter::tlv(DerWriter::INTEGER, $bytes);
    }

    /**
     * A compact JWS signed with `$leafKey` (an EC P-256 key), carrying `$x5c`
     * in the header.
     *
     * @param array<string, mixed> $claims
     * @param list<string> $x5cDer
     */
    public static function jws(
        array $claims,
        array $x5cDer,
        OpenSSLAsymmetricKey $leafKey,
        string $alg = 'ES256',
    ): string {
        $header = ['alg' => $alg, 'x5c' => array_map(base64_encode(...), $x5cDer)];
        $signingInput = self::b64url((string) json_encode($header)) . '.' . self::b64url((string) json_encode($claims));
        if (!openssl_sign($signingInput, $der, $leafKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('cannot sign the test JWS');
        }

        return $signingInput . '.' . self::b64url(self::derToP1363($der));
    }

    public static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** ECDSA DER SEQUENCE { r, s } to the fixed-width r ‖ s a JWS carries. */
    public static function derToP1363(string $der): string
    {
        $pos = 2;
        if ((ord($der[1]) & 0x80) !== 0) {
            $pos += ord($der[1]) & 0x7f;
        }
        $out = '';
        for ($i = 0; $i < 2; ++$i) {
            $length = ord($der[$pos + 1]);
            $value = ltrim(substr($der, $pos + 2, $length), "\x00");
            $out .= str_pad($value, 32, "\x00", STR_PAD_LEFT);
            $pos += 2 + $length;
        }

        return $out;
    }
}
