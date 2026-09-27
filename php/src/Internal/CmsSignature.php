<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use OpenSSLAsymmetricKey;

/**
 * Verifies a CMS SignerInfo's signature under whatever algorithm its pinned
 * chain vouches for (docs/design/0.7-hardening-parity.md, "any receipt
 * signer algorithm"): the guaranteed minimum set is RSA PKCS#1 v1.5 and
 * RSA-PSS, ECDSA over P-256/P-384, and MD5/SHA-1/SHA-224/SHA-256/SHA-384/
 * SHA-512 digests. No key-type or algorithm allowlist beyond what OpenSSL
 * itself can verify (Q14).
 *
 * PHP's `openssl_verify()` has no RSA-PSS mode, so PSS is verified by hand:
 * `openssl_public_decrypt()` with `OPENSSL_NO_PADDING` recovers the padded
 * message representative, and EMSA-PSS-VERIFY (RFC 8017 §9.1.2) is applied
 * to it directly.
 *
 * @internal
 */
final class CmsSignature
{
    private const DIGEST_OIDS = [
        '1.2.840.113549.2.5' => 'md5',
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    /** @var array<string, int> */
    private const OPENSSL_ALGO = [
        'md5' => OPENSSL_ALGO_MD5,
        'sha1' => OPENSSL_ALGO_SHA1,
        'sha224' => OPENSSL_ALGO_SHA224,
        'sha256' => OPENSSL_ALGO_SHA256,
        'sha384' => OPENSSL_ALGO_SHA384,
        'sha512' => OPENSSL_ALGO_SHA512,
    ];

    private const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    private const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
    private const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    /** RSA PKCS#1 v1.5 signature OIDs that name their own hash. */
    private const RSA_PKCS1_NAMED_HASH = [
        '1.2.840.113549.1.1.4' => 'md5',
        '1.2.840.113549.1.1.5' => 'sha1',
        '1.2.840.113549.1.1.14' => 'sha224',
        '1.2.840.113549.1.1.11' => 'sha256',
        '1.2.840.113549.1.1.12' => 'sha384',
        '1.2.840.113549.1.1.13' => 'sha512',
    ];

    /** ECDSA signature OIDs that name their own hash. */
    private const ECDSA_NAMED_HASH = [
        '1.2.840.10045.4.1' => 'sha1',
        '1.2.840.10045.4.3.1' => 'sha224',
        '1.2.840.10045.4.3.2' => 'sha256',
        '1.2.840.10045.4.3.3' => 'sha384',
        '1.2.840.10045.4.3.4' => 'sha512',
    ];

    /**
     * The digest name (`hash()`-compatible) for `$digestAlgorithmOid`, or
     * `null` when it names no digest this library implements. The receipt
     * verifier resolves this itself, before {@see verify()}, because it
     * needs the digest to compute the `messageDigest` signed attribute's
     * expected value.
     */
    public static function resolveDigestName(string $digestAlgorithmOid): ?string
    {
        return self::DIGEST_OIDS[$digestAlgorithmOid] ?? null;
    }

    /**
     * Verifies `$signature` over `$data` with `$signer`'s public key, under
     * the algorithm `$info` names.
     *
     * @throws VerificationException {@see Reason::InvalidSignature} for an
     *         unsupported or self-contradictory algorithm, or a signature
     *         that does not check out; {@see Reason::InvalidCertificate}
     *         when the signer's key does not decode
     */
    public static function verify(string $data, string $signature, Certificate $signer, CmsSignerInfo $info): void
    {
        $digestName = self::DIGEST_OIDS[$info->digestAlgorithmOid] ?? null;
        if ($digestName === null) {
            throw new VerificationException(Reason::InvalidSignature, 'unsupported digest algorithm');
        }

        [$family, $namedHash] = self::classify($info);
        // A signatureAlgorithm that names a hash must name the one the
        // SignerInfo digested with (a relabelled field is not one
        // signature under two names); rsaEncryption / id-ecPublicKey name
        // none and take digestAlgorithm.
        if ($namedHash !== null && $namedHash !== $digestName) {
            throw new VerificationException(
                Reason::InvalidSignature,
                'signatureAlgorithm names another hash than digestAlgorithm',
            );
        }

        $key = $signer->publicKey();
        if ($key === null) {
            throw new VerificationException(Reason::InvalidCertificate, 'receipt signer certificate key does not decode');
        }
        $keyType = $signer->publicKeyType();

        if ($family === 'pss') {
            if ($keyType !== OPENSSL_KEYTYPE_RSA) {
                throw new VerificationException(Reason::InvalidSignature, 'signer key is not RSA');
            }
            [$mgfHash, $saltLength] = self::pssParams($info->signatureAlgorithmParams, $digestName);
            if (!self::verifyRsaPss($data, $signature, $key, $digestName, $mgfHash, $saltLength)) {
                throw new VerificationException(Reason::InvalidSignature, 'CMS signature check failed');
            }

            return;
        }
        if ($family === 'ecdsa' && $keyType !== OPENSSL_KEYTYPE_EC) {
            throw new VerificationException(Reason::InvalidSignature, 'signer key is not EC');
        }
        if ($family === 'pkcs1v15' && $keyType !== OPENSSL_KEYTYPE_RSA) {
            throw new VerificationException(Reason::InvalidSignature, 'signer key is not RSA');
        }
        // openssl_verify() answers 1 valid, 0 invalid and -1 on error, and
        // -1 is truthy in PHP: `=== 1` is the only acceptable comparison.
        $result = openssl_verify($data, $signature, $key, self::OPENSSL_ALGO[$digestName]);
        Certificate::drainOpenSslErrors();
        if ($result !== 1) {
            throw new VerificationException(Reason::InvalidSignature, 'CMS signature check failed');
        }
    }

    /** @return array{string, ?string} [family, namedHash] */
    private static function classify(CmsSignerInfo $info): array
    {
        $oid = $info->signatureAlgorithmOid;
        if ($oid === self::OID_RSA_ENCRYPTION) {
            return ['pkcs1v15', null];
        }
        if (isset(self::RSA_PKCS1_NAMED_HASH[$oid])) {
            return ['pkcs1v15', self::RSA_PKCS1_NAMED_HASH[$oid]];
        }
        if ($oid === self::OID_RSASSA_PSS) {
            return ['pss', self::pssHashName($info->signatureAlgorithmParams)];
        }
        if ($oid === self::OID_EC_PUBLIC_KEY) {
            return ['ecdsa', null];
        }
        if (isset(self::ECDSA_NAMED_HASH[$oid])) {
            return ['ecdsa', self::ECDSA_NAMED_HASH[$oid]];
        }

        throw new VerificationException(Reason::InvalidSignature, 'unsupported signature algorithm');
    }

    /**
     * `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] ..., maskGenAlgorithm
     * [1] ..., saltLength [2] INTEGER DEFAULT 20, trailerField [3] ... }`
     * (RFC 8017 A.2.3), every field EXPLICITLY tagged and optional (RFC 8017
     * defaults: SHA-1 throughout, salt length 20).
     */
    private static function pssHashName(?Asn1Node $params): string
    {
        if ($params === null) {
            return 'sha1';
        }
        foreach ($params->children() as $field) {
            if ($field->tag === Der::TAG_CONTEXT_0) {
                $oidNode = $field->child(0)?->child(0);
                if ($oidNode !== null && $oidNode->tag === Der::TAG_OID) {
                    return self::DIGEST_OIDS[Der::decodeOid($oidNode->contents)] ?? 'sha1';
                }
            }
        }

        return 'sha1';
    }

    /** @return array{string, int} [mgf1Hash, saltLength] */
    private static function pssParams(?Asn1Node $params, string $digestName): array
    {
        $mgfHash = $digestName;
        $saltLength = self::digestByteLength($digestName);
        if ($params === null) {
            return [$mgfHash, $saltLength];
        }
        foreach ($params->children() as $field) {
            if ($field->tag === Der::TAG_CONTEXT_1) {
                // maskGenAlgorithm: AlgorithmIdentifier { mgf1, AlgorithmIdentifier { hashOid } }
                $mgfHashOid = $field->child(0)?->child(1)?->child(0);
                if ($mgfHashOid !== null && $mgfHashOid->tag === Der::TAG_OID) {
                    $mgfHash = self::DIGEST_OIDS[Der::decodeOid($mgfHashOid->contents)] ?? $mgfHash;
                }
            } elseif ($field->tag === Der::TAG_CONTEXT_2) {
                $intNode = $field->child(0);
                if ($intNode !== null && $intNode->tag === Der::TAG_INTEGER && strlen($intNode->contents) <= 4) {
                    $value = 0;
                    foreach (str_split($intNode->contents) as $byte) {
                        $value = $value * 256 + ord($byte);
                    }
                    $saltLength = $value;
                }
            }
        }

        return [$mgfHash, $saltLength];
    }

    private static function digestByteLength(string $name): int
    {
        return match ($name) {
            'md5' => 16,
            'sha1' => 20,
            'sha224' => 28,
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
        };
    }

    /** RFC 8017 §9.1.2, EMSA-PSS-VERIFY, applied to the RSA public operation directly. */
    private static function verifyRsaPss(
        string $message,
        string $signature,
        OpenSSLAsymmetricKey $key,
        string $hashName,
        string $mgfHash,
        int $saltLength,
    ): bool {
        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['bits'], $details['rsa']['n'])) {
            return false;
        }
        $modBits = (int) $details['bits'];
        $k = intdiv($modBits + 7, 8);
        if (strlen($signature) !== $k) {
            return false;
        }
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);

        $decrypted = openssl_public_decrypt($signature, $em, $key, OPENSSL_NO_PADDING);
        Certificate::drainOpenSslErrors();
        if ($decrypted === false) {
            return false;
        }
        // openssl_public_decrypt() strips leading zero bytes from the RSA
        // integer result; restore the fixed k-byte width before reading it
        // as the RFC's octet string EM.
        $em = str_pad($em, $k, "\x00", STR_PAD_LEFT);
        if ($emLen < $k) {
            if (substr($em, 0, $k - $emLen) !== str_repeat("\x00", $k - $emLen)) {
                return false;
            }
            $em = substr($em, $k - $emLen);
        }

        $hLen = self::digestByteLength($hashName);
        if ($emLen < $hLen + $saltLength + 2 || $saltLength < 0) {
            return false;
        }
        if ($em[$emLen - 1] !== "\xbc") {
            return false;
        }
        $maskedDbLen = $emLen - $hLen - 1;
        $maskedDb = substr($em, 0, $maskedDbLen);
        $h = substr($em, $maskedDbLen, $hLen);

        $bitsToClear = 8 * $emLen - $emBits;
        if ($bitsToClear > 0) {
            $topByte = ord($maskedDb[0]);
            if (($topByte & (0xFF << (8 - $bitsToClear) & 0xFF)) !== 0) {
                return false;
            }
        }

        $dbMask = self::mgf1($h, $maskedDbLen, $mgfHash);
        $db = $maskedDb ^ $dbMask;
        if ($bitsToClear > 0) {
            $db[0] = chr(ord($db[0]) & (0xFF >> $bitsToClear));
        }

        $psLen = $emLen - $hLen - $saltLength - 2;
        if ($psLen < 0) {
            return false;
        }
        if (substr($db, 0, $psLen) !== str_repeat("\x00", $psLen) || $db[$psLen] !== "\x01") {
            return false;
        }
        $salt = substr($db, $psLen + 1);
        if (strlen($salt) !== $saltLength) {
            return false;
        }

        $mHash = hash($hashName, $message, true);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $hPrime = hash($hashName, $mPrime, true);

        return hash_equals($hPrime, $h);
    }

    /** MGF1 (RFC 8017 B.2.1). */
    private static function mgf1(string $seed, int $length, string $hashName): string
    {
        $hLen = self::digestByteLength($hashName);
        $out = '';
        $count = (int) ceil($length / $hLen);
        for ($i = 0; $i < $count; ++$i) {
            $out .= hash($hashName, $seed . pack('N', $i), true);
        }

        return substr($out, 0, $length);
    }
}
