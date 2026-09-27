<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;

/**
 * Verifies a CMS SignerInfo's signature under whatever algorithm its pinned
 * chain vouches for (#160, docs/design/0.7-api.md): the guaranteed minimum set is RSA PKCS#1 v1.5,
 * ECDSA over P-256/P-384, and MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512
 * digests. No key-type or algorithm allowlist beyond what OpenSSL itself can
 * verify (Q14).
 *
 * RSA-PSS (id-RSASSA-PSS) is refused as {@see Reason::InvalidSignature}, like
 * any algorithm this class cannot verify. PHP's `openssl_verify()` has no PSS
 * mode, Apple never signs receipts with PSS, and the alternative is
 * hand-written EMSA-PSS on a path where the signer picks the algorithm.
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
        if ($oid === self::OID_EC_PUBLIC_KEY) {
            return ['ecdsa', null];
        }
        if (isset(self::ECDSA_NAMED_HASH[$oid])) {
            return ['ecdsa', self::ECDSA_NAMED_HASH[$oid]];
        }

        throw new VerificationException(Reason::InvalidSignature, 'unsupported signature algorithm');
    }
}
