<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * CMS/PKCS#7 SignedData structure walking for legacy app receipts — the part
 * of receipt verification that is pure DER work. Bytes in, bytes out: the
 * crypto lives in the verifier.
 *
 * Ported check-for-check from `node/src/cms.ts` so the two implementations
 * cannot disagree about what a receipt contains.
 *
 * @internal
 */
final class Cms
{
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    private const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

    /**
     * Only the digests Apple uses for receipts. Anything else is rejected
     * rather than looked up: a receipt is not the place to be liberal.
     */
    private const DIGEST_ALGORITHMS = [
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
    ];

    /**
     * @param list<string> $certificates DER bytes of each embedded certificate
     * @param 'sha1'|'sha256' $digest the digest the signature is over
     */
    private function __construct(
        public readonly string $content,
        public readonly array $certificates,
        public readonly string $signerIssuerRaw,
        public readonly string $signerSerial,
        public readonly string $digest,
        public readonly ?Asn1Node $signedAttrs,
        public readonly string $signature,
    ) {
    }

    /** @throws VerificationException */
    public static function parse(string $der, int $nodeBudget = Der::DEFAULT_NODE_BUDGET): self
    {
        try {
            $contentInfo = Der::parse($der, $nodeBudget);
        } catch (ParseException $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'not parseable ASN.1', $e);
        }

        try {
            $info = $contentInfo->children();
            if ($contentInfo->tag !== Der::TAG_SEQUENCE
                || count($info) < 2
                || $info[0]->contents !== Der::encodeOidContents(self::OID_SIGNED_DATA)
                || $info[1]->tag !== Der::TAG_CONTEXT_0) {
                throw new ParseException('not a CMS SignedData');
            }
            $inner = $info[1]->child(0);
            if ($inner === null) {
                throw new ParseException('empty SignedData');
            }
            $signedData = $inner->children();
            if (count($signedData) < 4) {
                throw new ParseException('unexpected SignedData layout');
            }
            $encap = $signedData[2]->children();
            if (count($encap) < 2 || $encap[1]->tag !== Der::TAG_CONTEXT_0) {
                throw new ParseException('no encapsulated payload');
            }
            $contentNode = $encap[1]->child(0);
            if ($contentNode === null || !Der::isOctetString($contentNode)) {
                throw new ParseException('encapsulated payload is not an OCTET STRING');
            }
            $content = Der::octets($contentNode);

            $certificates = [];
            $last = count($signedData) - 1;
            for ($i = 3; $i < $last; ++$i) {
                if ($signedData[$i]->tag === Der::TAG_CONTEXT_0) {
                    $certificates = array_map(
                        static fn (Asn1Node $c): string => $c->raw,
                        $signedData[$i]->children(),
                    );
                }
            }

            $signerInfos = $signedData[$last];
            $signerInfo = $signerInfos->child(0);
            if ($signerInfos->tag !== Der::TAG_SET || $signerInfo === null) {
                throw new ParseException('no signer info');
            }

            return self::parseSignerInfo($signerInfo, $content, $certificates);
        } catch (VerificationException $e) {
            throw $e;
        } catch (ParseException $e) {
            throw new VerificationException(Reason::InvalidReceiptFormat, 'malformed CMS structure', $e);
        }
    }

    /**
     * @param list<string> $certificates
     *
     * @throws ParseException
     */
    private static function parseSignerInfo(Asn1Node $node, string $content, array $certificates): self
    {
        $fields = $node->children();
        if (count($fields) < 5) {
            throw new ParseException('unexpected SignerInfo layout');
        }
        $sid = $fields[1]->children();
        if (count($sid) < 2) {
            throw new ParseException('unexpected SignerIdentifier layout');
        }
        $issuerRaw = $sid[0]->raw;
        $serial = $sid[1]->contents;

        $digestOidNode = $fields[2]->child(0);
        if ($digestOidNode === null) {
            throw new ParseException('missing digest algorithm');
        }
        $digestOid = Der::decodeOid($digestOidNode->contents);

        $index = 3;
        $signedAttrs = null;
        if ($fields[$index]->tag === Der::TAG_CONTEXT_0) {
            $signedAttrs = $fields[$index];
            ++$index;
        }
        ++$index; // signatureAlgorithm — RSA PKCS#1 v1.5; the digest OID drives the hash
        if (!isset($fields[$index])) {
            throw new ParseException('unexpected SignerInfo layout');
        }
        $signature = $fields[$index]->contents;

        // Rejected here rather than at signature time so an unsupported digest
        // reads as a malformed receipt, which is what every other port says.
        if (!isset(self::DIGEST_ALGORITHMS[$digestOid])) {
            throw new ParseException('unsupported digest algorithm');
        }

        return new self(
            content: $content,
            certificates: $certificates,
            signerIssuerRaw: $issuerRaw,
            signerSerial: $serial,
            digest: self::DIGEST_ALGORITHMS[$digestOid],
            signedAttrs: $signedAttrs,
            signature: $signature,
        );
    }

    /**
     * Index of the embedded certificate the SignerInfo names by
     * issuerAndSerialNumber, or -1. Unparseable entries are skipped rather
     * than fatal: a receipt may legitimately carry a certificate we cannot
     * read alongside the one we need.
     *
     * @param list<Certificate> $embedded
     */
    public function findSignerIndex(array $embedded): int
    {
        foreach ($embedded as $i => $cert) {
            if (hash_equals($cert->serialNumber, $this->signerSerial)
                && hash_equals($cert->issuerDer, $this->signerIssuerRaw)) {
                return $i;
            }
        }

        return -1;
    }

    /** @throws ParseException */
    public function messageDigestAttribute(): ?string
    {
        if ($this->signedAttrs === null) {
            return null;
        }
        $wanted = Der::encodeOidContents(self::OID_MESSAGE_DIGEST);
        foreach ($this->signedAttrs->children() as $attr) {
            // Every signed attribute is SEQUENCE { OID, SET OF value }; a shape
            // missing either part is malformed, not merely uninteresting.
            $parts = $attr->children();
            $type = $parts[0] ?? null;
            $value = ($parts[1] ?? null)?->child(0);
            if ($type === null || $value === null) {
                throw new ParseException('malformed signed attribute');
            }
            if ($type->contents === $wanted) {
                return $value->contents;
            }
        }

        return null;
    }

    /**
     * The bytes a SignerInfo signature covers when signedAttrs are present:
     * the attributes re-encoded as an explicit SET (RFC 5652 §5.4) — swap the
     * IMPLICIT [0] tag for SET. Signing the `[0]`-tagged bytes as they appear
     * on the wire is the classic mistake here, and it verifies nothing.
     */
    public function signedAttrsSignedBytes(): string
    {
        if ($this->signedAttrs === null) {
            throw new ParseException('no signed attributes');
        }

        return chr(Der::TAG_SET) . substr($this->signedAttrs->raw, 1);
    }
}
