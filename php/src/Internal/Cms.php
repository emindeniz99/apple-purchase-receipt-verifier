<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;

/**
 * CMS/PKCS#7 SignedData structure walking for legacy app receipts — the part
 * of receipt verification that is pure DER work. Bytes in, bytes out: the
 * crypto lives in the receipt verifier.
 *
 * Every SignerInfo is decoded (up to {@see MAX_SIGNER_INFOS}), because 0.7
 * accepts a receipt when at least one SignerInfo verifies under a pinned
 * chain (docs/design/0.7-api.md §1, "Several SignerInfos").
 *
 * @internal
 */
final class Cms
{
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    private const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    private const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';

    /**
     * Genuine receipts embed a leaf, an intermediate and (for the legacy
     * SHA-1 chain) a root. Ten leaves room for a longer Apple chain while
     * bounding what rejecting a receipt costs: this is enforced BEFORE any
     * embedded certificate is decoded or RSA-checked.
     */
    public const MAX_EMBEDDED_CERTIFICATES = 10;

    /**
     * All signers sign the same content, so an extra signer cannot change
     * what Apple signed; a fifth fails before any signature is checked
     * (docs/design/0.7-api.md §1, "Several SignerInfos").
     */
    public const MAX_SIGNER_INFOS = 4;

    /**
     * @param list<string> $certificates DER bytes of each embedded certificate
     * @param list<CmsSignerInfo> $signerInfos in receipt order, at least one
     */
    private function __construct(
        public readonly string $content,
        public readonly string $econtentTypeOid,
        public readonly array $certificates,
        public readonly array $signerInfos,
    ) {
    }

    /** @throws VerificationException */
    public static function parse(string $der, int $nodeBudget = Der::DEFAULT_NODE_BUDGET): self
    {
        try {
            $contentInfo = Der::parse($der, $nodeBudget);
        } catch (ParseException $e) {
            throw new VerificationException(Reason::Malformed, 'not parseable ASN.1', $e);
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
            if (count($encap) < 2 || $encap[0]->tag !== Der::TAG_OID || $encap[1]->tag !== Der::TAG_CONTEXT_0) {
                throw new ParseException('no encapsulated payload');
            }
            $econtentTypeOid = $encap[0]->contents;
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
            if (count($certificates) > self::MAX_EMBEDDED_CERTIFICATES) {
                throw new VerificationException(
                    Reason::Malformed,
                    'receipt embeds more than ' . self::MAX_EMBEDDED_CERTIFICATES . ' certificates',
                );
            }

            $signerInfosNode = $signedData[$last];
            if ($signerInfosNode->tag !== Der::TAG_SET) {
                throw new ParseException('no signer info');
            }
            $signerNodes = $signerInfosNode->children();
            if ($signerNodes === []) {
                throw new VerificationException(Reason::Malformed, 'no signer info');
            }
            if (count($signerNodes) > self::MAX_SIGNER_INFOS) {
                throw new VerificationException(
                    Reason::Malformed,
                    'receipt carries more than ' . self::MAX_SIGNER_INFOS . ' SignerInfos',
                );
            }
            // Every SignerInfo's signedAttrs syntax is validated here,
            // eagerly and in receipt order, regardless of which signer ends
            // up verifying (hardening parity change #4 / J4).
            $signerInfos = array_map(self::parseSignerInfo(...), $signerNodes);

            return new self($content, $econtentTypeOid, $certificates, $signerInfos);
        } catch (VerificationException $e) {
            throw $e;
        } catch (ParseException $e) {
            throw new VerificationException(Reason::Malformed, 'malformed CMS structure', $e);
        }
    }

    /** @throws ParseException */
    private static function parseSignerInfo(Asn1Node $node): CmsSignerInfo
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
            self::requireSignedAttrsSyntax($signedAttrs);
            ++$index;
        }
        $sigAlgNode = $fields[$index];
        ++$index;
        $signatureNode = $fields[$index] ?? null;
        if ($sigAlgNode->tag !== Der::TAG_SEQUENCE
            || $signatureNode === null || !Der::isOctetString($signatureNode)) {
            throw new ParseException('unexpected SignerInfo layout');
        }
        $sigAlgOidNode = $sigAlgNode->child(0);
        if ($sigAlgOidNode === null || $sigAlgOidNode->tag !== Der::TAG_OID) {
            throw new ParseException('unexpected signatureAlgorithm layout');
        }

        return new CmsSignerInfo(
            issuerRaw: $issuerRaw,
            serial: $serial,
            digestAlgorithmOid: Der::decodeOid($digestOidNode->contents),
            signedAttrs: $signedAttrs,
            signatureAlgorithmOid: Der::decodeOid($sigAlgOidNode->contents),
            signature: Der::octets($signatureNode),
        );
    }

    /**
     * `signedAttrs`'s syntax, checked before any key is used: `SET OF
     * Attribute`, each `Attribute ::= SEQUENCE { type OID, values SET SIZE
     * (1..MAX) OF AttributeValue }`. Semantic rules (a duplicate
     * `messageDigest`, a mismatched `contentType`) are left to the signature
     * check, as {@see Reason::InvalidSignature} for that signer — only the
     * SYNTAX is judged here, for every signer, before any signature.
     *
     * @throws ParseException
     */
    private static function requireSignedAttrsSyntax(Asn1Node $signedAttrs): void
    {
        foreach ($signedAttrs->children() as $attr) {
            $parts = $attr->children();
            if ($attr->tag !== Der::TAG_SEQUENCE || count($parts) < 2
                || $parts[0]->tag !== Der::TAG_OID || $parts[1]->tag !== Der::TAG_SET
                || $parts[1]->childCount() < 1) {
                throw new ParseException('malformed signedAttrs: not an attribute set');
            }
            // The tag alone is not an OID: a type whose contents do not
            // decode (empty, or ending mid-arc) makes the set malformed too,
            // as it is in Node and Java, rather than an unknown attribute
            // the signature then vouches for.
            try {
                Der::decodeOid($parts[0]->contents);
            } catch (ParseException) {
                throw new ParseException('malformed signedAttrs: attribute type is not a valid OBJECT IDENTIFIER');
            }
        }
    }

    /**
     * Every embedded certificate `$signer` names by issuerAndSerialNumber,
     * in bag order. More than one entry can carry the same issuer and
     * serial as the genuine signer (a "twin", carrying its own, different
     * key): each is a candidate to try in turn, so a copy embedded ahead of
     * the genuine signer does not shadow it. Unparseable entries are
     * skipped rather than fatal: a receipt may legitimately carry a
     * certificate we cannot read alongside the one we need.
     *
     * @param list<Certificate> $embedded
     *
     * @return list<int>
     */
    public static function findSignerIndices(CmsSignerInfo $signer, array $embedded): array
    {
        $indices = [];
        foreach ($embedded as $i => $cert) {
            if (hash_equals($cert->serialNumber, $signer->serial)
                && hash_equals($cert->issuerDer, $signer->issuerRaw)) {
                $indices[] = $i;
            }
        }

        return $indices;
    }

    /**
     * Whether `$der` carries the issuer Name and serialNumber `$signer`
     * names, read as generic ASN.1 rather than as a certificate: the whole
     * point, since the entries this is asked about are the ones
     * {@see Certificate::parse()} refused, and an identity is still legible
     * in bytes that are not a certificate all the way down.
     */
    public static function namesSigner(string $der, CmsSignerInfo $signer): bool
    {
        try {
            $certificate = Der::parse($der);
        } catch (ParseException) {
            return false;
        }
        if ($certificate->tag !== Der::TAG_SEQUENCE) {
            return false;
        }
        $tbs = $certificate->child(0);
        if ($tbs === null || $tbs->tag !== Der::TAG_SEQUENCE) {
            return false;
        }
        $index = $tbs->child(0)?->tag === Der::TAG_CONTEXT_0 ? 1 : 0;
        $serial = $tbs->child($index);
        $issuer = $tbs->child($index + 2);

        return $serial !== null
            && $issuer !== null
            && $serial->tag === Der::TAG_INTEGER
            && $issuer->tag === Der::TAG_SEQUENCE
            && hash_equals($serial->contents, $signer->serial)
            && hash_equals($issuer->raw, $signer->issuerRaw);
    }

    /**
     * The `messageDigest` signed attribute's value, and, when present, the
     * `contentType` attribute checked against `$this->econtentTypeOid`
     * (RFC 5652 §5.4). Both are semantic checks (a duplicate
     * `messageDigest`, a mismatched `contentType`) reported for this signer
     * as {@see Reason::InvalidSignature}; the syntax has already been
     * validated by {@see requireSignedAttrsSyntax()}.
     *
     * @throws VerificationException {@see Reason::InvalidSignature}
     */
    public function messageDigestAttribute(CmsSignerInfo $signer): ?string
    {
        if ($signer->signedAttrs === null) {
            return null;
        }
        $wantedDigest = Der::encodeOidContents(self::OID_MESSAGE_DIGEST);
        $wantedContentType = Der::encodeOidContents(self::OID_CONTENT_TYPE);
        $messageDigest = null;
        $messageDigestSeen = false;
        foreach ($signer->signedAttrs->children() as $attr) {
            $parts = $attr->children();
            $type = $parts[0];
            $values = $parts[1]->children();
            if ($type->contents === $wantedDigest) {
                if ($messageDigestSeen) {
                    throw new VerificationException(
                        Reason::InvalidSignature,
                        'messageDigest attribute is present more than once',
                    );
                }
                if (count($values) !== 1) {
                    throw new VerificationException(
                        Reason::InvalidSignature,
                        'messageDigest attribute must carry exactly one value',
                    );
                }
                $messageDigestSeen = true;
                $messageDigest = $values[0]->contents;
            } elseif ($type->contents === $wantedContentType) {
                if (count($values) !== 1 || $values[0]->contents !== $this->econtentTypeOid) {
                    throw new VerificationException(
                        Reason::InvalidSignature,
                        'contentType attribute does not match the encapsulated content type',
                    );
                }
            }
        }

        return $messageDigest;
    }

    /**
     * The bytes a SignerInfo signature covers when signedAttrs are present:
     * the attributes re-encoded as an explicit SET (RFC 5652 §5.4) — swap the
     * IMPLICIT [0] tag for SET. Signing the `[0]`-tagged bytes as they appear
     * on the wire is the classic mistake here, and it verifies nothing.
     */
    public static function signedAttrsSignedBytes(CmsSignerInfo $signer): string
    {
        if ($signer->signedAttrs === null) {
            throw new ParseException('no signed attributes');
        }

        return chr(Der::TAG_SET) . substr($signer->signedAttrs->raw, 1);
    }
}
