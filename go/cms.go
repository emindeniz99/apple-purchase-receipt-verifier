package applereceipt

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/der"
)

// CMS/PKCS#7 SignedData structure walking for legacy app receipts: the
// part of receipt verification that is pure DER work. Bytes in, bytes
// out — the crypto lives in receipt.go.

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidMD5           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
)

// cmsSignerInfo is one SignerInfo, parsed but not yet verified.
type cmsSignerInfo struct {
	issuerRaw      []byte
	serialContents []byte
	digestOID      asn1.ObjectIdentifier
	signedAttrs    *der.Node // nil when the signature is over the content directly
	// sigAlgOID and sigAlgParams are the signatureAlgorithm field: either a
	// bare key-type OID (rsaEncryption, id-ecPublicKey), whose signature
	// scheme and digest come from the signer's key and digestOID, or an
	// OID that names its own hash (sha256WithRSAEncryption,
	// ecdsa-with-SHA384, id-RSASSA-PSS with explicit parameters), which
	// must then agree with digestOID.
	sigAlgOID    asn1.ObjectIdentifier
	sigAlgParams *der.Node // nil when the field carries no parameters
	signature    []byte
}

type parsedCMS struct {
	content []byte
	// eContentType is the raw OID contents of encapContentInfo's
	// eContentType, compared against a SignerInfo's signed contentType
	// attribute (RFC 5652 §11.1: they MUST match).
	eContentType []byte
	certificates [][]byte
	// signerInfoNodes are the raw, unparsed SignerInfo SEQUENCEs, in
	// receipt order. The caller checks the SignerInfo count against its
	// cap before parsing any of them (maxSignerInfos), the same order the
	// embedded-certificate cap is checked in relative to parsing them.
	signerInfoNodes []*der.Node
}

var errMalformedCMS = errors.New("malformed CMS structure")

// parseCMS walks ContentInfo -> SignedData and pulls out the encapsulated
// content, the embedded certificates and the SignerInfos.
//
// der.Parse rejects trailing bytes after the outermost value, so a
// receipt with an unverified tail appended is refused here rather than
// silently truncated (PLAN.md §2.3).
func parseCMS(b []byte) (*parsedCMS, error) {
	contentInfo, err := der.Parse(b)
	if err != nil {
		return nil, err
	}
	if contentInfo.Tag != der.TagSequence {
		return nil, errMalformedCMS
	}
	contentType := der.Child(contentInfo, 0)
	wrapper := der.Child(contentInfo, 1)
	if contentType == nil || contentType.Tag != der.TagOID ||
		!oidEqual(contentType.Contents, oidSignedData) ||
		wrapper == nil || wrapper.Tag != der.TagContext0 {
		return nil, errors.New("not a CMS SignedData")
	}
	signedData := der.Child(wrapper, 0)
	if signedData == nil || signedData.Tag != der.TagSequence || len(signedData.Children) < 4 {
		return nil, errMalformedCMS
	}

	// encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] }
	encap := der.Child(signedData, 2)
	eContentTypeNode := der.Child(encap, 0)
	eContent := der.Child(encap, 1)
	if encap == nil || encap.Tag != der.TagSequence || eContentTypeNode == nil ||
		eContentTypeNode.Tag != der.TagOID || eContent == nil || eContent.Tag != der.TagContext0 {
		return nil, errors.New("no encapsulated payload")
	}
	contentNode := der.Child(eContent, 0)
	if !der.IsOctetString(contentNode) {
		return nil, errors.New("encapsulated payload is not an OCTET STRING")
	}
	content := der.OctetValue(contentNode)

	// certificates [0] IMPLICIT and crls [1] IMPLICIT sit between
	// encapContentInfo and signerInfos, both optional.
	var certificates [][]byte
	fields := signedData.Children
	for _, child := range fields[3 : len(fields)-1] {
		if child.Tag == der.TagContext0 {
			certificates = make([][]byte, 0, len(child.Children))
			for _, cert := range child.Children {
				certificates = append(certificates, cert.Raw)
			}
		}
	}

	signerInfos := fields[len(fields)-1]
	if signerInfos.Tag != der.TagSet || len(signerInfos.Children) == 0 {
		return nil, errors.New("no signer info")
	}
	return &parsedCMS{
		content:         content,
		eContentType:    eContentTypeNode.Contents,
		certificates:    certificates,
		signerInfoNodes: signerInfos.Children,
	}, nil
}

// parseSignerInfo reads one CMS SignerInfo:
//
//	SignerInfo ::= SEQUENCE {
//	    version CMSVersion,
//	    sid SignerIdentifier,               -- issuerAndSerialNumber only
//	    digestAlgorithm DigestAlgorithmIdentifier,
//	    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//	    signatureAlgorithm SignatureAlgorithmIdentifier,
//	    signature SignatureValue,
//	    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// A trailing unsignedAttrs, present or not, is tolerated and ignored, as
// fields after the third are tolerated elsewhere in this library's
// grammars.
func parseSignerInfo(node *der.Node) (cmsSignerInfo, error) {
	var info cmsSignerInfo
	if node == nil || node.Tag != der.TagSequence || len(node.Children) < 5 {
		return info, errors.New("malformed SignerInfo")
	}
	sid := der.Child(node, 1)
	issuer := der.Child(sid, 0)
	serial := der.Child(sid, 1)
	if sid == nil || sid.Tag != der.TagSequence || issuer == nil || serial == nil ||
		serial.Tag != der.TagInteger {
		return info, errors.New("SignerInfo does not use issuerAndSerialNumber")
	}
	digestAlgorithm := der.Child(node, 2)
	digestOIDNode := der.Child(digestAlgorithm, 0)
	if digestAlgorithm == nil || digestAlgorithm.Tag != der.TagSequence ||
		digestOIDNode == nil || digestOIDNode.Tag != der.TagOID {
		return info, errors.New("malformed digestAlgorithm")
	}
	digestOID, err := decodeOID(digestOIDNode.Contents)
	if err != nil {
		return info, err
	}

	index := 3
	var signedAttrs *der.Node
	if attrs := der.Child(node, index); attrs != nil && attrs.Tag == der.TagContext0 {
		if err := validateSignedAttributesShape(attrs); err != nil {
			return info, err
		}
		signedAttrs = attrs
		index++
	}
	sigAlg := der.Child(node, index)
	sigAlgOIDNode := der.Child(sigAlg, 0)
	if sigAlg == nil || sigAlg.Tag != der.TagSequence ||
		sigAlgOIDNode == nil || sigAlgOIDNode.Tag != der.TagOID {
		return info, errors.New("malformed signatureAlgorithm")
	}
	sigAlgOID, err := decodeOID(sigAlgOIDNode.Contents)
	if err != nil {
		return info, err
	}
	index++
	signature := der.Child(node, index)
	if !der.IsOctetString(signature) {
		return info, errors.New("malformed SignerInfo signature")
	}
	return cmsSignerInfo{
		issuerRaw:      issuer.Raw,
		serialContents: serial.Contents,
		digestOID:      digestOID,
		signedAttrs:    signedAttrs,
		sigAlgOID:      sigAlgOID,
		sigAlgParams:   der.Child(sigAlg, 1),
		signature:      der.OctetValue(signature),
	}, nil
}

// validateSignedAttributesShape checks that every child of a SignerInfo's
// signedAttrs is Attribute-shaped (SEQUENCE { type OID, values SET }),
// before any cryptography and whichever SignerInfo (and whichever
// position among several) it belongs to (owner, 2026-09-27): a SignerInfo
// beside one that verifies does not get a pass on its own shape. Called
// from parseSignerInfo, so a shape defect here fails the whole receipt as
// ReasonMalformed the same way any other unparseable SignerInfo does,
// rather than being deferred to the signer this SignerInfo happens to
// name.
func validateSignedAttributesShape(signedAttrs *der.Node) error {
	for _, attr := range signedAttrs.Children {
		attrType := der.Child(attr, 0)
		values := der.Child(attr, 1)
		if attr.Tag != der.TagSequence || attrType == nil || attrType.Tag != der.TagOID ||
			values == nil || values.Tag != der.TagSet || len(values.Children) == 0 {
			return errors.New("malformed signed attribute")
		}
	}
	return nil
}

// readSignedAttributes returns the messageDigest and contentType signed
// attributes' values (contentType's raw OID contents), or an error when
// either attribute type appears more than once (RFC 5652 §5.3, "MUST
// NOT include multiple instances of any attribute"). Unlike a shape
// defect (validateSignedAttributesShape), a genuine duplicate is a
// property of the CONTENT the signature covers, so it is checked here,
// per signer, as part of the cryptographic verdict (INVALID_SIGNATURE),
// not as an early structural rejection.
func readSignedAttributes(signedAttrs *der.Node) (messageDigest, contentType []byte, err error) {
	seenMessageDigest := false
	seenContentType := false
	for _, attr := range signedAttrs.Children {
		attrType := der.Child(attr, 0)
		value := der.Child(der.Child(attr, 1), 0)
		switch {
		case oidEqual(attrType.Contents, oidMessageDigest):
			if seenMessageDigest {
				return nil, nil, errors.New("messageDigest attribute appears more than once")
			}
			seenMessageDigest = true
			messageDigest = der.OctetValue(value)
		case oidEqual(attrType.Contents, oidContentType):
			if seenContentType {
				return nil, nil, errors.New("content-type attribute appears more than once")
			}
			seenContentType = true
			if value != nil && value.Tag == der.TagOID {
				contentType = value.Contents
			}
		}
	}
	return messageDigest, contentType, nil
}

// signedAttrsSignedBytes is what the SignerInfo signature actually covers
// when signed attributes are present: the attributes re-encoded as an
// explicit SET (RFC 5652 §5.4), i.e. the IMPLICIT [0] identifier octet
// swapped for SET.
//
// Only a definite-length encoding can be re-tagged this way; a BER
// indefinite-length signedAttrs would need a full re-encode, and no Apple
// receipt uses one.
func signedAttrsSignedBytes(signedAttrs *der.Node) ([]byte, error) {
	raw := signedAttrs.Raw
	if len(raw) < 2 {
		return nil, errors.New("malformed signed attributes")
	}
	if raw[1] == 0x80 {
		return nil, errors.New("indefinite-length signed attributes are not supported")
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	out[0] = der.TagSet
	return out, nil
}

func oidEqual(contents []byte, oid asn1.ObjectIdentifier) bool {
	encoded, err := encodeOIDContents(oid)
	if err != nil {
		return false
	}
	return bytes.Equal(contents, encoded)
}

// encodeOIDContents renders an OID's contents octets, so a comparison can
// be made on bytes rather than by decoding attacker-supplied ones.
func encodeOIDContents(oid asn1.ObjectIdentifier) ([]byte, error) {
	if len(oid) < 2 {
		return nil, errors.New("object identifier too short")
	}
	out := []byte{byte(oid[0]*40 + oid[1])}
	for _, part := range oid[2:] {
		if part < 0 {
			return nil, errors.New("negative object identifier arc")
		}
		var chunk []byte
		value := part
		chunk = append(chunk, byte(value&0x7f))
		value >>= 7
		for value > 0 {
			chunk = append(chunk, byte(value&0x7f)|0x80)
			value >>= 7
		}
		for i := len(chunk) - 1; i >= 0; i-- {
			out = append(out, chunk[i])
		}
	}
	return out, nil
}

// decodeOID reads OID contents octets into an ObjectIdentifier, bounded
// so a hostile arc cannot allocate or spin.
func decodeOID(contents []byte) (asn1.ObjectIdentifier, error) {
	if len(contents) == 0 || len(contents) > 64 {
		return nil, errors.New("unsupported object identifier length")
	}
	first := int(contents[0])
	arc0 := first / 40
	if arc0 > 2 {
		arc0 = 2
	}
	out := asn1.ObjectIdentifier{arc0, first - arc0*40}
	value := 0
	started := false
	for _, b := range contents[1:] {
		if value > (1 << 24) {
			return nil, errors.New("object identifier arc out of range")
		}
		value = value<<7 | int(b&0x7f)
		started = true
		if b&0x80 == 0 {
			out = append(out, value)
			value = 0
			started = false
		}
	}
	if started {
		return nil, errors.New("truncated object identifier")
	}
	return out, nil
}
