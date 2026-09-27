package applereceipt

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/der"
)

// Any receipt signer algorithm (docs/design/0.7-hardening-parity.md,
// change 3): the signer must chain to a pinned root and carry Apple's
// receipt-signing marker, and its signature must verify; its key type,
// digest and signature algorithm are not restricted beyond what
// crypto/x509 and crypto/rsa can check. This file resolves a CMS
// SignerInfo's digestAlgorithm and signatureAlgorithm fields into the
// x509.SignatureAlgorithm (or, for MD5, the crypto/rsa call) to check the
// content signature with.

var (
	oidMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// digestFromOID maps a digestAlgorithm OID to the crypto.Hash it names.
// SHA-224 is deliberately absent: crypto/x509 has no SignatureAlgorithm
// constant that pairs it with RSA or ECDSA, so a signer using it is
// ReasonInvalidSignature ("unsupported"), the same verdict an unknown
// digest OID gets.
func digestFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	case oid.Equal(oidMD5):
		return crypto.MD5, true
	default:
		return 0, false
	}
}

// namedSignatureScheme maps a signatureAlgorithm OID that names its own
// hash to that hash and the matching x509.SignatureAlgorithm. algo is 0
// for MD5, which crypto/x509 cannot check (see checkMD5Signature); the
// caller reads digest instead.
func namedSignatureScheme(oid asn1.ObjectIdentifier) (digest crypto.Hash, algo x509.SignatureAlgorithm, named bool) {
	switch {
	case oid.Equal(oidMD5WithRSA):
		return crypto.MD5, 0, true
	case oid.Equal(oidSHA1WithRSA):
		return crypto.SHA1, x509.SHA1WithRSA, true
	case oid.Equal(oidSHA256WithRSA):
		return crypto.SHA256, x509.SHA256WithRSA, true
	case oid.Equal(oidSHA384WithRSA):
		return crypto.SHA384, x509.SHA384WithRSA, true
	case oid.Equal(oidSHA512WithRSA):
		return crypto.SHA512, x509.SHA512WithRSA, true
	case oid.Equal(oidECDSAWithSHA1):
		return crypto.SHA1, x509.ECDSAWithSHA1, true
	case oid.Equal(oidECDSAWithSHA256):
		return crypto.SHA256, x509.ECDSAWithSHA256, true
	case oid.Equal(oidECDSAWithSHA384):
		return crypto.SHA384, x509.ECDSAWithSHA384, true
	case oid.Equal(oidECDSAWithSHA512):
		return crypto.SHA512, x509.ECDSAWithSHA512, true
	default:
		return 0, 0, false
	}
}

// pssHashAlgorithm reads RSASSA-PSS-params' hashAlgorithm [0] field
// (RFC 4055 §3.1), defaulting to SHA-1 (its DEFAULT) when params is nil
// or the field is absent. Only the hash is read: crypto/x509 always
// verifies RSA-PSS assuming the salt length equals the hash length, so a
// signature made with a genuinely different salt length fails the
// signature check honestly rather than through a parameter this package
// declined to read.
func pssHashAlgorithm(params *der.Node) (crypto.Hash, bool) {
	if params == nil || params.Tag != der.TagSequence {
		if params == nil {
			return crypto.SHA1, true
		}
		return 0, false
	}
	for _, field := range params.Children {
		if field.Tag != der.TagContext0 {
			continue
		}
		seq := der.Child(field, 0)
		oidNode := der.Child(seq, 0)
		if seq == nil || seq.Tag != der.TagSequence || oidNode == nil || oidNode.Tag != der.TagOID {
			return 0, false
		}
		oid, err := decodeOID(oidNode.Contents)
		if err != nil {
			return 0, false
		}
		return digestFromOID(oid)
	}
	return crypto.SHA1, true
}

func pssAlgorithm(digest crypto.Hash) (x509.SignatureAlgorithm, bool) {
	switch digest {
	case crypto.SHA256:
		return x509.SHA256WithRSAPSS, true
	case crypto.SHA384:
		return x509.SHA384WithRSAPSS, true
	case crypto.SHA512:
		return x509.SHA512WithRSAPSS, true
	default:
		return 0, false
	}
}

// resolveCMSSignatureAlgorithm decides how to check a CMS SignerInfo's
// signature. keyIsRSA says whether the signer's certificate carries an RSA
// key (an ECDSA key otherwise). ok is false for a digest or signature
// algorithm this package's cryptography does not implement, or when
// signatureAlgorithm names a hash that disagrees with digestAlgorithm: a
// relabelling, not a genuine second signature.
func resolveCMSSignatureAlgorithm(info cmsSignerInfo, keyIsRSA bool) (algo x509.SignatureAlgorithm, digest crypto.Hash, ok bool) {
	digestFromInfo, digestKnown := digestFromOID(info.digestOID)

	if info.sigAlgOID.Equal(oidRSASSAPSS) {
		pssDigest, pssOK := pssHashAlgorithm(info.sigAlgParams)
		if !pssOK || !digestKnown || pssDigest != digestFromInfo || !keyIsRSA {
			return 0, 0, false
		}
		algo, algoOK := pssAlgorithm(pssDigest)
		return algo, pssDigest, algoOK
	}
	if namedDigest, namedAlgo, named := namedSignatureScheme(info.sigAlgOID); named {
		if !digestKnown || namedDigest != digestFromInfo {
			return 0, 0, false
		}
		if namedDigest == crypto.MD5 {
			if !keyIsRSA {
				return 0, 0, false
			}
			return 0, crypto.MD5, true
		}
		return namedAlgo, namedDigest, true
	}
	// A bare key-type OID (rsaEncryption, id-ecPublicKey, or any OID this
	// package does not specifically recognise): digestAlgorithm decides
	// the hash, and the signer's own key type decides the scheme.
	if !digestKnown {
		return 0, 0, false
	}
	if digestFromInfo == crypto.MD5 {
		if !keyIsRSA {
			return 0, 0, false
		}
		return 0, crypto.MD5, true
	}
	if keyIsRSA {
		switch digestFromInfo {
		case crypto.SHA1:
			return x509.SHA1WithRSA, digestFromInfo, true
		case crypto.SHA256:
			return x509.SHA256WithRSA, digestFromInfo, true
		case crypto.SHA384:
			return x509.SHA384WithRSA, digestFromInfo, true
		case crypto.SHA512:
			return x509.SHA512WithRSA, digestFromInfo, true
		default:
			return 0, 0, false
		}
	}
	switch digestFromInfo {
	case crypto.SHA1:
		return x509.ECDSAWithSHA1, digestFromInfo, true
	case crypto.SHA256:
		return x509.ECDSAWithSHA256, digestFromInfo, true
	case crypto.SHA384:
		return x509.ECDSAWithSHA384, digestFromInfo, true
	case crypto.SHA512:
		return x509.ECDSAWithSHA512, digestFromInfo, true
	default:
		return 0, 0, false
	}
}
