package applereceipt

import (
	"bytes"
	"crypto"
	"crypto/md5" //nolint:gosec // accepted only under a pinned, already-vouched-for signer (Q15)
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Apple's legacy receipt digest
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/chain"
	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/der"
)

// maxEmbeddedCertificates bounds how many certificates a receipt may
// carry (docs/design/0.7-api.md, Bounds). Genuine receipts embed one to
// three. The bound is enforced before any embedded certificate is
// decoded, because decoding is the expensive part: every embedded
// certificate is parsed and then tried as a candidate issuer during the
// top-down walk, so a receipt carrying a thousand of them would cost far
// more to reject than a genuine receipt costs to accept.
const maxEmbeddedCertificates = 10

// maxSignerInfos bounds how many SignerInfos a receipt may carry. A fifth
// fails as ReasonMalformed before any signature is checked.
const maxSignerInfos = 4

// MaxReceiptBytes is the ceiling on receipt size: on the base64 string,
// in UTF-8 bytes, before it is decoded. It is 3 MiB, Apple's own limit,
// fixed and the same in every port of this library. Measured on
// 2026-09-23 against both of Apple's verifyReceipt endpoints, a request
// body of 3,145,728 bytes is answered and one of 3,145,729 bytes gets
// HTTP 413, and no receipt Apple accepts can be larger than the request
// that carries it.
const MaxReceiptBytes = 3_145_728

// verifyReceipt is Verifier.VerifyReceipt's implementation.
func verifyReceipt(base64Text string, anchors []*x509.Certificate, ctx *verifyCtx) (*ReceiptPayload, error) {
	if base64Text == "" {
		return nil, newError(ReasonMalformed, "receipt is empty")
	}
	// Checked before the decode, which would otherwise allocate the bytes
	// it decodes to.
	if len(base64Text) > MaxReceiptBytes {
		return nil, newError(ReasonTooLarge,
			"receipt exceeds the maximum accepted size of %d bytes", MaxReceiptBytes)
	}
	receiptDER, derr := receiptDataFromBase64(base64Text)
	if derr != nil {
		return nil, derr
	}
	content, err := verifyReceiptSignature(receiptDER, anchors, ctx)
	if err != nil {
		return nil, err
	}
	ctx.enter(stagePayloadParse)
	// A trusted signer signed these bytes, so a payload this library
	// cannot read is the library's failure or a format Apple added, not
	// the client's: ReasonUnreadablePayload, never ReasonMalformed, which
	// the endpoint answers as 21002 and an app server reads as "deny".
	payload, perr := parseReceiptPayload(content)
	if perr != nil {
		return nil, wrapError(ReasonUnreadablePayload, perr, "signed receipt content could not be read")
	}
	ctx.enter(stageAfterSignature)
	return payload, nil
}

// verifyReceiptSignature is every check up to and including a signature;
// it returns the signed content, not yet decoded.
func verifyReceiptSignature(receiptDER []byte, anchors []*x509.Certificate, ctx *verifyCtx) ([]byte, error) {
	cms, err := parseCMS(receiptDER)
	if err != nil {
		return nil, wrapError(ReasonMalformed, err, "receipt is not a parseable CMS SignedData")
	}
	if len(cms.signerInfoNodes) > maxSignerInfos {
		return nil, newError(ReasonMalformed,
			"receipt carries %d SignerInfos, more than the maximum of %d",
			len(cms.signerInfoNodes), maxSignerInfos)
	}
	// Bounded here, before a single embedded certificate is decoded or
	// tried as an issuer, all of which an unverified receipt would
	// otherwise get to pay for out of the caller's CPU.
	if len(cms.certificates) > maxEmbeddedCertificates {
		return nil, newError(ReasonMalformed,
			"receipt embeds %d certificates, more than the maximum of %d",
			len(cms.certificates), maxEmbeddedCertificates)
	}

	// Only the creation date is read before trust is established, because
	// it is the instant the chain's validity is judged at; nothing else
	// in the payload is decoded until the chain and the signature have
	// passed. A date that is missing, empty, unreadable or stated twice
	// cannot blame anyone yet, so it only moves the chain instant to the
	// clock and never rejects by itself.
	creationDateMs := readCreationDateMs(cms.content)

	// A certificate that crypto/x509 parses but whose signature BIT
	// STRING is not canonically encoded is fatal wherever it sits,
	// signer or stranger (owner, 2026-09-27): unlike a certificate that
	// simply fails to parse at all (noise a pinned root never vouches
	// for, and so never reached (Q16)), this is a well-formed-looking
	// certificate whose signature crypto/x509 silently reinterprets as
	// different bytes than what was actually signed, which is exactly
	// the class of platform-parser leniency this library refuses to
	// trust.
	for _, entry := range cms.certificates {
		if _, err := x509.ParseCertificate(entry); err == nil && !certificateSignatureIsCanonicallyEncoded(entry) {
			return nil, newError(ReasonMalformed,
				"an embedded certificate's signature is not canonically encoded")
		}
	}
	decoded, unreadable := decodeEmbeddedCertificates(cms.certificates)

	signerInfos := make([]cmsSignerInfo, 0, len(cms.signerInfoNodes))
	for _, node := range cms.signerInfoNodes {
		info, serr := parseSignerInfo(node)
		if serr != nil {
			return nil, wrapError(ReasonMalformed, serr, "malformed SignerInfo")
		}
		signerInfos = append(signerInfos, info)
	}

	// Signer-independent, so the top-down walk runs once for every
	// receipt, lazily, the first time a SignerInfo names a readable
	// signer, rather than once per SignerInfo.
	var authenticated *chain.Authenticated
	var firstFailure error
	for _, info := range signerInfos {
		candidates, unreadableErr := matchingSignerCertificates(info, decoded, unreadable)
		if len(candidates) == 0 {
			serr := unreadableErr
			if serr == nil {
				serr = newError(ReasonMalformed, "signer certificate is not embedded in the receipt")
			}
			if firstFailure == nil {
				firstFailure = serr
			}
			continue
		}
		atMillis := creationDateMs
		if atMillis == nil {
			now, cerr := ctx.now()
			if cerr != nil {
				return nil, cerr
			}
			atMillis = &now
		}
		if authenticated == nil {
			authenticated = chain.AuthenticatedTopDown(decoded, anchors)
		}
		// Every embedded certificate naming this SignerInfo is tried
		// (owner, 2026-09-27): a name (issuer + serial) is not a key, so
		// a stranger certificate that merely claims the genuine signer's
		// identity must not be able to shadow it. A candidate's key is
		// used only after ITS OWN chain to a pinned root has passed.
		for _, signer := range candidates {
			verr := verifySignerAndSignature(cms, info, signer, authenticated, anchors, *atMillis)
			if verr == nil {
				return cms.content, nil
			}
			// Every SignerInfo signs the same content, so another one
			// passing proves the same bytes; only when none does is the
			// first one's failure the verdict.
			if firstFailure == nil {
				firstFailure = verr
			}
		}
	}
	if firstFailure == nil {
		firstFailure = newError(ReasonMalformed, "no signer info")
	}
	return nil, firstFailure
}

// decodeEmbeddedCertificates parses every embedded certificate that will
// parse, and keeps the raw bytes of the ones that will not: a stranger a
// pinned root does not vouch for is simply excluded from the top-down
// walk (Q16), never fatal on its own.
func decodeEmbeddedCertificates(raw [][]byte) (decoded []*x509.Certificate, unreadable [][]byte) {
	decoded = make([]*x509.Certificate, 0, len(raw))
	for _, entry := range raw {
		cert, err := x509.ParseCertificate(entry)
		if err != nil {
			unreadable = append(unreadable, entry)
			continue
		}
		decoded = append(decoded, cert)
	}
	return decoded, unreadable
}

// certificateSignatureIsCanonicallyEncoded reports whether raw's outer
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
// signatureValue BIT STRING }'s signatureValue declares zero unused bits,
// as every genuine X.509 signature (a whole number of octets) does.
//
// crypto/x509 parses a non-canonical encoding anyway: Go's BIT STRING
// reader right-aligns the value by the declared unused-bit count rather
// than rejecting a nonzero count on an octet-aligned value, which turns
// "1 unused bit" into a 1-bit rotation of every byte of cert.Signature,
// silently producing a different (and here, cryptographically dead)
// value rather than an error. That is exactly the shape of divergence
// this bound exists to catch (PLAN.md's "never trust the platform
// parser's leniency"): a certificate whose signature bytes decode to
// something other than what was actually signed is unreadable, not
// merely differently signed, whether or not crypto/rsa or crypto/ecdsa
// happens to reject the rotated bytes on every input.
func certificateSignatureIsCanonicallyEncoded(raw []byte) bool {
	node, err := der.Parse(raw)
	if err != nil || node.Tag != der.TagSequence || len(node.Children) < 3 {
		return true // structurally unrecognisable; x509.ParseCertificate's verdict stands
	}
	signature := node.Children[2]
	if signature.Tag != der.TagBitString || len(signature.Contents) == 0 {
		return true
	}
	return signature.Contents[0] == 0
}

// matchingSignerCertificates returns every embedded, decoded certificate
// whose issuer and serial number match info's SignerIdentifier: a name,
// not a key, so more than one can match (owner, 2026-09-27: a stranger
// certificate claiming the genuine signer's identity, ahead of it in the
// bag, must not be able to shadow it; the caller tries every candidate
// and uses a key only once ITS OWN chain has passed).
//
// unreadableSignerErr is set when no candidate decoded, but an entry that
// does not decode carries the same identity: ReasonInvalidCertificate, as
// an unreadable x5c entry is on the JWS path. An unreadable entry that is
// NOT the signer is not blamed on the receipt at all: a certificate that
// genuinely fails to parse is exactly the kind of stranger no pinned root
// ever vouches for, so it is simply excluded from the top-down walk (Q16)
// like any other stranger, the same as a certificate that parses fine but
// names nobody real. (A parseable-but-non-canonically-encoded certificate
// is a different case, and is fatal wherever it sits: checked by the
// caller before this function ever runs.)
func matchingSignerCertificates(info cmsSignerInfo, decoded []*x509.Certificate, unreadable [][]byte) (candidates []*x509.Certificate, unreadableSignerErr error) {
	serial := derInteger(info.serialContents)
	for _, cert := range decoded {
		if bytes.Equal(cert.RawIssuer, info.issuerRaw) && cert.SerialNumber.Cmp(serial) == 0 {
			candidates = append(candidates, cert)
		}
	}
	// Which entry an unreadable one is has to be read out of the entry
	// itself: an identity is still legible in bytes that are not a
	// certificate all the way down.
	for _, raw := range unreadable {
		if namesTheSigner(raw, info) {
			unreadableSignerErr = newError(ReasonInvalidCertificate, "receipt signer certificate does not decode")
			break
		}
	}
	return candidates, unreadableSignerErr
}

// namesTheSigner reports whether raw carries the issuer Name and
// serialNumber the SignerInfo names, read as generic ASN.1 rather than as
// an X.509 certificate — which is the whole point: the entries this is
// asked about are the ones x509.ParseCertificate refused, and an identity
// is still legible in bytes that are not a certificate all the way down.
//
// TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber
// INTEGER, signature AlgorithmIdentifier, issuer Name, ... } — anything
// that does not have that shape is not an identity, and cannot match.
func namesTheSigner(raw []byte, info cmsSignerInfo) bool {
	certificate, err := der.Parse(raw)
	if err != nil || certificate.Tag != der.TagSequence {
		return false
	}
	tbs := der.Child(certificate, 0)
	if tbs == nil || tbs.Tag != der.TagSequence {
		return false
	}
	index := 0
	if version := der.Child(tbs, 0); version != nil && version.Tag == der.TagContext0 {
		index = 1 // the EXPLICIT version, absent in a v1 certificate
	}
	serial := der.Child(tbs, index)
	issuer := der.Child(tbs, index+2) // index+1 is the signature AlgorithmIdentifier
	if serial == nil || serial.Tag != der.TagInteger || issuer == nil ||
		issuer.Tag != der.TagSequence {
		return false
	}
	return bytes.Equal(issuer.Raw, info.issuerRaw) &&
		derInteger(serial.Contents).Cmp(derInteger(info.serialContents)) == 0
}

// derInteger reads DER INTEGER contents, honouring two's complement.
func derInteger(contents []byte) *big.Int {
	if len(contents) == 0 {
		return big.NewInt(0)
	}
	value := new(big.Int).SetBytes(contents)
	if contents[0]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(len(contents)*8)))
	}
	return value
}

// millisToTime converts epoch milliseconds to a time.Time in UTC.
func millisToTime(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

// verifySignerAndSignature validates the chain, the Apple marker OIDs and
// the CMS signature for one SignerInfo whose signer certificate resolved.
func verifySignerAndSignature(cms *parsedCMS, info cmsSignerInfo, signer *x509.Certificate,
	authenticated *chain.Authenticated, anchors []*x509.Certificate, atMillis int64) error {
	at := millisToTime(atMillis)
	// Chain BEFORE the marker OID (PLAN.md §2.2 step 3), so a receipt
	// signed by a foreign chain reports ReasonUntrustedChain rather than
	// ReasonInvalidCertificatePurpose.
	path, err := chain.BuildAndValidatePath(signer, authenticated, anchors, at)
	if err != nil {
		return err
	}
	if !hasExtension(signer, oidAppleLeafMarker) {
		return newError(ReasonInvalidCertificatePurpose,
			"receipt signer lacks Apple receipt-signing marker OID %s", oidAppleLeafMarker)
	}
	// The certificate above the signer on the path. A signer issued
	// straight by a root has no WWDR certificate to carry the marker
	// (owner, 2026-09-27: the intermediate marker check is new in 0.7,
	// bringing the receipt path level with the JWS path, which has
	// always checked both).
	if len(path) < 2 || !hasExtension(path[1], oidAppleWWDRMarker) {
		return newError(ReasonInvalidCertificatePurpose,
			"receipt intermediate certificate lacks Apple WWDR marker OID %s", oidAppleWWDRMarker)
	}
	// The chain is checked BEFORE the signature on purpose: checking the
	// signature first would run the attacker's own key (their choice of
	// RSA size and exponent) before anything about it is trusted.
	return verifyCMSSignature(cms, info, signer)
}

// receiptDataFromBase64 is the receipt-data decoder every base64 entry
// point uses: the size cap, then decodeBase64. Exposed to the external
// test package via export_test.go for the shared decodeBase64
// conformance cases, which call it directly rather than through a
// verifier: 0.7 exposes no public decoder.
func receiptDataFromBase64(text string) ([]byte, error) {
	if len(text) > MaxReceiptBytes {
		return nil, newError(ReasonTooLarge, "receipt exceeds the %d byte limit", MaxReceiptBytes)
	}
	receiptDER := decodeBase64(text)
	if receiptDER == nil {
		return nil, newError(ReasonMalformed, "receipt is not canonical standard base64")
	}
	return receiptDER, nil
}

func invalidSignature(format string, args ...any) error {
	return newError(ReasonInvalidSignature, format, args...)
}

// verifyCMSSignature checks a SignerInfo's signature against the signed
// content (or, when present, the signed attributes) using the signer's
// own certificate.
//
// The signer's key type, digest and signature algorithm are not
// restricted beyond what this package's cryptography can check
// (docs/design/0.7-hardening-parity.md, change 3): the signer is already
// pinned to an Apple root and carries Apple's receipt-signing marker, so a
// change of algorithm on Apple's side does not reject genuine receipts.
func verifyCMSSignature(cms *parsedCMS, info cmsSignerInfo, signer *x509.Certificate) error {
	signed := cms.content
	if info.signedAttrs != nil {
		// With signed attributes the signature covers the attributes, so
		// the link to the content is the messageDigest attribute. Without
		// checking it, an attacker could keep a genuine signature and
		// swap the content.
		digest, ddOK := digestFromOID(info.digestOID)
		if !ddOK {
			return invalidSignature("unsupported receipt signer digest algorithm")
		}
		messageDigest, contentType, err := readSignedAttributes(info.signedAttrs)
		if err != nil {
			// A genuine duplicate (RFC 5652 §5.3) is a property of what
			// the signature covers, not an outer shape defect: the
			// verdict is about the signature, INVALID_SIGNATURE.
			return invalidSignature("%v", err)
		}
		computed := digestBytes(digest, cms.content)
		if messageDigest == nil || subtle.ConstantTimeCompare(messageDigest, computed) != 1 {
			return invalidSignature("messageDigest attribute does not match the content")
		}
		// RFC 5652 §11.1: a signed content-type attribute, when present,
		// MUST match encapContentInfo's eContentType.
		if contentType != nil && !bytes.Equal(contentType, cms.eContentType) {
			return invalidSignature("content-type attribute differs from the eContentType")
		}
		signedBytes, serr := signedAttrsSignedBytes(info.signedAttrs)
		if serr != nil {
			return wrapError(ReasonMalformed, serr, "malformed signed attributes")
		}
		signed = signedBytes
	}
	return checkSignerSignature(signer, info, signed)
}

// checkSignerSignature is the cryptographic content of verifyCMSSignature,
// split out so both the signed-attributes and the direct-content paths
// share it.
func checkSignerSignature(signer *x509.Certificate, info cmsSignerInfo, signed []byte) error {
	keyIsRSA := signer.PublicKeyAlgorithm == x509.RSA
	algo, digest, ok := resolveCMSSignatureAlgorithm(info, keyIsRSA)
	if !ok {
		return invalidSignature("unsupported receipt signer digest or signature algorithm")
	}
	if digest == crypto.MD5 {
		return checkMD5Signature(signer, info.signature, signed)
	}
	if !chain.RSAKeyWithinCap(signer) {
		return invalidSignature("receipt signer RSA key exceeds the accepted modulus size")
	}
	if err := signer.CheckSignature(algo, signed, info.signature); err != nil {
		return wrapError(ReasonInvalidSignature, err, "CMS signature check failed")
	}
	return nil
}

// checkMD5Signature verifies an RSASSA-PKCS1-v1_5 signature under MD5
// (Q15: accepted only because a pinned chain, already vouched for and
// carrying Apple's marker OID, signed it). crypto/x509.CheckSignature
// refuses MD5 outright (InsecureAlgorithmError) even through its
// low-level entry point, so crypto/rsa is called one level below x509:
// still a library primitive, never hand-written arithmetic.
func checkMD5Signature(signer *x509.Certificate, signature, signed []byte) error {
	key, ok := signer.PublicKey.(*rsa.PublicKey)
	if !ok {
		return invalidSignature("MD5 receipt signature needs an RSA key")
	}
	if !chain.RSAKeyWithinCap(signer) {
		return invalidSignature("receipt signer RSA key exceeds the accepted modulus size")
	}
	sum := md5.Sum(signed) //nolint:gosec // Q15
	if err := rsa.VerifyPKCS1v15(key, crypto.MD5, sum[:], signature); err != nil {
		return wrapError(ReasonInvalidSignature, err, "CMS signature check failed")
	}
	return nil
}

func digestBytes(digest crypto.Hash, data []byte) []byte {
	switch digest {
	case crypto.SHA1:
		sum := sha1.Sum(data) //nolint:gosec // Apple's legacy receipt digest
		return sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	case crypto.MD5:
		sum := md5.Sum(data) //nolint:gosec // Q15
		return sum[:]
	default:
		return nil
	}
}
