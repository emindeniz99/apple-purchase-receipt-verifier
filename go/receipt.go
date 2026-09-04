package applereceipt

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/chain"
)

// maxEmbeddedCertificates bounds how many certificates a receipt may
// carry.
//
// Genuine receipts embed one to three (the public fixtures carry 1, 3 and
// 3). The bound is enforced before any embedded certificate is decoded,
// because decoding is the expensive part: every embedded certificate is
// parsed and then RSA-checked as a candidate issuer during the path walk,
// so a receipt carrying a thousand of them would cost far more to reject
// than a genuine receipt costs to accept. Ten leaves room for a longer
// Apple chain.
const maxEmbeddedCertificates = 10

// DefaultMaxReceiptBytes is the default ceiling on receipt size.
//
// The largest genuine receipt in this repository's corpus is 79 KB with
// 187 in-app purchases, so a megabyte sits an order of magnitude above
// anything real. It is a port-local defensive bound — no conformance
// verdict depends on it — and a caller with an unusual corpus can raise
// it through ReceiptVerifierOptions.
const DefaultMaxReceiptBytes = 1 << 20

// ReceiptVerifierOptions configures a ReceiptVerifier.
//
// There is deliberately no clock option. Certificate validity on the
// receipt path is judged at the receipt's own creation date (attribute
// 12), and where a receipt carries none, at the system clock. Those are
// the only instants involved, and neither may be movable by a caller: an
// injected clock that could reach them would let a caller authenticate a
// receipt signed under an expired chain.
type ReceiptVerifierOptions struct {
	// TrustedRoots are the pinned anchors. Required, non-empty. Use
	// AppleReceiptRoots() in production.
	TrustedRoots []*x509.Certificate

	// BundleID the receipt must carry. Required.
	BundleID string

	// MaxReceiptBytes is the ceiling on a receipt's DECODED size. It
	// bounds the base64 decode as well as the parse, so an oversized
	// input is rejected without ever being materialized in full. Zero
	// means DefaultMaxReceiptBytes.
	MaxReceiptBytes int
}

// ReceiptVerifier verifies legacy PKCS#7 app receipts entirely offline
// against pinned Apple roots — the server-side port of Apple's
// "Validating receipts on the device" procedure (PLAN.md §2.2).
//
// A ReceiptVerifier is immutable after construction and safe for
// concurrent use by multiple goroutines.
type ReceiptVerifier struct {
	roots           []*x509.Certificate
	bundleID        string
	maxReceiptBytes int
}

// NewReceiptVerifier validates the options and returns a verifier. A
// configuration mistake is a plain error, never a *VerificationError.
func NewReceiptVerifier(opts ReceiptVerifierOptions) (*ReceiptVerifier, error) {
	if len(opts.TrustedRoots) == 0 {
		return nil, errors.New("applereceipt: TrustedRoots must not be empty")
	}
	for i, root := range opts.TrustedRoots {
		if root == nil {
			return nil, errors.New("applereceipt: TrustedRoots contains a nil certificate at index " + itoa(i))
		}
	}
	if opts.BundleID == "" {
		return nil, errors.New("applereceipt: BundleID is required")
	}
	if opts.MaxReceiptBytes < 0 {
		return nil, errors.New("applereceipt: MaxReceiptBytes must not be negative")
	}
	maxBytes := opts.MaxReceiptBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxReceiptBytes
	}
	return &ReceiptVerifier{
		roots:           append([]*x509.Certificate(nil), opts.TrustedRoots...),
		bundleID:        opts.BundleID,
		maxReceiptBytes: maxBytes,
	}, nil
}

// Verify verifies a receipt in its DER form and checks the bundle id.
func (v *ReceiptVerifier) Verify(receipt []byte) (*AppReceipt, error) {
	return v.verify(func() []byte { return receipt }, nil, false)
}

// VerifyWithDeviceGUID verifies a receipt in its DER form, checks the
// bundle id, and additionally enforces the device binding:
// SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) must equal attribute 5.
//
// The check is optional (PLAN.md D4) because a server does not always
// have the device's identifierForVendor.
func (v *ReceiptVerifier) VerifyWithDeviceGUID(receipt, deviceGUID []byte) (*AppReceipt, error) {
	return v.verify(func() []byte { return receipt }, deviceGUID, true)
}

// VerifyBase64 verifies a receipt in the base64 form clients transmit.
//
// MaxReceiptBytes bounds the decode as well as the parse, so an
// arbitrarily long string costs no more than an at-the-ceiling one.
func (v *ReceiptVerifier) VerifyBase64(receipt string) (*AppReceipt, error) {
	return v.verify(func() []byte { return decodeBase64(receipt, v.maxReceiptBytes) }, nil, false)
}

// VerifyBase64WithDeviceGUID verifies a base64 receipt and enforces the
// device binding. Every input form is reachable with and without the
// device GUID.
func (v *ReceiptVerifier) VerifyBase64WithDeviceGUID(receipt string, deviceGUID []byte) (*AppReceipt, error) {
	return v.verify(func() []byte { return decodeBase64(receipt, v.maxReceiptBytes) }, deviceGUID, true)
}

// verify takes the input as a thunk so that decoding happens INSIDE the
// panic containment, not in the caller's frame: every failure on a public
// entry point, decoder included, is then a typed *VerificationError.
func (v *ReceiptVerifier) verify(decode func() []byte, deviceGUID []byte, checkDevice bool) (receipt *AppReceipt, err error) {
	defer containPanic(ReasonInvalidReceiptFormat, &err, func() { receipt = nil })

	fields, err := verifyReceiptCore(decode(), v.roots, v.maxReceiptBytes)
	if err != nil {
		return nil, err
	}
	if fields.BundleID != v.bundleID {
		return nil, newError(ReasonWrongBundleID, "receipt bundle id is not the configured one")
	}
	if checkDevice {
		if err := verifyDeviceHash(fields, deviceGUID); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

// VerifyReceiptCore verifies a receipt's chain and CMS signature and
// returns its fields — WITHOUT checking the bundle id.
//
// It is the primitive under both ReceiptVerifier and
// VerifyReceiptEndpoint (which, like Apple's endpoint, accepts any
// bundle). Callers that unlock products with the result must compare
// AppReceipt.BundleID themselves, or use ReceiptVerifier, which does it
// for them.
//
// It takes no clock, for the reason documented on ReceiptVerifierOptions.
func VerifyReceiptCore(receipt []byte, trustedRoots []*x509.Certificate) (result *AppReceipt, err error) {
	defer containPanic(ReasonInvalidReceiptFormat, &err, func() { result = nil })

	if len(trustedRoots) == 0 {
		return nil, errors.New("applereceipt: trustedRoots must not be empty")
	}
	return verifyReceiptCore(receipt, trustedRoots, DefaultMaxReceiptBytes)
}

func verifyReceiptCore(receipt []byte, roots []*x509.Certificate, maxBytes int) (*AppReceipt, error) {
	if len(receipt) == 0 {
		return nil, newError(ReasonInvalidReceiptFormat, "receipt is empty")
	}
	if len(receipt) > maxBytes {
		return nil, newError(ReasonInvalidReceiptFormat,
			"receipt exceeds the %d byte limit", maxBytes)
	}
	cms, err := parseCMS(receipt)
	if err != nil {
		return nil, wrapError(ReasonInvalidReceiptFormat, err, "receipt is not a parseable CMS SignedData")
	}

	// The payload is parsed before anything is verified, because the
	// creation date is the instant the chain's validity is judged at.
	// NOTHING from it is returned or acted on until every check below
	// passes.
	fields, err := parseReceiptPayload(cms.content)
	if err != nil {
		return nil, err
	}
	// A receipt with no creation date falls back to the SYSTEM clock,
	// never to an injected one — which is why this path takes no clock.
	at := time.Now()
	if fields.CreationDate != nil {
		at = *fields.CreationDate
	}

	if len(cms.certificates) > maxEmbeddedCertificates {
		return nil, newError(ReasonInvalidChain,
			"receipt embeds more than %d certificates", maxEmbeddedCertificates)
	}
	embedded := make([]*x509.Certificate, 0, len(cms.certificates))
	for i, raw := range cms.certificates {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			// Fatal, not skipped. The certificate bag is the one part of
			// a receipt the SignerInfo signature does not cover, so an
			// attacker can rewrite it on a genuine receipt for free.
			// Skipping an entry we cannot read would mean returning
			// "verified" about bytes we could not parse — and it is a
			// divergence: Java, Node, Python and Swift all treat a
			// non-decodable entry as fatal. Reject what you cannot
			// represent.
			return nil, wrapError(ReasonInvalidReceiptFormat, err,
				"embedded certificate %d is not a parseable X.509 certificate", i)
		}
		embedded = append(embedded, cert)
	}
	signer := findSignerCertificate(embedded, cms.signerInfo)
	if signer == nil {
		return nil, newError(ReasonInvalidReceiptFormat, "signer certificate is not embedded in the receipt")
	}

	// Chain BEFORE the marker OID (PLAN.md §2.2 step 3), so a receipt
	// signed by a foreign chain reports INVALID_CHAIN rather than
	// INVALID_CERTIFICATE_PURPOSE.
	if err := chain.BuildAndValidatePath(signer, embedded, roots, at); err != nil {
		return nil, err
	}
	if !hasExtension(signer, oidAppleLeafMarker) {
		return nil, newError(ReasonInvalidCertificatePurpose,
			"receipt signer lacks Apple receipt-signing marker OID %s", oidAppleLeafMarker)
	}
	if err := verifyCMSSignature(cms, signer); err != nil {
		return nil, err
	}
	return fields, nil
}

// findSignerCertificate resolves the SignerInfo's issuerAndSerialNumber
// against the embedded certificates: the issuer Name by exact DER bytes,
// the serial by numeric value so a leading padding octet cannot make two
// encodings of the same serial look different.
func findSignerCertificate(embedded []*x509.Certificate, info cmsSignerInfo) *x509.Certificate {
	serial := derInteger(info.serialContents)
	for _, cert := range embedded {
		if bytes.Equal(cert.RawIssuer, info.issuerRaw) && cert.SerialNumber.Cmp(serial) == 0 {
			return cert
		}
	}
	return nil
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

func verifyCMSSignature(cms *parsedCMS, signer *x509.Certificate) error {
	if _, ok := signer.PublicKey.(*rsa.PublicKey); !ok {
		return newError(ReasonInvalidSignature, "receipt signer key is not RSA")
	}
	var algorithm x509.SignatureAlgorithm
	var digest func([]byte) []byte
	switch {
	case cms.signerInfo.digestOID.Equal(oidSHA1):
		algorithm = x509.SHA1WithRSA
		digest = func(b []byte) []byte { sum := sha1.Sum(b); return sum[:] }
	case cms.signerInfo.digestOID.Equal(oidSHA256):
		algorithm = x509.SHA256WithRSA
		digest = func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }
	default:
		// Only the digests Apple uses for receipts, matching the other
		// ports; anything else is a receipt we will not guess about.
		return newError(ReasonInvalidReceiptFormat, "unsupported receipt digest algorithm")
	}

	signed := cms.content
	if cms.signerInfo.signedAttrs != nil {
		// With signed attributes the signature covers the attributes, so
		// the link to the content is the messageDigest attribute. Without
		// checking it, an attacker could keep a genuine signature and
		// swap the content.
		messageDigest, err := findMessageDigestAttribute(cms.signerInfo.signedAttrs)
		if err != nil {
			return wrapError(ReasonInvalidReceiptFormat, err, "malformed signed attributes")
		}
		if messageDigest == nil || subtle.ConstantTimeCompare(messageDigest, digest(cms.content)) != 1 {
			return newError(ReasonInvalidSignature, "messageDigest attribute does not match the content")
		}
		signed, err = signedAttrsSignedBytes(cms.signerInfo.signedAttrs)
		if err != nil {
			return wrapError(ReasonInvalidReceiptFormat, err, "malformed signed attributes")
		}
	}
	if err := signer.CheckSignature(algorithm, signed, cms.signerInfo.signature); err != nil {
		return wrapError(ReasonInvalidSignature, err, "CMS signature check failed")
	}
	return nil
}

// verifyDeviceHash enforces the optional device binding.
//
// The comparison is constant time: the expected hash comes from the
// receipt and the computed one from a caller-supplied GUID, and a
// byte-by-byte early exit would leak how much of a guessed GUID was
// right.
func verifyDeviceHash(fields *AppReceipt, deviceGUID []byte) error {
	if fields.OpaqueValue == nil || fields.SHA1Hash == nil || fields.BundleIDBytes == nil {
		return newError(ReasonDeviceHashMismatch,
			"receipt lacks the attributes the device-hash check needs")
	}
	h := sha1.New()
	h.Write(deviceGUID)
	h.Write(fields.OpaqueValue)
	h.Write(fields.BundleIDBytes)
	if subtle.ConstantTimeCompare(h.Sum(nil), fields.SHA1Hash) != 1 {
		return newError(ReasonDeviceHashMismatch, "computed device hash does not match attribute 5")
	}
	return nil
}
