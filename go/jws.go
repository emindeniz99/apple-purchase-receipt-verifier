package applereceipt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/chain"
)

// Apple marker OIDs.
//
// These are what stop a "valid Apple-issued certificate, wrong purpose"
// forgery: without them, any developer's own Apple Distribution leaf,
// which chains through the same WWDR intermediate to the same pinned
// root, could sign an accepted payload. The receipt path checks the
// leaf marker too, and, new in 0.7, the WWDR marker on its intermediate.
var (
	// oidAppleLeafMarker is 1.2.840.113635.100.6.11.1, the App Store /
	// receipt-signing marker on the leaf.
	oidAppleLeafMarker = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	// oidAppleWWDRMarker is 1.2.840.113635.100.6.2.1, the Worldwide
	// Developer Relations intermediate CA marker.
	oidAppleWWDRMarker = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

// MaxJWSBytes bounds the compact JWS a verifier will look at, in UTF-8
// bytes, checked before the string is split or any segment decoded: a
// hostile multi-megabyte "JWS" is refused before it is base64-decoded and
// JSON-parsed. 256 KiB is the Java, PHP and Python ports' number; Apple's
// payloads are a few kilobytes.
const MaxJWSBytes = 262_144

// MaxJSONNestingDepth is how many arrays and objects a JWS header, a JWS
// payload or an endpoint request body may hold open at once, counted
// before the JSON is parsed (docs/design/0.7-api.md, Bounds).
const MaxJSONNestingDepth = 64

// MaxJSONMemberNameLength is how many characters a JSON object member
// name may hold, in a JWS header, a JWS payload or an endpoint request
// body, counted before the JSON is parsed (docs/design/0.7-api.md,
// Bounds). It bounds member NAMES only, never string values: a
// receipt-data or productId value of any length is unaffected.
const MaxJSONMemberNameLength = 50_000

// MaxJSONNumberDigits is how many digits a JSON number literal may hold,
// in the same three places, counted before the JSON is parsed
// (docs/design/0.7-api.md, Bounds).
const MaxJSONNumberDigits = 1_000

// JSONPayload is a verified JWS payload: the JSON object Apple signed,
// unchanged.
//
// The library reads only signedDate from it. Parse JSON() with the JSON
// library of your choice, into a struct declaring the claims you use;
// Apple's claims are epoch milliseconds already. No typed JWS models ship
// with this library: Apple's own app-store-server-library publishes the
// transaction, renewal and notification model classes for languages that
// have one.
type JSONPayload struct {
	json string
}

// NewJSONPayload wraps json as a JSONPayload. Public so callers can build
// one in their own tests.
func NewJSONPayload(json string) *JSONPayload { return &JSONPayload{json: json} }

// JSON is the verified payload, exactly as signed.
func (p *JSONPayload) JSON() string { return p.json }

// String is JSON.
func (p *JSONPayload) String() string { return p.json }

// verifySignedData is Verifier.VerifySignedData's implementation.
//
// A broken outer structure fails as ReasonMalformed before any
// cryptography: not three segments, a segment that is not canonical
// base64url, a header that is not a JSON object, an alg other than ES256,
// an x5c that is not three strings. A payload that does not parse as a
// JSON object is not reported there: it is carried past the chain and
// signature checks with the clock standing in for its signing date, and
// fails as ReasonInvalidSignature if the signature does not verify,
// ReasonUnreadablePayload if it does. Nothing unverified gets to decide
// which of the two a caller sees.
func verifySignedData(jws string, anchors []*x509.Certificate, ctx *verifyCtx) (*JSONPayload, error) {
	if jws == "" {
		return nil, newError(ReasonMalformed, "jws is empty")
	}
	if len(jws) > MaxJWSBytes {
		return nil, newError(ReasonTooLarge, "jws exceeds the maximum accepted size of %d bytes", MaxJWSBytes)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, newError(ReasonMalformed, "expected 3 dot-separated segments, got %d", len(parts))
	}
	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// Strict, not lenient: a lenient reading would give one Apple-signed
	// payload unboundedly many accepted wire forms, and the signature
	// segment is not covered by the signature at all.
	headerBytes, err := decodeBase64URLStrict(headerB64)
	if err != nil {
		return nil, wrapError(ReasonMalformed, err, "header is not canonical base64url")
	}
	payloadBytes, err := decodeBase64URLStrict(payloadB64)
	if err != nil {
		return nil, wrapError(ReasonMalformed, err, "payload is not canonical base64url")
	}
	signature, err := decodeBase64URLStrict(signatureB64)
	if err != nil {
		return nil, wrapError(ReasonMalformed, err, "signature is not canonical base64url")
	}

	alg, x5c, herr := readJWSHeader(headerBytes)
	if herr != nil {
		return nil, herr
	}
	if alg != "ES256" {
		return nil, newError(ReasonMalformed, "alg must be ES256")
	}
	if len(x5c) != 3 {
		return nil, newError(ReasonMalformed, "x5c must contain exactly 3 certificates")
	}
	leaf, err := parseX5CCertificate(x5c[0], "leaf")
	if err != nil {
		return nil, err
	}
	intermediate, err := parseX5CCertificate(x5c[1], "intermediate")
	if err != nil {
		return nil, err
	}
	// All three entries are parsed, and the third is still trusted by
	// nobody: it is the JWS-supplied root, it is not a trust anchor and
	// it is not byte-compared to ours, so an attacker swapping in their
	// own self-signed "root" changes nothing. What parsing it settles is
	// only whether the entry IS a certificate.
	if _, err := parseX5CCertificate(x5c[2], "root"); err != nil {
		return nil, err
	}

	payloadJSON, signedDateMs, perr := readJWSPayload(payloadBytes)
	// Chain validity is judged at the payload's signing date, so a
	// payload signed with a since-rotated certificate keeps verifying. A
	// payload stating no usable date of its own is judged at the clock.
	var atMillis int64
	if signedDateMs != nil {
		atMillis = *signedDateMs
	} else {
		now, cerr := ctx.now()
		if cerr != nil {
			return nil, cerr
		}
		atMillis = now
	}
	if cerr := chain.ValidatePair(leaf, intermediate, anchors, millisToTime(atMillis)); cerr != nil {
		return nil, cerr
	}
	// The marker OIDs after the chain (owner, 2026-09-27): a chain to a
	// foreign root is ReasonUntrustedChain whatever it carries, and only
	// a pinned chain can be the wrong kind of Apple certificate. Still
	// before the leaf's key checks the JWS signature.
	if !hasExtension(leaf, oidAppleLeafMarker) {
		return nil, newError(ReasonInvalidCertificatePurpose,
			"leaf certificate lacks Apple marker OID %s", oidAppleLeafMarker)
	}
	if !hasExtension(intermediate, oidAppleWWDRMarker) {
		return nil, newError(ReasonInvalidCertificatePurpose,
			"intermediate certificate lacks Apple marker OID %s", oidAppleWWDRMarker)
	}
	if serr := verifyES256(leaf, headerB64+"."+payloadB64, signature); serr != nil {
		return nil, serr
	}
	ctx.enter(stageAfterSignature)
	if perr != nil {
		return nil, wrapError(ReasonUnreadablePayload, perr, "signed payload is not a JSON object")
	}
	return &JSONPayload{json: payloadJSON}, nil
}

// readJWSHeader reads the last alg and x5c top-level members of the
// header, a duplicate member keeps the last one, as a map would. The
// header is outer structure, so anything that stops the read is
// ReasonMalformed: bytes that are not strict UTF-8, a byte-order mark
// (RFC 8259 §8.1 forbids one), a document that does not start with an
// object, or anything but whitespace after it.
func readJWSHeader(b []byte) (alg string, x5c []string, err error) {
	if jsonBoundsExceeded(b, MaxJSONNestingDepth, MaxJSONMemberNameLength, MaxJSONNumberDigits) {
		return "", nil, newError(ReasonMalformed, "header exceeds a JSON bound (nesting, member name length, or number length)")
	}
	object, derr := decodeStrictJSONObject(b)
	if derr != nil {
		return "", nil, wrapError(ReasonMalformed, derr, "header is not a JSON object")
	}
	if value, ok := object["alg"].(string); ok {
		alg = value
	}
	if list, ok := object["x5c"].([]any); ok {
		entries := make([]string, 0, len(list))
		for _, entry := range list {
			text, ok := entry.(string)
			if !ok {
				return alg, nil, nil
			}
			entries = append(entries, text)
		}
		x5c = entries
	}
	return alg, x5c, nil
}

// readJWSPayload returns the payload text and its last top-level
// signedDate, or why it is not a JSON object in UTF-8. Reading it never
// fails verification by itself: the caller carries a non-nil err past
// the chain and signature checks.
//
// A signedDate that is not a number, or is a number no instant can hold
// (1e300), counts as not stated: the clock stands in for it (owner,
// 2026-09-27).
func readJWSPayload(b []byte) (payloadJSON string, signedDateMs *int64, err error) {
	payloadJSON = string(b)
	if jsonBoundsExceeded(b, MaxJSONNestingDepth, MaxJSONMemberNameLength, MaxJSONNumberDigits) {
		return payloadJSON, nil, errors.New("payload exceeds a JSON bound (nesting, member name length, or number length)")
	}
	object, derr := decodeStrictJSONObject(b)
	if derr != nil {
		return payloadJSON, nil, derr
	}
	if number, ok := object["signedDate"].(json.Number); ok {
		if ms, ok := integralMillis(number); ok {
			signedDateMs = &ms
		}
	}
	return payloadJSON, signedDateMs, nil
}

// decodeStrictJSONObject decodes exactly one JSON object from b: strict
// UTF-8, no byte-order mark, and only whitespace after the object.
func decodeStrictJSONObject(b []byte) (map[string]any, error) {
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("a byte order mark is not allowed")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("not valid UTF-8")
	}
	claims, err := decodeJSONObject(b)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func parseX5CCertificate(text, what string) (*x509.Certificate, error) {
	// decodeBase64 refuses anything but canonical standard base64 as nil,
	// which the parser below reports as not a certificate. The whole
	// compact JWS is already under MaxJWSBytes, which bounds the decode.
	decoded := decodeBase64(text)
	if decoded == nil {
		return nil, newError(ReasonInvalidCertificate, "x5c %s entry is not valid base64", what)
	}
	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, wrapError(ReasonInvalidCertificate, err, "x5c %s entry is not a valid certificate", what)
	}
	if !certificateSignatureIsCanonicallyEncoded(decoded) {
		return nil, newError(ReasonInvalidCertificate,
			"x5c %s entry's signature is not canonically encoded", what)
	}
	return cert, nil
}

// hasExtension reports whether the certificate carries an extension with
// the given OID. It reads cert.Extensions, the raw list crypto/x509
// always populates, so an extension Go does not model is still visible.
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// verifyES256 checks the RFC 7515 signature over ASCII(header "." payload)
// with the leaf's P-256 key. The signature is raw r||s, 64 bytes.
func verifyES256(leaf *x509.Certificate, signingInput string, signature []byte) error {
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return newError(ReasonInvalidSignature, "leaf key is not EC")
	}
	if key.Curve != elliptic.P256() {
		return newError(ReasonInvalidSignature, "leaf key is not on P-256")
	}
	if len(signature) != 64 {
		return newError(ReasonInvalidSignature, "ES256 signature must be 64 bytes, got %d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(key, digest[:], r, s) {
		return newError(ReasonInvalidSignature, "ES256 signature check failed")
	}
	return nil
}

// --- JSON number reading --------------------------------------------------

// int64 bounds as float64. Both are exactly representable, and the upper
// one is the first float above math.MaxInt64, so the test is half-open.
const (
	minInt64AsFloat          = -9223372036854775808.0
	maxInt64ExclusiveAsFloat = 9223372036854775808.0
)

// integralMillis reads a JSON number as an int64 claim: a literal integer
// is read directly; a number with a fraction or an exponent is read as a
// float64 and truncated toward zero when it lies within the int64 range.
// Anything else (1e300, say) is not representable and (0, false).
//
// json.Number.Int64 parses the literal spelling, so it refuses every
// number that is not a bare integer even when the value it names fits
// comfortably (1722945600000.0, 1.7229456e12). JSON does not distinguish
// integers from floats and every other port reads the value rather than
// its spelling, so this falls back to the float reading rather than
// reading a signedDate's meaning off how it happened to be written.
func integralMillis(number json.Number) (int64, bool) {
	if value, err := number.Int64(); err == nil {
		return value, true
	}
	value, err := number.Float64()
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	if value < minInt64AsFloat || value >= maxInt64ExclusiveAsFloat {
		return 0, false
	}
	return int64(value), true
}
