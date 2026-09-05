package applereceipt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/chain"
)

// Apple marker OIDs.
//
// These are what stop a "valid Apple-issued certificate, wrong purpose"
// forgery: without them, any developer's own Apple Distribution leaf —
// which chains through the same WWDR intermediate to the same pinned
// root — could sign an accepted payload. The receipt path checks the same
// leaf OID (PLAN.md D13).
var (
	// oidAppleLeafMarker is 1.2.840.113635.100.6.11.1, the App Store /
	// receipt-signing marker on the leaf.
	oidAppleLeafMarker = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	// oidAppleWWDRMarker is 1.2.840.113635.100.6.2.1, the Worldwide
	// Developer Relations intermediate CA marker.
	oidAppleWWDRMarker = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

// maxJWSBytes bounds the compact JWS a verifier will look at. Apple's
// payloads are a few kilobytes; the largest fixture here is under 3 KB.
// This is a port-local defensive bound (it moves no verdict any
// conformance vector pins) that keeps a hostile multi-megabyte "JWS" from
// being base64-decoded and JSON-parsed before it is rejected.
const maxJWSBytes = 1 << 20

// JWSVerifierOptions configures a JWSVerifier. A plain struct rather than
// functional options, so every knob is greppable and an omitted field is
// visible at the call site.
type JWSVerifierOptions struct {
	// TrustedRoots are the pinned anchors. Required, non-empty. Use
	// AppleJWSRoots() in production. The operating system trust store is
	// never consulted.
	TrustedRoots []*x509.Certificate

	// BundleID every payload must carry. Required.
	BundleID string

	// AcceptedEnvironments is the accept-set (PLAN.md D3). Required,
	// non-empty. Include EnvironmentSandbox on endpoints App Review can
	// reach.
	AcceptedEnvironments []Environment

	// AppAppleID is required to accept a Production AppTransaction, and
	// ignored otherwise.
	AppAppleID *int64

	// MaxSignedAge rejects payloads signed longer ago than this
	// (PLAN.md D5). Zero disables the check.
	MaxSignedAge time.Duration

	// Now is the source of wall-clock time. nil means time.Now.
	//
	// It drives exactly one verdict: the MaxSignedAge staleness rule.
	// Certificate validity is judged at the payload's signing date, and
	// where the payload carries no date, at the system clock — never at
	// Now. A caller injecting a clock to test staleness, or to work
	// around skew, must not thereby be able to accept an expired chain.
	Now func() time.Time
}

// JWSVerifier verifies Apple-signed JWS payloads — StoreKit 2
// jwsRepresentation, signedTransactionInfo / signedRenewalInfo, and App
// Store Server Notifications V2 — entirely offline against pinned Apple
// roots (PLAN.md §2.1).
//
// A JWSVerifier is immutable after construction and safe for concurrent
// use by multiple goroutines.
type JWSVerifier struct {
	roots                []*x509.Certificate
	bundleID             string
	acceptedEnvironments map[Environment]bool
	appAppleID           *int64
	maxSignedAge         time.Duration
	now                  func() time.Time
}

// NewJWSVerifier validates the options and returns a verifier.
//
// A configuration mistake — no anchors, an empty bundle id, an empty or
// unknown accept-set — is a plain error, never a *VerificationError.
// Misconfiguration is a programming bug, not a verification verdict, and
// a caller switching on Reason must never see one.
func NewJWSVerifier(opts JWSVerifierOptions) (*JWSVerifier, error) {
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
	if len(opts.AcceptedEnvironments) == 0 {
		return nil, errors.New("applereceipt: AcceptedEnvironments must not be empty")
	}
	accepted := make(map[Environment]bool, len(opts.AcceptedEnvironments))
	for _, env := range opts.AcceptedEnvironments {
		if !env.known() {
			return nil, errors.New("applereceipt: unknown environment " + string(env))
		}
		accepted[env] = true
	}
	if opts.MaxSignedAge < 0 {
		return nil, errors.New("applereceipt: MaxSignedAge must not be negative")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &JWSVerifier{
		roots:                append([]*x509.Certificate(nil), opts.TrustedRoots...),
		bundleID:             opts.BundleID,
		acceptedEnvironments: accepted,
		appAppleID:           opts.AppAppleID,
		maxSignedAge:         opts.MaxSignedAge,
		now:                  now,
	}, nil
}

// VerifyTransaction verifies a signed transaction and then enforces the
// bundle id and the environment accept-set.
func (v *JWSVerifier) VerifyTransaction(jws string) (payload *TransactionPayload, err error) {
	defer containPanic(ReasonInvalidJWSFormat, &err, func() { payload = nil })

	claims, err := v.verifySignature(jws)
	if err != nil {
		return nil, err
	}
	result := newTransactionPayload(claims)
	if err := v.requireBundleID(result.BundleID); err != nil {
		return nil, err
	}
	if err := v.requireAcceptedEnvironment(result.Environment); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyAppTransaction verifies a signed AppTransaction and then enforces
// the bundle id, the environment (its receiptType claim) and — in
// Production — the app Apple id.
func (v *JWSVerifier) VerifyAppTransaction(jws string) (payload *AppTransactionPayload, err error) {
	defer containPanic(ReasonInvalidJWSFormat, &err, func() { payload = nil })

	claims, err := v.verifySignature(jws)
	if err != nil {
		return nil, err
	}
	result := newAppTransactionPayload(claims)
	if err := v.requireBundleID(result.BundleID); err != nil {
		return nil, err
	}
	if err := v.requireAcceptedEnvironment(result.ReceiptType); err != nil {
		return nil, err
	}
	if err := v.requireAppAppleID(result.ReceiptType, result.AppAppleID); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyRaw verifies the chain and the signature and returns every claim,
// enforcing none of them.
//
// It is for payload types with no dedicated model — renewal info,
// notification envelopes. The caller must check bundleId, environment and
// appAppleId in the returned claims itself.
func (v *JWSVerifier) VerifyRaw(jws string) (claims Claims, err error) {
	defer containPanic(ReasonInvalidJWSFormat, &err, func() { claims = nil })

	return v.verifySignature(jws)
}

// verifySignature runs steps 1-11 of PLAN.md §2.1: shape, header,
// certificates, marker OIDs, payload, chain, signature, staleness. The
// order is normative — a case that pins an early reason must not get a
// later one.
func (v *JWSVerifier) verifySignature(jws string) (Claims, error) {
	if jws == "" {
		return nil, newError(ReasonInvalidJWSFormat, "jws is empty")
	}
	if len(jws) > maxJWSBytes {
		return nil, newError(ReasonInvalidJWSFormat,
			"jws exceeds the %d byte limit", maxJWSBytes)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, newError(ReasonInvalidJWSFormat,
			"expected 3 dot-separated segments, got %d", len(parts))
	}
	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	header, err := parseJSONSegment(headerB64, "header")
	if err != nil {
		return nil, err
	}
	if alg, _ := header["alg"].(string); alg != "ES256" {
		return nil, newError(ReasonInvalidJWSFormat, "alg must be ES256")
	}
	x5c, err := headerX5C(header)
	if err != nil {
		return nil, err
	}

	// x5c[2] is deliberately never parsed. It is the JWS-supplied root; it
	// is not a trust anchor and is not byte-compared to ours, so an
	// attacker swapping in their own self-signed "root" changes nothing.
	leaf, err := parseX5CCertificate(x5c[0], "leaf")
	if err != nil {
		return nil, err
	}
	intermediate, err := parseX5CCertificate(x5c[1], "intermediate")
	if err != nil {
		return nil, err
	}

	// Marker OIDs before the chain on the JWS path (PLAN.md §2.1 step 3);
	// the receipt path is deliberately the other way round.
	if !hasExtension(leaf, oidAppleLeafMarker) {
		return nil, newError(ReasonInvalidCertificatePurpose,
			"leaf certificate lacks Apple marker OID %s", oidAppleLeafMarker)
	}
	if !hasExtension(intermediate, oidAppleWWDRMarker) {
		return nil, newError(ReasonInvalidCertificatePurpose,
			"intermediate certificate lacks Apple marker OID %s", oidAppleWWDRMarker)
	}

	payload, err := parseJSONSegment(payloadB64, "payload")
	if err != nil {
		return nil, err
	}

	signedAt, err := signedAtMillis(payload)
	if err != nil {
		return nil, err
	}
	// The fallback reads the system clock directly, never v.now: an
	// injected clock must not be able to move a certificate-validity
	// verdict (see JWSVerifierOptions.Now).
	effective := time.Now()
	if signedAt != nil {
		effective = time.UnixMilli(*signedAt)
	}
	if err := chain.ValidatePair(leaf, intermediate, v.roots, effective); err != nil {
		return nil, err
	}

	if err := verifyES256(leaf, headerB64+"."+payloadB64, signatureB64); err != nil {
		return nil, err
	}
	if err := v.requireFresh(signedAt); err != nil {
		return nil, err
	}
	return payload, nil
}

func headerX5C(header Claims) ([]string, error) {
	list, ok := header["x5c"].([]any)
	if !ok || len(list) != 3 {
		return nil, newError(ReasonInvalidJWSFormat, "x5c must contain exactly 3 certificates")
	}
	out := make([]string, 3)
	for i, entry := range list {
		text, ok := entry.(string)
		if !ok {
			return nil, newError(ReasonInvalidJWSFormat, "x5c entry %d is not a string", i)
		}
		out[i] = text
	}
	return out, nil
}

func parseJSONSegment(segment, what string) (Claims, error) {
	decoded, err := decodeBase64URLStrict(segment)
	if err != nil {
		return nil, wrapError(ReasonInvalidJWSFormat, err, "%s is not valid base64url", what)
	}
	claims, err := decodeJSONObject(decoded)
	if err != nil {
		return nil, wrapError(ReasonInvalidJWSFormat, err, "%s is not valid base64url JSON", what)
	}
	return claims, nil
}

func parseX5CCertificate(text, what string) (*x509.Certificate, error) {
	// The whole compact JWS is already under maxJWSBytes, so that is the
	// only ceiling an x5c entry can need.
	cert, err := x509.ParseCertificate(decodeBase64(text, maxJWSBytes))
	if err != nil {
		return nil, wrapError(ReasonInvalidCertificate, err,
			"x5c %s entry is not a valid certificate", what)
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
func verifyES256(leaf *x509.Certificate, signingInput, signatureB64 string) error {
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return newError(ReasonInvalidSignature, "leaf key is not EC")
	}
	if key.Curve != elliptic.P256() {
		return newError(ReasonInvalidSignature, "leaf key is not on P-256")
	}
	signature, err := decodeBase64URLStrict(signatureB64)
	if err != nil {
		return wrapError(ReasonInvalidJWSFormat, err, "signature is not valid base64url")
	}
	if len(signature) != 64 {
		return newError(ReasonInvalidSignature,
			"ES256 signature must be 64 bytes, got %d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(key, digest[:], r, s) {
		return newError(ReasonInvalidSignature, "ES256 signature check failed")
	}
	return nil
}

// --- claim checks --------------------------------------------------------

func (v *JWSVerifier) requireBundleID(actual string) error {
	if actual != v.bundleID {
		// The detail names neither value: it is logged by integrators.
		return newError(ReasonWrongBundleID, "payload bundle id is not the configured one")
	}
	return nil
}

func (v *JWSVerifier) requireAcceptedEnvironment(claim Environment) error {
	if !claim.known() || !v.acceptedEnvironments[claim] {
		return newError(ReasonWrongEnvironment, "payload environment is not in the accepted set")
	}
	return nil
}

// requireAppAppleID binds a Production AppTransaction to one app: without
// it, a genuine Production AppTransaction for a different app would pass
// every other check.
func (v *JWSVerifier) requireAppAppleID(environment Environment, actual *int64) error {
	if environment != EnvironmentProduction {
		return nil
	}
	if v.appAppleID == nil || actual == nil || *v.appAppleID != *actual {
		return newError(ReasonWrongAppAppleID,
			"production payload does not carry the configured app Apple id")
	}
	return nil
}

// requireFresh is the one verdict that legitimately moves with wall-clock
// time, and therefore the only one the injected clock drives.
//
// A payload carrying no date of its own is never stale: there is nothing
// to measure the age of, and falling back to "now" would make it always
// fresh or always stale depending on which way the fallback pointed.
func (v *JWSVerifier) requireFresh(signedAt *int64) error {
	if v.maxSignedAge == 0 || signedAt == nil {
		return nil
	}
	age := v.now().Sub(time.UnixMilli(*signedAt))
	if age > v.maxSignedAge {
		return newError(ReasonStalePayload, "payload is older than the configured maximum age")
	}
	return nil
}
