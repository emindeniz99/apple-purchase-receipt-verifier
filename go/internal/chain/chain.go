// Package chain builds and validates certificate paths against pinned
// trust anchors.
//
// Nothing here ever consults the operating system trust store, and nothing
// here ever reaches the network. x509.Certificate.Verify is not called —
// it is exactly the "library default that trusts system roots" this
// library must not have: with a nil VerifyOptions.Roots it falls back to
// the platform verifier, and on macOS to the OS trust evaluation. It also
// routes through CheckSignatureFrom, which refuses SHA-1 certificate
// signatures, and every genuine legacy Apple receipt chain is SHA-1
// signed end to end. So the walk is hand-written.
//
// The walk is top-down (docs/design/0.7-hardening-parity.md, change 1): a
// certificate's signature is checked only with the key of a certificate a
// pinned anchor has already vouched for, directly or transitively, walking
// down from the anchors. A certificate no pinned root vouches for is never
// used to check anything: it is simply left out, so its key, however
// large, is never even decoded into an arithmetic operation. That is what
// makes an oversized-key denial-of-service input cheap to reject: the
// stranger's key is not touched at all, not merely rejected slowly.
//
// The instant to judge validity at is a required parameter on every
// exported function. "Validate at now" is deliberately not expressible:
// certificate validity is judged at the payload's signing time so that a
// historical payload signed with a since-rotated certificate still
// verifies (PLAN.md §2.1 step 4, §2.2 step 2).
package chain

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// MaxPathLength bounds how many certificates a receipt path may hold below
// a pinned anchor (the anchor itself excluded). Node uses the same value.
const MaxPathLength = 6

// MaxRSABits is the widest RSA modulus this package will ever hand to
// crypto/rsa for a signature check, checked before crypto/rsa is called at
// all (docs/design/0.7-hardening-parity.md, "Measurements behind change
// 1"). crypto/rsa has no cap of its own: one verify measured 21 ms at
// 16,384 bits, 317 ms at 65,536 bits and 5.2 s at 262,144 bits. Apple's
// largest published root is RSA-4096, so 8,192 bits (the BoringSSL ceiling
// the Swift port inherits) is ample headroom for a genuine chain and a
// hard ceiling on what an attacker-chosen key can cost to reject.
const MaxRSABits = 8192

func chainErr(format string, args ...any) error {
	return apperr.New(apperr.ReasonUntrustedChain, format, args...)
}

func certErr(format string, args ...any) error {
	return apperr.New(apperr.ReasonInvalidCertificate, format, args...)
}

// ValidAt reports whether at falls inside the certificate's validity
// window, inclusive at both ends.
func ValidAt(cert *x509.Certificate, at time.Time) bool {
	return !at.Before(cert.NotBefore) && !at.After(cert.NotAfter)
}

// isCA is the CA test for every hop above the leaf: basicConstraints must
// be present and say CA, a keyUsage extension, when present, must permit
// certificate signing, and the certificate must carry no critical
// extension this package does not understand. RFC 5280 §4.2: a
// certificate-using system MUST reject a certificate that carries a
// critical extension it does not recognise, so an unknown critical
// extension on an intermediate makes the path fail the same way an
// unusable CA does (owner, 2026-09-27): UNTRUSTED_CHAIN, since crypto/x509
// already collects exactly this list per certificate.
func isCA(cert *x509.Certificate) bool {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		return false
	}
	return true
}

// RSAKeyWithinCap reports whether cert's public key is not RSA, or is RSA
// with a modulus no wider than MaxRSABits. Exported so a content signature
// check outside this package (the CMS SignerInfo signature, once its
// signer certificate is vouched for) applies the same cap before calling
// into crypto/rsa, the same defence in depth this package applies to every
// certificate-to-certificate link.
func RSAKeyWithinCap(cert *x509.Certificate) bool {
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return true
	}
	return key.N.BitLen() <= MaxRSABits
}

// issued reports whether issuer signed cert: exact DER name match, the RSA
// modulus cap when issuer's key is RSA, and a verifying signature. There is
// no allowlist of certificate signature algorithms beyond that (owner,
// 2026-09-27, Q14): whatever crypto/x509 verifies under a pinned chain is
// accepted, matching the Java reference.
//
// The signature is checked with the three-argument
// Certificate.CheckSignature rather than CheckSignatureFrom, because
// CheckSignatureFrom bans SHA-1 (and the GODEBUG=x509sha1=1 escape hatch
// was removed in Go 1.24). sha1_canary_test.go asserts the acceptance
// this depends on; if a future Go removes it, the documented fallback is
// rsa.VerifyPKCS1v15(pub, crypto.SHA1, sha1(tbs), sig), which is not
// removable.
func issued(cert, issuer *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return false
	}
	if !RSAKeyWithinCap(issuer) {
		return false
	}
	recordKeyUse(issuer)
	return issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func isAnchor(cert *x509.Certificate, anchors []*x509.Certificate) bool {
	for _, anchor := range anchors {
		if bytes.Equal(cert.Raw, anchor.Raw) {
			return true
		}
	}
	return false
}

func anchoredBy(cert *x509.Certificate, anchors []*x509.Certificate) bool {
	for _, anchor := range anchors {
		if issued(cert, anchor) {
			return true
		}
	}
	return false
}

// ValidatePair validates the fixed three-element JWS path
// leaf -> intermediate -> pinned anchor at the instant at.
//
// The two signatures are checked from the anchor down first (#161): the
// intermediate must already be vouched for by a pinned anchor before its
// key is ever used to check the leaf's signature. x5c[2] is never passed
// in: the JWS-supplied root is not a trust anchor and is never
// byte-compared to ours, so swapping it changes nothing.
func ValidatePair(leaf, intermediate *x509.Certificate, anchors []*x509.Certificate, at time.Time) error {
	if len(anchors) == 0 {
		return chainErr("no trust anchors configured")
	}
	if !anchoredBy(intermediate, anchors) {
		return chainErr("intermediate not issued by a pinned root")
	}
	// The intermediate is vouched for, so its key may now check the leaf's
	// signature.
	if !issued(leaf, intermediate) {
		return chainErr("leaf not issued by intermediate")
	}
	if !ValidAt(intermediate, at) {
		return certErr("certificate not valid at signing time")
	}
	if !isCA(intermediate) {
		return chainErr("intermediate is not a CA")
	}
	if !ValidAt(leaf, at) {
		return certErr("certificate not valid at signing time")
	}
	return nil
}

// Authenticated is the embedded certificates a pinned anchor vouched for,
// from AuthenticatedTopDown, and a memo of every (certificate, issuer) link
// already checked, so BuildAndValidatePath never checks one twice.
type Authenticated struct {
	certs   []*x509.Certificate
	checked map[linkKey]bool
}

type linkKey struct {
	cert, issuer [sha256.Size]byte
}

func identity(cert *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(cert.Raw)
}

func (a *Authenticated) issuedBy(cert, issuer *x509.Certificate) bool {
	key := linkKey{identity(cert), identity(issuer)}
	if verdict, ok := a.checked[key]; ok {
		return verdict
	}
	verdict := issued(cert, issuer)
	a.checked[key] = verdict
	return verdict
}

// AuthenticatedTopDown returns the embedded certificates whose signature
// verifies under a pinned anchor, or under a certificate already accepted
// this way, walking down from the anchors in at most MaxPathLength rounds.
// Only these certificates are ever handed to BuildAndValidatePath.
//
// Walking down means no key an anchor did not vouch for, directly or
// through a certificate it vouched for, is ever used to check a signature:
// a receipt padded with certificates carrying the attacker's own keys
// (their choice of size and exponent) costs one name comparison per issuer
// for each of them, and they are simply left out, never parsed into an
// arithmetic key, never handed to CheckSignature. An embedded copy of an
// anchor is the anchor, and is accepted without a signature check.
func AuthenticatedTopDown(embedded, anchors []*x509.Certificate) *Authenticated {
	authenticated := &Authenticated{checked: make(map[linkKey]bool, len(embedded))}
	pending := make([]*x509.Certificate, 0, len(embedded))
	for _, cert := range embedded {
		if isAnchor(cert, anchors) {
			authenticated.certs = append(authenticated.certs, cert)
			continue
		}
		pending = append(pending, cert)
	}
	issuers := append(append([]*x509.Certificate(nil), anchors...), authenticated.certs...)
	for round := 0; round < MaxPathLength && len(pending) > 0; round++ {
		var accepted, stillPending []*x509.Certificate
		for _, candidate := range pending {
			ok := false
			for _, issuer := range issuers {
				if authenticated.issuedBy(candidate, issuer) {
					ok = true
					break
				}
			}
			if ok {
				accepted = append(accepted, candidate)
			} else {
				stillPending = append(stillPending, candidate)
			}
		}
		if len(accepted) == 0 {
			break
		}
		authenticated.certs = append(authenticated.certs, accepted...)
		issuers = accepted
		pending = stillPending
	}
	return authenticated
}

// BuildAndValidatePath walks from target through the certificates
// AuthenticatedTopDown accepted to one of the pinned anchors (the shape a
// receipt chain uses, where the intermediates are embedded in the CMS),
// then checks every certificate on the path is inside its validity window
// at the instant at. Returns the path, target first, anchor excluded.
//
// The candidates are exactly the ones AuthenticatedTopDown vouched for, so
// the walk verifies no key a pinned root did not vouch for, and a link it
// already checked is not checked again. The depth bound is MaxPathLength,
// and each candidate is tried once per hop, so a cross-signed certificate
// mesh cannot make the walk exponential.
func BuildAndValidatePath(target *x509.Certificate, authenticated *Authenticated,
	anchors []*x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	if len(anchors) == 0 {
		return nil, chainErr("no trust anchors configured")
	}
	path := []*x509.Certificate{target}
	current := target
	for {
		if len(path) > 1 && !isCA(current) {
			return nil, chainErr("an intermediate is not a CA")
		}
		if anchoredByAny(authenticated, current, anchors) {
			break
		}
		if len(path) >= MaxPathLength {
			return nil, chainErr("chain exceeds the maximum length")
		}
		next := findIssuerOnPath(authenticated, current, path)
		if next == nil {
			return nil, chainErr("chain does not reach a pinned root")
		}
		path = append(path, next)
		current = next
	}
	for _, cert := range path {
		if !ValidAt(cert, at) {
			return nil, certErr("certificate not valid at signing time")
		}
	}
	return path, nil
}

func anchoredByAny(authenticated *Authenticated, cert *x509.Certificate, anchors []*x509.Certificate) bool {
	for _, anchor := range anchors {
		if authenticated.issuedBy(cert, anchor) {
			return true
		}
	}
	return false
}

func findIssuerOnPath(authenticated *Authenticated, current *x509.Certificate, path []*x509.Certificate) *x509.Certificate {
	for _, candidate := range authenticated.certs {
		if onPath(path, candidate) {
			continue
		}
		if authenticated.issuedBy(current, candidate) {
			return candidate
		}
	}
	return nil
}

func onPath(path []*x509.Certificate, cert *x509.Certificate) bool {
	for _, p := range path {
		if p == cert {
			return true
		}
	}
	return false
}

// --- the key-use seam, for tests only ------------------------------------

var (
	keyUseRecording bool
	keysUsed        [][]byte
)

func recordKeyUse(issuer *x509.Certificate) {
	if keyUseRecording {
		keysUsed = append(keysUsed, issuer.RawSubjectPublicKeyInfo)
	}
}

// KeysUsedDuring runs fn and returns, besides whatever fn itself returns
// through its closure, the SPKI of every key a certificate signature check
// used while fn ran. It is the direct assertion the hardening parity work
// asks for: that a stranger's key was never used to check a signature, not
// only that the call finished inside a time budget.
//
// Test-only instrumentation: it is package state, not safe to use from more
// than one goroutine at a time, and never touched outside a KeysUsedDuring
// call.
func KeysUsedDuring(fn func()) [][]byte {
	keyUseRecording = true
	keysUsed = nil
	defer func() { keyUseRecording = false }()
	fn()
	return keysUsed
}
