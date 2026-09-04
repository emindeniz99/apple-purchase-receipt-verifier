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
// The instant to judge validity at is a required parameter on every
// exported function. "Validate at now" is deliberately not expressible:
// certificate validity is judged at the payload's signing time so that a
// historical payload signed with a since-rotated certificate still
// verifies (PLAN.md §2.1 step 4, §2.2 step 2).
package chain

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// MaxPathLength bounds how many hops a receipt path may take before a
// pinned anchor. Node uses the same value.
const MaxPathLength = 6

// allowedSignatureAlgorithms is the certificate signature allowlist.
//
// SHA-1 with RSA is on it because every genuine legacy Apple receipt
// chain — leaf, WWDR intermediate and the Apple Inc. Root — is SHA1-RSA,
// and rejecting it would reject every legacy receipt in existence.
// ECDSA-SHA384 is on it because Apple's own official JWS test chains use
// it. MD2, MD5, DSA, RSA-PSS and UnknownSignatureAlgorithm are not on it.
var allowedSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.SHA1WithRSA:     true,
	x509.SHA256WithRSA:   true,
	x509.SHA384WithRSA:   true,
	x509.SHA512WithRSA:   true,
	x509.ECDSAWithSHA256: true,
	x509.ECDSAWithSHA384: true,
	x509.ECDSAWithSHA512: true,
}

func chainErr(format string, args ...any) error {
	return apperr.New(apperr.ReasonInvalidChain, format, args...)
}

// ValidAt reports whether at falls inside the certificate's validity
// window, inclusive at both ends.
func ValidAt(cert *x509.Certificate, at time.Time) bool {
	return !at.Before(cert.NotBefore) && !at.After(cert.NotAfter)
}

// isCA is the CA test for every hop above the leaf: basicConstraints must
// be present and say CA, and a keyUsage extension, when present, must
// permit certificate signing.
func isCA(cert *x509.Certificate) bool {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return true
}

// issued reports whether issuer signed cert: exact DER name match, an
// allowlisted signature algorithm, and a verifying signature.
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
	if !allowedSignatureAlgorithms[cert.SignatureAlgorithm] {
		return false
	}
	return issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// anchoredBy reports whether one of the pinned anchors issued cert.
//
// An anchor's own validity window is deliberately not checked: trust
// anchors are trusted by fiat, which is standard PKIX semantics and is
// what lets a historical receipt verify under a root that has since
// expired.
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
// x5c[2] is never passed in: the JWS-supplied root is not a trust anchor
// and is never byte-compared to ours, so swapping it changes nothing.
func ValidatePair(leaf, intermediate *x509.Certificate, anchors []*x509.Certificate, at time.Time) error {
	if len(anchors) == 0 {
		return chainErr("no trust anchors configured")
	}
	if !ValidAt(leaf, at) || !ValidAt(intermediate, at) {
		return chainErr("certificate not valid at signing time")
	}
	if !isCA(intermediate) {
		return chainErr("intermediate is not a CA")
	}
	if !issued(leaf, intermediate) {
		return chainErr("leaf not issued by intermediate")
	}
	if !anchoredBy(intermediate, anchors) {
		return chainErr("intermediate not issued by a pinned root")
	}
	return nil
}

// BuildAndValidatePath walks from target through candidates to a pinned
// anchor at the instant at. Receipt chains embed their intermediates in
// the CMS, so the path is discovered rather than fixed.
//
// candidates are used for path building only. They are never trust
// anchors: the walk succeeds only when some certificate on the path was
// issued by one of anchors.
func BuildAndValidatePath(target *x509.Certificate, candidates, anchors []*x509.Certificate, at time.Time) error {
	if len(anchors) == 0 {
		return chainErr("no trust anchors configured")
	}
	// Keyed on subject + public key so a cross-signed mesh, or a
	// certificate naming itself as its own issuer, cannot make the walk
	// revisit a node and loop.
	visited := make(map[[sha256.Size]byte]bool, MaxPathLength)
	current := target
	for depth := 0; depth < MaxPathLength; depth++ {
		key := identity(current)
		if visited[key] {
			return chainErr("certificate path revisits a certificate")
		}
		visited[key] = true

		if !ValidAt(current, at) {
			return chainErr("certificate not valid at signing time")
		}
		if depth > 0 && !isCA(current) {
			return chainErr("intermediate is not a CA")
		}
		if anchoredBy(current, anchors) {
			return nil
		}
		next := findIssuer(current, candidates, visited)
		if next == nil {
			return chainErr("chain does not reach a pinned root")
		}
		current = next
	}
	return chainErr("chain exceeds maximum length")
}

func findIssuer(cert *x509.Certificate, candidates []*x509.Certificate, visited map[[sha256.Size]byte]bool) *x509.Certificate {
	for _, candidate := range candidates {
		if visited[identity(candidate)] {
			continue
		}
		if issued(cert, candidate) {
			return candidate
		}
	}
	return nil
}

func identity(cert *x509.Certificate) [sha256.Size]byte {
	h := sha256.New()
	h.Write(cert.RawSubject)
	h.Write(cert.RawSubjectPublicKeyInfo)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
