package applereceipt

import (
	"crypto/x509"
	"embed"
	"fmt"
	"path"
	"sort"
	"sync"
)

// The pinned Apple root certificates, compiled into the binary.
//
// They are embedded rather than read from disk at call time so the
// library works in a FROM scratch image and in any bundled runtime, and
// so that no code path can be talked into reading a different file. The
// repo-root certs/ directory stays the reviewable source of truth;
// go/roots/certs is a generated copy because go:embed cannot reach
// outside the module directory (verified: a ../certs pattern is an
// "invalid pattern syntax" compile error). `go generate ./...` refreshes
// the copy and CI diffs it, so a certs/ change that forgets the Go copy
// fails the build instead of shipping stale trust anchors.
//
//go:embed roots/certs/*.cer
var embeddedRoots embed.FS

var appleRoots = sync.OnceValues(func() ([]*x509.Certificate, error) {
	entries, err := embeddedRoots.ReadDir("roots/certs")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	// Deterministic order, so a caller that logs fingerprints sees the
	// same list on every platform.
	sort.Strings(names)
	certs := make([]*x509.Certificate, 0, len(names))
	for _, name := range names {
		der, err := embeddedRoots.ReadFile(path.Join("roots/certs", name))
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("bundled root %s is not a valid certificate: %w", name, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no bundled Apple roots were embedded")
	}
	return certs, nil
})

// mustAppleRoots panics only if the compiled-in bytes are unparseable,
// which cannot happen without a build that already failed the
// roots_test.go fingerprint assertions.
func mustAppleRoots() []*x509.Certificate {
	certs, err := appleRoots()
	if err != nil {
		panic("applereceipt: " + err.Error())
	}
	// A fresh slice per call: appending to or reordering the returned
	// slice must not be visible to the next caller.
	return append([]*x509.Certificate(nil), certs...)
}

// AppleJWSRoots returns the pinned trust anchors for StoreKit 2 and App
// Store Server JWS chains: all three published Apple roots.
//
// All three, not just the one today's chains end at. Apple documents the
// JWS chain as ending in "an Apple root certificate" without naming one,
// and its guidance is to trust every root on the PKI page, so anchoring
// on a single root would break silently if Apple re-anchored a path
// (PLAN.md D15).
//
// The returned slice is freshly allocated; mutating it does not affect
// later calls.
func AppleJWSRoots() []*x509.Certificate { return mustAppleRoots() }

// AppleReceiptRoots returns the pinned trust anchors for legacy PKCS#7
// app-receipt chains: the same three published Apple roots (PLAN.md D15).
//
// The returned slice is freshly allocated; mutating it does not affect
// later calls.
func AppleReceiptRoots() []*x509.Certificate { return mustAppleRoots() }
