package applereceipt

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
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

// appleRootFingerprints pins the SHA-256 of each bundled root DER, so a
// certs/ file swapped at build time (parseable, but not the certificate
// Apple published) does not silently become a trust anchor
// (docs/design/0.7-api.md, Startup failures).
var appleRootFingerprints = map[string]string{
	"AppleIncRootCertificate.cer": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
	"AppleRootCA-G2.cer":          "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
	"AppleRootCA-G3.cer":          "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
}

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
	if len(names) != len(appleRootFingerprints) {
		return nil, fmt.Errorf("expected %d bundled Apple roots, found %d",
			len(appleRootFingerprints), len(names))
	}
	certs := make([]*x509.Certificate, 0, len(names))
	for _, name := range names {
		want, known := appleRootFingerprints[name]
		if !known {
			return nil, fmt.Errorf("bundled root %s is not one of the pinned Apple roots", name)
		}
		der, err := embeddedRoots.ReadFile(path.Join("roots/certs", name))
		if err != nil {
			return nil, err
		}
		got := sha256.Sum256(der)
		if hex.EncodeToString(got[:]) != want {
			return nil, fmt.Errorf("bundled root %s does not match its pinned SHA-256 fingerprint", name)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("bundled root %s is not a valid certificate: %w", name, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
})

// mustAppleRoots panics only if the compiled-in bytes are unparseable or
// fail their pinned fingerprint, which cannot happen without a build that
// already failed roots_test.go's assertions. DefaultConfig calls it: the
// Go equivalent of Config.defaults() throwing at startup
// (docs/design/0.7-api.md, Startup failures): both happen once, before
// any input is read, rather than as an error every caller must remember
// to check.
func mustAppleRoots() []*x509.Certificate {
	certs, err := appleRoots()
	if err != nil {
		panic("applereceipt: " + err.Error())
	}
	// A fresh slice per call: appending to or reordering the returned
	// slice must not be visible to the next caller.
	return append([]*x509.Certificate(nil), certs...)
}

// AppleRoots returns the three published Apple roots this library pins,
// compiled into the binary: the trust anchors DefaultConfig uses for
// both the receipt and the JWS chain.
//
// All three, not just the one today's chains end at. Apple documents
// both chains as ending in "an Apple root certificate" without naming
// one, and its guidance is to trust every root on the PKI page, so
// anchoring on a single root would break silently if Apple re-anchored a
// path.
//
// The returned slice is freshly allocated; mutating it does not affect
// later calls.
func AppleRoots() []*x509.Certificate { return mustAppleRoots() }
