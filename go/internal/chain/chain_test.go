package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// Unit tests for the path builder itself. The end-to-end behaviour is
// covered through the public API and the shared conformance cases; these
// pin what is invisible from outside: the exact validity-window boundary,
// that every failure carries the right Reason, the top-down walk
// (#161) and the RSA modulus cap.

var serial int64 = 1

func issue(t *testing.T, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	isCA bool, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func path(t *testing.T, target *x509.Certificate, embedded, anchors []*x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	t.Helper()
	authenticated := AuthenticatedTopDown(embedded, anchors)
	return BuildAndValidatePath(target, authenticated, anchors, at)
}

func reasonOf(t *testing.T, err error) apperr.Reason {
	t.Helper()
	var verr *apperr.Error
	if !errors.As(err, &verr) {
		t.Fatalf("escaped as %T: %v", err, err)
	}
	return verr.Reason
}

func TestValidAtIsInclusiveAtBothEnds(t *testing.T) {
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	cert, _ := issue(t, "Window", nil, nil, true, from, to)

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"one second before notBefore", from.Add(-time.Second), false},
		{"exactly notBefore", cert.NotBefore, true},
		{"in the middle", from.Add(12 * time.Hour), true},
		{"exactly notAfter", cert.NotAfter, true},
		{"one second after notAfter", cert.NotAfter.Add(time.Second), false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if got := ValidAt(cert, test.at); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestFailuresCarryTheirReason(t *testing.T) {
	now := time.Now()
	root, rootKey := issue(t, "Root", nil, nil, true, now.Add(-time.Hour), now.Add(time.Hour))
	intermediate, interKey := issue(t, "Intermediate", root, rootKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	leaf, _ := issue(t, "Leaf", intermediate, interKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	stranger, strangerKey := issue(t, "Stranger", nil, nil, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	notACA, notACAKey := issue(t, "Not a CA", root, rootKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	leafUnderNotACA, _ := issue(t, "Leaf under Not a CA", notACA, notACAKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	strangerLeaf, _ := issue(t, "Stranger Leaf", stranger, strangerKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	failures := []struct {
		name string
		want apperr.Reason
		run  func() error
	}{
		{"no anchors at all", apperr.ReasonUntrustedChain, func() error {
			return ValidatePair(leaf, intermediate, nil, now)
		}},
		{"leaf outside its window", apperr.ReasonInvalidCertificate, func() error {
			return ValidatePair(leaf, intermediate, []*x509.Certificate{root}, now.Add(2*time.Hour))
		}},
		{"intermediate is not a CA", apperr.ReasonUntrustedChain, func() error {
			return ValidatePair(leafUnderNotACA, notACA, []*x509.Certificate{root}, now)
		}},
		{"leaf not issued by the intermediate", apperr.ReasonUntrustedChain, func() error {
			return ValidatePair(strangerLeaf, intermediate, []*x509.Certificate{root}, now)
		}},
		{"intermediate not issued by an anchor", apperr.ReasonUntrustedChain, func() error {
			return ValidatePair(leaf, intermediate, []*x509.Certificate{stranger}, now)
		}},
		{"path reaches no anchor", apperr.ReasonUntrustedChain, func() error {
			_, err := path(t, leaf, []*x509.Certificate{leaf, intermediate}, []*x509.Certificate{stranger}, now)
			return err
		}},
		{"path with no candidates", apperr.ReasonUntrustedChain, func() error {
			_, err := path(t, leaf, []*x509.Certificate{leaf}, []*x509.Certificate{root}, now)
			return err
		}},
		{"path with no anchors", apperr.ReasonUntrustedChain, func() error {
			_, err := path(t, leaf, []*x509.Certificate{leaf, intermediate}, nil, now)
			return err
		}},
	}
	for _, failure := range failures {
		failure := failure
		t.Run(failure.name, func(t *testing.T) {
			err := failure.run()
			if err == nil {
				t.Fatal("expected a failure")
			}
			if got := reasonOf(t, err); got != failure.want {
				t.Fatalf("reason: %s, want %s", got, failure.want)
			}
		})
	}
}

func TestHappyPathsSucceed(t *testing.T) {
	now := time.Now()
	root, rootKey := issue(t, "Root", nil, nil, true, now.Add(-time.Hour), now.Add(time.Hour))
	intermediate, interKey := issue(t, "Intermediate", root, rootKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	leaf, _ := issue(t, "Leaf", intermediate, interKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	if err := ValidatePair(leaf, intermediate, []*x509.Certificate{root}, now); err != nil {
		t.Fatalf("ValidatePair: %v", err)
	}
	if _, err := path(t, leaf, []*x509.Certificate{leaf, intermediate}, []*x509.Certificate{root}, now); err != nil {
		t.Fatalf("path: %v", err)
	}
	// The anchor's own window is never consulted, so an expired anchor
	// still anchors.
	expiredRoot, expiredKey := issue(t, "Expired Root", nil, nil, true,
		now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	underExpired, underKey := issue(t, "Under Expired", expiredRoot, expiredKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	expiredLeaf, _ := issue(t, "Expired Leaf", underExpired, underKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	if err := ValidatePair(expiredLeaf, underExpired,
		[]*x509.Certificate{expiredRoot}, now); err != nil {
		t.Fatalf("an anchor's own expiry must not be checked: %v", err)
	}
}

func TestPathAcceptsSixAndRejectsSeven(t *testing.T) {
	now := time.Now()
	window := func() (time.Time, time.Time) { return now.Add(-time.Hour), now.Add(time.Hour) }

	build := func(depth int) (target *x509.Certificate, embedded []*x509.Certificate, anchor *x509.Certificate) {
		nb, na := window()
		root, rootKey := issue(t, "Root", nil, nil, true, nb, na)
		current, currentKey := root, rootKey
		var chainCerts []*x509.Certificate
		for i := 0; i < depth-1; i++ {
			nb, na := window()
			next, nextKey := issue(t, "Intermediate", current, currentKey, true, nb, na)
			chainCerts = append(chainCerts, next)
			current, currentKey = next, nextKey
		}
		nb, na = window()
		leaf, _ := issue(t, "Leaf", current, currentKey, false, nb, na)
		chainCerts = append(chainCerts, leaf)
		return leaf, chainCerts, root
	}

	// Six certificates below the anchor, anchor excluded: accepted.
	target, embedded, anchor := build(6)
	if _, err := path(t, target, embedded, []*x509.Certificate{anchor}, now); err != nil {
		t.Fatalf("a 6-certificate path must be accepted: %v", err)
	}

	// Seven: rejected.
	target, embedded, anchor = build(7)
	_, err := path(t, target, embedded, []*x509.Certificate{anchor}, now)
	if err == nil {
		t.Fatal("a 7-certificate path must be rejected")
	}
	if got := reasonOf(t, err); got != apperr.ReasonUntrustedChain {
		t.Fatalf("reason: %s", got)
	}
}

// --- change 1: the top-down walk -------------------------------------------

// rsaKeyDER builds a self-consistent, but unsigned-by-anything-trusted,
// RSA public key of the given bit size, encoded the way
// x509.CreateCertificate would embed it, without the cost of actually
// generating one that large: it is a certificate whose issuer this test
// never asks the walk to trust.
func oversizedRSACert(t *testing.T, bits int) *x509.Certificate {
	t.Helper()
	// Building a genuine RSA key at 65536+ bits is itself slow (this is
	// exactly the cost this test proves the library never pays), so the
	// modulus is assembled directly: a large odd number is as valid an
	// RSA modulus, for the purpose of parsing and the walk's own cap
	// check, as a product of two real primes: nothing here ever reaches
	// modular exponentiation.
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	modulus.Sub(modulus, big.NewInt(1))
	key := &rsa.PublicKey{N: modulus, E: 65537}

	selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Stranger"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	// The certificate's own key (used to sign it, and to check anything
	// IT issued) is a fast EC key; the oversized RSA key is embedded in
	// its subject so the test controls exactly which key the walk would
	// have to use as an issuer.
	der, err := x509.CreateCertificate(rand.Reader, template, template, key, selfKey)
	if err != nil {
		// A key this large may be refused at encoding time by some Go
		// versions; either way, the walk must never reach it.
		t.Skipf("x509.CreateCertificate refused a %d-bit RSA key: %v", bits, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAnOversizedKeyIsNeverUsedToCheckASignature(t *testing.T) {
	now := time.Now()
	root, rootKey := issue(t, "Root", nil, nil, true, now.Add(-time.Hour), now.Add(time.Hour))
	intermediate, interKey := issue(t, "Intermediate", root, rootKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	leaf, _ := issue(t, "Leaf", intermediate, interKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	stranger := oversizedRSACert(t, 65536)
	anchors := []*x509.Certificate{root}
	embedded := []*x509.Certificate{leaf, intermediate, stranger}

	var authenticated *Authenticated
	var pathErr error
	start := time.Now()
	used := KeysUsedDuring(func() {
		authenticated = AuthenticatedTopDown(embedded, anchors)
		_, pathErr = BuildAndValidatePath(leaf, authenticated, anchors, now)
	})
	elapsed := time.Since(start)
	if pathErr != nil {
		t.Fatalf("the genuine path must still verify: %v", pathErr)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("took %v, over the DoS time budget", elapsed)
	}
	for _, spki := range used {
		if len(spki) > 1100 {
			t.Fatalf("a %d-byte stranger key checked a signature", len(spki))
		}
	}
	for _, cert := range authenticated.certs {
		if cert == stranger {
			t.Fatal("the stranger with the oversized key was authenticated")
		}
	}
}

func TestStrangerCertificatesAreIgnoredNotFatal(t *testing.T) {
	now := time.Now()
	root, rootKey := issue(t, "Root", nil, nil, true, now.Add(-time.Hour), now.Add(time.Hour))
	intermediate, interKey := issue(t, "Intermediate", root, rootKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	leaf, _ := issue(t, "Leaf", intermediate, interKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	stranger, strangerKey := issue(t, "Stranger", nil, nil, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	strangerLeaf, _ := issue(t, "Stranger Leaf", stranger, strangerKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	// A genuine chain padded with an unrelated stranger chain still
	// verifies (Q16): the padding is never asked to be trusted, and
	// never makes trusting the real chain fail.
	embedded := []*x509.Certificate{leaf, intermediate, stranger, strangerLeaf}
	if _, err := path(t, leaf, embedded, []*x509.Certificate{root}, now); err != nil {
		t.Fatalf("padding with strangers must not break a genuine chain: %v", err)
	}
}

func TestRSAModulusCap(t *testing.T) {
	// MaxRSABits itself, encoded exactly, must be accepted by the cap
	// check; one bit over must not.
	within := &x509.Certificate{PublicKey: &rsa.PublicKey{
		N: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), MaxRSABits), big.NewInt(1)),
		E: 65537,
	}}
	if !RSAKeyWithinCap(within) {
		t.Error("a modulus of exactly MaxRSABits must be within the cap")
	}
	over := &x509.Certificate{PublicKey: &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), MaxRSABits),
		E: 65537,
	}}
	if RSAKeyWithinCap(over) {
		t.Error("a modulus one bit over MaxRSABits must be refused")
	}
	nonRSA := &x509.Certificate{PublicKey: struct{}{}}
	if !RSAKeyWithinCap(nonRSA) {
		t.Error("a non-RSA key has no modulus cap to apply")
	}
}
