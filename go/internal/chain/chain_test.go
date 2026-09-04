package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// Unit tests for the path builder itself. The end-to-end behaviour is
// covered through the public API; these pin the two things that are
// invisible from outside: the exact validity-window boundary, and that
// every failure here carries INVALID_CHAIN and nothing else.

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

func TestEveryFailureCarriesInvalidChain(t *testing.T) {
	now := time.Now()
	root, rootKey := issue(t, "Root", nil, nil, true, now.Add(-time.Hour), now.Add(time.Hour))
	intermediate, interKey := issue(t, "Intermediate", root, rootKey, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	leaf, _ := issue(t, "Leaf", intermediate, interKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	stranger, strangerKey := issue(t, "Stranger", nil, nil, true,
		now.Add(-time.Hour), now.Add(time.Hour))
	notACA, _ := issue(t, "Not a CA", root, rootKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	strangerLeaf, _ := issue(t, "Stranger Leaf", stranger, strangerKey, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	failures := []struct {
		name string
		run  func() error
	}{
		{"no anchors at all", func() error {
			return ValidatePair(leaf, intermediate, nil, now)
		}},
		{"leaf outside its window", func() error {
			return ValidatePair(leaf, intermediate, []*x509.Certificate{root}, now.Add(2*time.Hour))
		}},
		{"intermediate is not a CA", func() error {
			return ValidatePair(leaf, notACA, []*x509.Certificate{root}, now)
		}},
		{"leaf not issued by the intermediate", func() error {
			return ValidatePair(strangerLeaf, intermediate, []*x509.Certificate{root}, now)
		}},
		{"intermediate not issued by an anchor", func() error {
			return ValidatePair(leaf, intermediate, []*x509.Certificate{stranger}, now)
		}},
		{"path reaches no anchor", func() error {
			return BuildAndValidatePath(leaf, []*x509.Certificate{intermediate},
				[]*x509.Certificate{stranger}, now)
		}},
		{"path with no candidates", func() error {
			return BuildAndValidatePath(leaf, nil, []*x509.Certificate{root}, now)
		}},
		{"path with no anchors", func() error {
			return BuildAndValidatePath(leaf, []*x509.Certificate{intermediate}, nil, now)
		}},
	}
	for _, failure := range failures {
		failure := failure
		t.Run(failure.name, func(t *testing.T) {
			err := failure.run()
			if err == nil {
				t.Fatal("expected a failure")
			}
			var verr *apperr.Error
			if !errors.As(err, &verr) {
				t.Fatalf("escaped as %T: %v", err, err)
			}
			if verr.Reason != apperr.ReasonInvalidChain {
				t.Fatalf("reason: %s", verr.Reason)
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
	if err := BuildAndValidatePath(leaf, []*x509.Certificate{intermediate},
		[]*x509.Certificate{root}, now); err != nil {
		t.Fatalf("BuildAndValidatePath: %v", err)
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
