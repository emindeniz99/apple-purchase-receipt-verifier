package applereceipt_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The three published Apple roots, pinned by SHA-256 fingerprint of their
// DER. Written out by hand so that swapping a certificate — the one
// change that would silently repoint every consumer's trust — fails
// loudly here rather than passing as "still three roots".
var appleRootFingerprints = map[string]string{
	"Apple Root CA":      "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
	"Apple Root CA - G2": "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
	"Apple Root CA - G3": "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
}

func TestBundledRootsAreTheThreePublishedAppleRoots(t *testing.T) {
	for _, set := range []struct {
		name  string
		roots []*x509.Certificate
	}{
		{"AppleJWSRoots", applereceipt.AppleJWSRoots()},
		{"AppleReceiptRoots", applereceipt.AppleReceiptRoots()},
	} {
		set := set
		t.Run(set.name, func(t *testing.T) {
			if len(set.roots) != len(appleRootFingerprints) {
				t.Fatalf("got %d roots, want %d", len(set.roots), len(appleRootFingerprints))
			}
			seen := map[string]bool{}
			for _, root := range set.roots {
				name := root.Subject.CommonName
				want, known := appleRootFingerprints[name]
				if !known {
					t.Errorf("unexpected bundled root %q", name)
					continue
				}
				sum := sha256.Sum256(root.Raw)
				if got := hex.EncodeToString(sum[:]); got != want {
					t.Errorf("%s: fingerprint %s, want %s", name, got, want)
				}
				seen[name] = true
				if !root.IsCA {
					t.Errorf("%s is not a CA", name)
				}
				// Self-signed, as a root must be. The signature itself is
				// never verified in production — a self-signature proves
				// nothing about trust — but the naming must be right.
				if root.Subject.String() != root.Issuer.String() {
					t.Errorf("%s is not self-issued", name)
				}
			}
			for name := range appleRootFingerprints {
				if !seen[name] {
					t.Errorf("bundled set is missing %q", name)
				}
			}
		})
	}
}

// Both sets carry all three roots (PLAN.md D15). Apple documents the JWS
// chain as ending in "an Apple root certificate" without naming one, so
// anchoring either path on a single root would break silently if Apple
// re-anchored a path.
func TestBothRootSetsAreTheSame(t *testing.T) {
	jws := fingerprintsOf(applereceipt.AppleJWSRoots())
	receipt := fingerprintsOf(applereceipt.AppleReceiptRoots())
	if strings.Join(jws, ",") != strings.Join(receipt, ",") {
		t.Fatalf("the two sets differ:\n%v\n%v", jws, receipt)
	}
}

func fingerprintsOf(roots []*x509.Certificate) []string {
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		sum := sha256.Sum256(root.Raw)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	sort.Strings(out)
	return out
}

// Each call hands back its own slice. Appending to or reordering what a
// caller got must not reach the next caller — a Go aliasing hazard the
// other ports do not have.
func TestRootAccessorsReturnIndependentSlices(t *testing.T) {
	first := applereceipt.AppleReceiptRoots()
	first[0] = nil
	first = append(first, nil)
	_ = first

	second := applereceipt.AppleReceiptRoots()
	if len(second) != len(appleRootFingerprints) {
		t.Fatalf("the second call returned %d roots", len(second))
	}
	for i, root := range second {
		if root == nil {
			t.Fatalf("root %d was nilled out by a previous caller", i)
		}
	}
}

// go/roots/certs is a generated copy of the repo-root certs/, because an
// embed pattern is not allowed to reach outside its module directory. The
// generator's guarantee is tested here rather than assumed: a certs/
// change that forgot the copy would otherwise ship stale trust anchors.
func TestEmbeddedRootsMatchTheRepositoryCerts(t *testing.T) {
	moduleDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(moduleDir, "..", "certs")
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Skipf("the repository certs/ directory is not reachable from here: %v", err)
	}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cer") {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("certs/ holds no .cer files")
	}
	copied, err := os.ReadDir(filepath.Join(moduleDir, "roots", "certs"))
	if err != nil {
		t.Fatal(err)
	}
	copiedNames := []string{}
	for _, entry := range copied {
		if !entry.IsDir() {
			copiedNames = append(copiedNames, entry.Name())
		}
	}
	sort.Strings(names)
	sort.Strings(copiedNames)
	if strings.Join(names, ",") != strings.Join(copiedNames, ",") {
		t.Fatalf("go/roots/certs holds %v, certs/ holds %v — run `go generate ./...`",
			copiedNames, names)
	}
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(moduleDir, "roots", "certs", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("go/roots/certs/%s differs from certs/%s — run `go generate ./...`", name, name)
		}
	}
}
