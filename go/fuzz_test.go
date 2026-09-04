package applereceipt_test

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Fuzz targets. Their seed corpora run on every `go test`; CI additionally
// runs them with -fuzz for a fixed budget, and any crasher it finds is
// committed under testdata/fuzz/ as a permanent regression case.
//
// The invariants are the same three everywhere:
//
//   - nothing panics;
//   - a non-nil error is always a *VerificationError;
//   - a nil error means the chain actually reached a pinned anchor,
//     asserted by re-running against a different anchor set and requiring
//     failure. Without that third one a fuzz target can only find crashes,
//     not "accepts things it should not".

func receiptSeeds(f *testing.F) [][]byte {
	f.Helper()
	ids := []string{
		"receipt", "receipt-double-wrapped", "receipt-foreign", "receipt-no-signer-oid",
		"receipt-expired-historical", "receipt-expired-fresh", "receipt-type-production",
		"receipt-type-vpp", "receipt-type-vpp-sandbox", "receipt-no-type",
		"receipt-attribute-type-overflow", "receipt-no-creation-date",
		"public-receipt-sandbox-g5", "xcode-app-receipt-empty",
	}
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		out = append(out, fuzzFixture(f, id))
	}
	return out
}

// fuzzFixture loads a seed. fixtureBytes takes a testing.TB, so the same
// digest-checked loader serves the fuzz targets.
func fuzzFixture(f *testing.F, id string) []byte {
	f.Helper()
	return fixtureBytes(f, id)
}

func FuzzVerifyReceipt(f *testing.F) {
	for _, seed := range receiptSeeds(f) {
		f.Add(seed)
	}
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x80})

	roots := applereceipt.AppleReceiptRoots()
	// A second, unrelated anchor set, used to prove that an accepted
	// receipt was accepted because of the anchors and not despite them.
	other := []*x509.Certificate{fuzzRoot(f)}

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := applereceipt.VerifyReceiptCore(input, roots)
		if err != nil {
			var verr *applereceipt.VerificationError
			if !errors.As(err, &verr) {
				t.Fatalf("escaped as %T: %v", err, err)
			}
			return
		}
		if result == nil {
			t.Fatal("a nil error must come with a receipt")
		}
		if _, err := applereceipt.VerifyReceiptCore(input, other); err == nil {
			t.Fatal("this input verifies against an unrelated anchor set too, " +
				"so the anchors are not being enforced")
		}
	})
}

func FuzzVerifyReceiptBase64(f *testing.F) {
	for _, seed := range receiptSeeds(f) {
		f.Add(base64.StdEncoding.EncodeToString(seed))
	}
	f.Add("")
	f.Add("!!!!not base64!!!!")

	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(), BundleID: "dev.bonzer.weeka.app",
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if _, err := verifier.VerifyBase64(input); err != nil {
			var verr *applereceipt.VerificationError
			if !errors.As(err, &verr) {
				t.Fatalf("escaped as %T: %v", err, err)
			}
		}
	})
}

func FuzzVerifyTransaction(f *testing.F) {
	for _, id := range []string{
		"transaction", "transaction-no-leaf-oid", "transaction-no-intermediate-oid",
		"app-transaction", "app-transaction-production", "expired-cert-historical",
		"expired-cert-fresh", "apple-transaction-info", "apple-renewal-info",
		"apple-test-notification", "apple-wrong-bundle-id", "apple-missing-x5c",
		"xcode-signed-transaction", "transaction-no-signed-date",
	} {
		f.Add(string(fuzzFixture(f, id)))
	}
	f.Add("")
	f.Add("a.b.c")

	root := fuzzRoot(f)
	verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots:         []*x509.Certificate{root},
		BundleID:             "com.example.app",
		AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
	})
	if err != nil {
		f.Fatal(err)
	}
	unrelated, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots:         applereceipt.AppleJWSRoots(),
		BundleID:             "com.example.app",
		AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
	})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		for _, call := range []struct {
			name string
			run  func(string) (any, error)
		}{
			{"VerifyTransaction", func(s string) (any, error) { return verifier.VerifyTransaction(s) }},
			{"VerifyAppTransaction", func(s string) (any, error) { return verifier.VerifyAppTransaction(s) }},
			{"VerifyRaw", func(s string) (any, error) { return verifier.VerifyRaw(s) }},
		} {
			_, err := call.run(input)
			if err == nil {
				continue
			}
			var verr *applereceipt.VerificationError
			if !errors.As(err, &verr) {
				t.Fatalf("%s escaped as %T: %v", call.name, err, err)
			}
		}
		if _, err := verifier.VerifyRaw(input); err == nil {
			if _, err := unrelated.VerifyRaw(input); err == nil {
				t.Fatal("this input verifies against Apple's roots too, " +
					"so the anchors are not being enforced")
			}
		}
	})
}

func fuzzRoot(f *testing.F) *x509.Certificate {
	f.Helper()
	return parseFixtureCertificate(f, "jws-root")
}
