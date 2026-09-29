package applereceipt_test

import (
	"crypto/x509"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The three Apple roots are compiled into aprv.wasm; this package carries no
// copy of them. The defaults therefore name no roots of their own, and the
// Verifier sends init an empty list, which the module reads as its built-in
// roots (facade_test.go pins that wire form). Every case in
// fixtures/cases.json whose trustedRoots source is "default" verifies a
// genuine Apple chain through exactly this path.
func TestTheDefaultsNameNoRootsOfTheirOwn(t *testing.T) {
	if roots := applereceipt.DefaultConfig().Roots(); roots != nil {
		t.Fatalf("DefaultConfig().Roots() = %d certificates, want nil (the module's roots)", len(roots))
	}
	if roots := applereceipt.NewConfig(applereceipt.ConfigOptions{}).Roots(); roots != nil {
		t.Fatalf("NewConfig with no Roots = %d certificates, want nil (the module's roots)", len(roots))
	}
	if _, err := applereceipt.NewVerifier(applereceipt.DefaultConfig()); err != nil {
		t.Fatalf("the defaults were refused: %v", err)
	}
}

// An explicitly empty, non-nil slice is not "the defaults": it is a caller
// who configured no trust at all, and NewVerifier refuses it rather than
// answering UNTRUSTED_CHAIN to everything, or quietly trusting Apple.
func TestAnExplicitlyEmptyRootListIsRefused(t *testing.T) {
	config := applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{}})
	if roots := config.Roots(); roots == nil || len(roots) != 0 {
		t.Fatalf("an explicit empty list read back as %#v", roots)
	}
	if _, err := applereceipt.NewVerifier(config); err == nil {
		t.Fatal("a Config with an explicitly empty root list was accepted")
	}
}

// Config.Roots() is documented as an unmodifiable copy: mutating what a
// caller got must not reach the Config, a Go aliasing hazard the other
// ports do not have.
func TestConfigRootsReturnsIndependentSlices(t *testing.T) {
	config := applereceipt.NewConfig(applereceipt.ConfigOptions{
		Roots: []*x509.Certificate{parseFixtureCertificate(t, "jws-root")},
	})
	roots := config.Roots()
	roots[0] = nil
	if config.Roots()[0] == nil {
		t.Fatal("mutating the returned slice reached the Config")
	}
}
