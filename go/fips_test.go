package applereceipt_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// Under GODEBUG=fips140=only, crypto/sha1 PANICS rather than returning an
// error: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only
// mode". Every genuine legacy Apple receipt is SHA-1 signed, so a library
// without panic containment would abort its caller's process for the
// crime of being deployed in FIPS mode.
//
// The contained behaviour is the honest one: the legacy receipt cannot be
// verified here, and that is a *VerificationError, not a crash. A
// SHA-256 receipt still verifies.
//
// GODEBUG is read once at startup, so t.Setenv is useless and the check
// has to happen in a child process.
func TestFIPSOnlyModeDoesNotCrashTheCaller(t *testing.T) {
	if !inSubprocess() {
		if !strings.HasPrefix(runtime.Version(), "go1.2") || runtime.Version() < "go1.24" {
			t.Skipf("GODEBUG=fips140 does not exist on %s", runtime.Version())
		}
		output, err := runSelf(t, "TestFIPSOnlyModeDoesNotCrashTheCaller", "GODEBUG=fips140=only")
		if err != nil && strings.Contains(output, "fips140=only") &&
			strings.Contains(output, "not supported") {
			t.Skipf("this toolchain cannot run in FIPS-140-only mode:\n%s", output)
		}
		requireChildPassed(t, output, err)
		return
	}

	// --- child, running with GODEBUG=fips140=only ----------------------
	t.Run("the SHA-1 legacy receipt fails without panicking", func(t *testing.T) {
		receipt := fixtureBytes(t, "public-receipt-sandbox-legacy")
		result, err := applereceipt.VerifyReceiptCore(receipt, applereceipt.AppleReceiptRoots())
		if err == nil {
			// Some builds allow SHA-1 for signature verification even in
			// FIPS-only mode. Verifying is a fine outcome; crashing is not.
			t.Logf("SHA-1 verification is permitted in this configuration; " +
				"the receipt verified")
			if result == nil {
				t.Fatal("a nil error must come with a receipt")
			}
			return
		}
		var verr *applereceipt.VerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("FIPS-only mode must produce a *VerificationError, got %T: %v", err, err)
		}
		t.Logf("contained as %s, which is the truth: this build cannot verify a SHA-1 receipt",
			verr.Reason)
	})

	t.Run("the SHA-256 receipt still verifies", func(t *testing.T) {
		receipt := fixtureBytes(t, "public-receipt-sandbox-g5")
		if _, err := applereceipt.VerifyReceiptCore(receipt, applereceipt.AppleReceiptRoots()); err != nil {
			t.Fatalf("a SHA-256 receipt must still verify in FIPS-140-only mode: %v", err)
		}
	})
}
