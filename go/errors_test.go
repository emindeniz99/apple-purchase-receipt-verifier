package applereceipt_test

import (
	"errors"
	"fmt"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The eight reason tokens are normative: they are what
// fixtures/cases.schema.json pins and what every port reports. A typo
// in one is otherwise invisible, so the table is written out by hand here
// rather than derived from the constants.
func TestReasonTokensAreTheCanonicalVocabulary(t *testing.T) {
	want := []string{
		"MALFORMED",
		"TOO_LARGE",
		"INVALID_SIGNATURE",
		"UNTRUSTED_CHAIN",
		"INVALID_CERTIFICATE",
		"INVALID_CERTIFICATE_PURPOSE",
		"UNREADABLE_PAYLOAD",
		"INTERNAL_ERROR",
	}
	got := applereceipt.AllReasons()
	if len(got) != len(want) {
		t.Fatalf("the vocabulary has %d reasons, expected %d", len(got), len(want))
	}
	for i, token := range want {
		if string(got[i]) != token {
			t.Errorf("reason %d: got %q, want %q", i, got[i], token)
		}
		if got[i].String() != token {
			t.Errorf("String() on reason %d: got %q", i, got[i].String())
		}
	}
	pairs := map[applereceipt.Reason]string{
		applereceipt.ReasonMalformed:                 "MALFORMED",
		applereceipt.ReasonTooLarge:                  "TOO_LARGE",
		applereceipt.ReasonInvalidSignature:          "INVALID_SIGNATURE",
		applereceipt.ReasonUntrustedChain:            "UNTRUSTED_CHAIN",
		applereceipt.ReasonInvalidCertificate:        "INVALID_CERTIFICATE",
		applereceipt.ReasonInvalidCertificatePurpose: "INVALID_CERTIFICATE_PURPOSE",
		applereceipt.ReasonUnreadablePayload:         "UNREADABLE_PAYLOAD",
		applereceipt.ReasonInternalError:             "INTERNAL_ERROR",
	}
	for reason, token := range pairs {
		if string(reason) != token {
			t.Errorf("%v is spelled %q", token, string(reason))
		}
	}
}

func TestAllReasonsReturnsAFreshSlice(t *testing.T) {
	first := applereceipt.AllReasons()
	first[0] = "TAMPERED"
	if applereceipt.AllReasons()[0] != applereceipt.ReasonMalformed {
		t.Fatal("AllReasons must not hand out the package's own slice")
	}
}

func TestUnwrapReachesTheCause(t *testing.T) {
	cause := errors.New("the underlying problem")
	err := &applereceipt.Failure{
		Reason:  applereceipt.ReasonMalformed,
		Message: "wrapped",
		Cause:   cause,
	}
	if !errors.Is(err, cause) {
		t.Fatal("Unwrap must expose the cause to errors.Is")
	}
	if errors.Unwrap(err) != cause {
		t.Fatal("errors.Unwrap must return the cause")
	}
}

func TestNilFailureDoesNotPanic(t *testing.T) {
	var err *applereceipt.Failure
	// Calling a method on a typed nil is a mistake, but it must not take
	// the caller's process down with it.
	if err.Error() == "" {
		t.Fatal("Error() on a nil receiver must say something")
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("Unwrap on a nil receiver must be nil")
	}
	if err.Is(applereceipt.ReasonUntrustedChain) {
		t.Fatal("Is on a nil receiver must be false")
	}
}

func TestFailureFormatsUsefully(t *testing.T) {
	err := &applereceipt.Failure{
		Reason:  applereceipt.ReasonUntrustedChain,
		Message: "chain does not reach a pinned root",
	}
	want := "UNTRUSTED_CHAIN: chain does not reach a pinned root"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if fmt.Sprintf("%v", err) != want {
		t.Fatalf("%%v: %q", fmt.Sprintf("%v", err))
	}
}
