package applereceipt_test

import (
	"errors"
	"fmt"
	"strings"
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

func TestErrorReadingStyles(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	verifier := verifierFor(t, other.anchors())
	_, err := verifier.VerifyReceipt(applereceiptBase64(pki.receipt(t)))
	if err == nil {
		t.Fatal("expected a failure")
	}

	t.Run("errors.As is the canonical read", func(t *testing.T) {
		var failure *applereceipt.Failure
		if !errors.As(err, &failure) {
			t.Fatal("errors.As must extract a *Failure")
		}
		if failure.Reason != applereceipt.ReasonUntrustedChain {
			t.Fatalf("reason: %s", failure.Reason)
		}
	})
	t.Run("errors.Is on a bare Reason works as sugar", func(t *testing.T) {
		if !errors.Is(err, applereceipt.ReasonUntrustedChain) {
			t.Fatal("errors.Is(err, ReasonUntrustedChain) must match")
		}
		if errors.Is(err, applereceipt.ReasonInvalidSignature) {
			t.Fatal("errors.Is must not cross-match a different reason")
		}
	})
	t.Run("ReasonOf", func(t *testing.T) {
		reason, ok := applereceipt.ReasonOf(err)
		if !ok || reason != applereceipt.ReasonUntrustedChain {
			t.Fatalf("ReasonOf: %v %v", reason, ok)
		}
		if _, ok := applereceipt.ReasonOf(errors.New("something else")); ok {
			t.Fatal("ReasonOf must not claim a reason for a foreign error")
		}
		if _, ok := applereceipt.ReasonOf(nil); ok {
			t.Fatal("ReasonOf(nil) must be false")
		}
	})
	t.Run("the message is REASON: message", func(t *testing.T) {
		if !strings.HasPrefix(err.Error(), "UNTRUSTED_CHAIN: ") {
			t.Fatalf("message form: %q", err.Error())
		}
	})
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

// Messages are logged by integrators, so they must not carry receipt
// bytes, claim values or key material (PLAN.md D11 / S11).
func TestErrorMessagesLeakNothingFromTheInput(t *testing.T) {
	pki := newReceiptPKI(t)
	secret := "com.secret.bundle.identifier"
	der := pki.receipt(t,
		attr(2, derUTF8String(secret)),
		attr(3, derUTF8String("9.9.9-secret-build")),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.secret.product")),
			attr(1703, derUTF8String("70000000000042")))),
	)

	var messages []string
	other := newReceiptPKI(t)
	verifier := verifierFor(t, other.anchors())
	if _, err := verifier.VerifyReceipt(applereceiptBase64(der)); err != nil {
		messages = append(messages, err.Error())
	}

	jwsPKI := newJWSPKI(t)
	claims := map[string]any{
		"bundleId":      secret,
		"transactionId": "70000000000042",
		"environment":   "Sandbox",
		"signedDate":    float64(1_722_945_600_000),
	}
	otherJWS := newJWSPKI(t)
	jwsVerifier := verifierFor(t, otherJWS.anchorSlice())
	if _, err := jwsVerifier.VerifySignedData(jwsPKI.sign(t, claims)); err != nil {
		messages = append(messages, err.Error())
	}

	if len(messages) < 2 {
		t.Fatalf("expected two failures to inspect, got %d", len(messages))
	}
	forbidden := []string{secret, "9.9.9-secret-build", "com.secret.product", "70000000000042"}
	for _, message := range messages {
		for _, needle := range forbidden {
			if strings.Contains(message, needle) {
				t.Errorf("error message leaks %q: %s", needle, message)
			}
		}
	}
}

// Every non-nil error a verification entry point returns is a *Failure.
// Constructor argument errors are the one exception, and they are a
// different type on purpose.
func TestOnlyFailuresEscapeTheEntryPoints(t *testing.T) {
	pki := newReceiptPKI(t)
	receiptVerifier := verifierFor(t, pki.anchors())
	jws := newJWSPKI(t)
	jwsVerifier := verifierFor(t, jws.anchorSlice())

	hostile := [][]byte{
		nil, {}, []byte("garbage"), derSequence(derInt(1)),
		nestedSequences(100), {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	}
	calls := []struct {
		name string
		call func([]byte) error
	}{
		{"VerifyReceipt", func(b []byte) error {
			_, err := receiptVerifier.VerifyReceipt(string(b))
			return err
		}},
		{"VerifyReceipt (base64)", func(b []byte) error {
			_, err := receiptVerifier.VerifyReceipt(applereceiptBase64(b))
			return err
		}},
		{"VerifySignedData", func(b []byte) error {
			_, err := jwsVerifier.VerifySignedData(string(b))
			return err
		}},
	}
	for _, call := range calls {
		call := call
		t.Run(call.name, func(t *testing.T) {
			for i, input := range hostile {
				err := call.call(input)
				if err == nil {
					t.Fatalf("input %d verified", i)
				}
				var failure *applereceipt.Failure
				if !errors.As(err, &failure) {
					t.Fatalf("input %d escaped as %T: %v", i, err, err)
				}
			}
		})
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
